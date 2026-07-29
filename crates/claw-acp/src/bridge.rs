//! ACP stdio server bridge backed by GTA-Claw application ports.

use std::{collections::VecDeque, future::Future, pin::Pin, sync::Arc, time::Duration};

use serde::Serialize;
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader},
    sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, mpsc},
    task::JoinSet,
    time::timeout,
};

use crate::{
    Error, Result,
    protocol::{RpcPeer, decode, is_response_message, message_parts, read_message, response_id},
    schema::ProtocolVersion,
    schema_v1::{
        AgentCapabilities, CancelNotification, CloseSessionRequest, CloseSessionResponse,
        Implementation, InitializeRequest, InitializeResponse, ListSessionsRequest,
        ListSessionsResponse, LoadSessionRequest, LoadSessionResponse, NewSessionRequest,
        NewSessionResponse, PromptRequest, PromptResponse, RequestPermissionRequest,
        RequestPermissionResponse, ResumeSessionRequest, ResumeSessionResponse, SessionId,
        SessionNotification, SessionUpdate, SetSessionConfigOptionRequest,
        SetSessionConfigOptionResponse, SetSessionModeRequest, SetSessionModeResponse,
    },
};

const MAX_IN_FLIGHT_REQUESTS: usize = 64;
const MAX_IN_FLIGHT_CANCELLATIONS: usize = 8;
const MAX_PENDING_CANCELLATIONS: usize = 64;
const MAX_TRACKED_DISPATCH_TASKS: usize = MAX_IN_FLIGHT_REQUESTS + MAX_IN_FLIGHT_CANCELLATIONS + 1;
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
    ///
    /// # Errors
    ///
    /// Returns the transport failure when the notification cannot be written:
    /// the client closed its end of stdio, or the connection was already torn
    /// down by an earlier write failure.
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
    ///
    /// # Errors
    ///
    /// Returns the client's own JSON-RPC error when it refuses the request,
    /// an invalid-request error when its response does not decode into a
    /// [`RequestPermissionResponse`], and a disconnect error when the client
    /// closes stdio before answering.
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
    fn new_session(
        &self,
        request: NewSessionRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'_, NewSessionResponse>;
    /// Loads an existing ACP session and replays its history through notifications.
    fn load_session(
        &self,
        request: LoadSessionRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'_, LoadSessionResponse>;
    /// Resumes an existing ACP session.
    fn resume_session(
        &self,
        request: ResumeSessionRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'_, ResumeSessionResponse>;
    /// Lists persistent ACP sessions.
    fn list_sessions(&self, request: ListSessionsRequest) -> AcpFuture<'_, ListSessionsResponse>;
    /// Closes a session and releases its resources.
    fn close_session(&self, request: CloseSessionRequest) -> AcpFuture<'_, CloseSessionResponse>;
    /// Processes one prompt turn and streams intermediate updates.
    fn prompt(
        &self,
        request: PromptRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'_, PromptResponse>;
    /// Changes the active mode for one session.
    fn set_mode(&self, request: SetSessionModeRequest) -> AcpFuture<'_, SetSessionModeResponse>;
    /// Changes one session configuration option.
    fn set_config_option(
        &self,
        request: SetSessionConfigOptionRequest,
    ) -> AcpFuture<'_, SetSessionConfigOptionResponse>;
    /// Cancels active work in one session.
    fn cancel(&self, notification: CancelNotification) -> AcpFuture<'_, ()>;
}

/// ACP agent bridge serving GTA-Claw sessions over stdio.
pub struct AcpBridge {
    backend: Arc<dyn AcpBackend>,
    /// Shared so that dispatching a request is an `Arc` bump instead of a deep
    /// clone of the advertised capabilities: 3.3 ns against 23.8 ns per
    /// request. Only `initialize` needs an owned copy.
    capabilities: Arc<AgentCapabilities>,
    #[cfg(test)]
    task_count_peak: Option<Arc<std::sync::atomic::AtomicUsize>>,
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
            capabilities: Arc::new(capabilities),
            #[cfg(test)]
            task_count_peak: None,
        }
    }

    #[cfg(test)]
    fn with_task_count_peak(mut self, peak: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        self.task_count_peak = Some(peak);
        self
    }

    #[cfg(test)]
    fn observe_task_count(&self, tasks: &JoinSet<()>) {
        if let Some(peak) = self.task_count_peak.as_ref() {
            peak.fetch_max(tasks.len(), std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Serves the ACP bridge over process stdio until the client disconnects.
    ///
    /// A client that closes stdin, or that never writes at all, ends the loop
    /// without an error.
    ///
    /// # Errors
    ///
    /// Returns the framing failure when the client sends a frame that is not
    /// newline-delimited JSON or that exceeds the frame byte limit, and an
    /// internal error when a dispatch task panicked. Both cases end the
    /// session; the failing frame is answered with a null-id JSON-RPC error
    /// first when stdout is still writable.
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
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        let _ = incoming_sender.send(Err(error)).await;
                        break;
                    }
                }
            }
        });
        let request_slots = Arc::new(Semaphore::new(MAX_IN_FLIGHT_REQUESTS));
        let cancellation_slots = Arc::new(Semaphore::new(MAX_IN_FLIGHT_CANCELLATIONS));
        let mut pending_cancellations = VecDeque::new();
        let mut tasks = JoinSet::new();
        let terminal_error = loop {
            if let Err(error) = reap_completed_tasks(&mut tasks) {
                break Some(error);
            }
            if let Err(error) = dispatch_cancellations(
                &mut pending_cancellations,
                &cancellation_slots,
                &mut tasks,
                &self.backend,
            ) {
                break Some(error);
            }
            #[cfg(test)]
            self.observe_task_count(&tasks);
            if tasks.len() > MAX_TRACKED_DISPATCH_TASKS {
                break Some(Error::internal_error().data("ACP dispatch task bound exceeded"));
            }
            let message = tokio::select! {
                biased;
                () = peer.disconnected() => break None,
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = completed {
                        break Some(Error::internal_error().data(error.to_string()));
                    }
                    continue;
                }
                message = incoming.recv() => message,
            };
            if !peer.is_connected() {
                break None;
            }
            let mut message = match message {
                Some(Ok(message)) => message,
                None => break None,
                Some(Err(error)) => {
                    let _ = peer.respond::<Value>(Value::Null, Err(error.clone())).await;
                    break Some(error);
                }
            };
            if message.get("method").is_none() {
                if is_response_message(&message) {
                    let _ = peer.resolve_response(&mut message);
                } else {
                    let _ = peer
                        .respond::<Value>(response_id(&message), Err(Error::invalid_request()))
                        .await;
                }
                continue;
            }
            let (method, params, id) = match message_parts(&mut message) {
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
                let capabilities = Arc::clone(&self.capabilities);
                let peer = peer.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    dispatch_request(backend, capabilities, peer, method, params, id).await;
                });
                #[cfg(test)]
                self.observe_task_count(&tasks);
                if tasks.len() > MAX_TRACKED_DISPATCH_TASKS {
                    break Some(Error::internal_error().data("ACP dispatch task bound exceeded"));
                }
            } else if method == "session/cancel" {
                let Ok(notification) = decode(params) else {
                    continue;
                };
                if pending_cancellations.len() >= MAX_PENDING_CANCELLATIONS
                    && let Err(error) = dispatch_cancellations(
                        &mut pending_cancellations,
                        &cancellation_slots,
                        &mut tasks,
                        &self.backend,
                    )
                {
                    break Some(error);
                }
                if pending_cancellations.len() >= MAX_PENDING_CANCELLATIONS {
                    break Some(Error::server_error(
                        -32099,
                        "Too many queued ACP cancellations",
                    ));
                }
                pending_cancellations.push_back(notification);
            }
        };
        peer.begin_disconnect();
        if !reader.is_finished() {
            reader.abort();
        }
        let _ = reader.await;
        if timeout(DISCONNECT_DRAIN_TIMEOUT, async {
            loop {
                if reap_completed_tasks(&mut tasks).is_err() {
                    break;
                }
                if dispatch_cancellations(
                    &mut pending_cancellations,
                    &cancellation_slots,
                    &mut tasks,
                    &self.backend,
                )
                .is_err()
                {
                    break;
                }
                #[cfg(test)]
                self.observe_task_count(&tasks);
                if pending_cancellations.is_empty() {
                    while tasks.join_next().await.is_some() {}
                    break;
                }
                if tasks.join_next().await.is_none() {
                    break;
                }
            }
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        peer.finish_disconnect();
        terminal_error.map_or_else(|| Ok(()), |error| Err(error.into()))
    }
}

fn reap_completed_tasks(tasks: &mut JoinSet<()>) -> std::result::Result<(), Error> {
    while let Some(completed) = tasks.try_join_next() {
        completed.map_err(|error| Error::internal_error().data(error.to_string()))?;
    }
    Ok(())
}

fn dispatch_cancellations(
    pending: &mut VecDeque<CancelNotification>,
    slots: &Arc<Semaphore>,
    tasks: &mut JoinSet<()>,
    backend: &Arc<dyn AcpBackend>,
) -> std::result::Result<(), Error> {
    loop {
        let Some(notification) = pending.pop_front() else {
            return Ok(());
        };
        match Arc::clone(slots).try_acquire_owned() {
            Ok(permit) => spawn_cancellation(tasks, Arc::clone(backend), notification, permit),
            Err(TryAcquireError::NoPermits) => {
                pending.push_front(notification);
                return Ok(());
            }
            Err(TryAcquireError::Closed) => {
                pending.push_front(notification);
                return Err(Error::internal_error().data("ACP cancellation semaphore closed"));
            }
        }
    }
}

fn spawn_cancellation(
    tasks: &mut JoinSet<()>,
    backend: Arc<dyn AcpBackend>,
    notification: CancelNotification,
    permit: OwnedSemaphorePermit,
) {
    tasks.spawn(async move {
        let _permit = permit;
        let _ = backend.cancel(notification).await;
    });
}

async fn dispatch_request(
    backend: Arc<dyn AcpBackend>,
    capabilities: Arc<AgentCapabilities>,
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
                .agent_capabilities(AgentCapabilities::clone(&capabilities))
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
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll},
    };

    use tokio::io::{AsyncWriteExt, duplex};
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[derive(Clone, Debug)]
    struct CancellationControl {
        started: Arc<AtomicUsize>,
        release: CancellationToken,
    }

    #[derive(Debug, Default)]
    struct TestBackend {
        cancellation: Option<CancellationControl>,
    }

    impl AcpBackend for TestBackend {
        fn new_session(
            &self,
            _request: NewSessionRequest,
            _context: AcpSessionContext,
        ) -> AcpFuture<'_, NewSessionResponse> {
            panic!("backend must not receive a session request")
        }

        fn load_session(
            &self,
            _request: LoadSessionRequest,
            _context: AcpSessionContext,
        ) -> AcpFuture<'_, LoadSessionResponse> {
            panic!("backend must not receive a load request")
        }

        fn resume_session(
            &self,
            _request: ResumeSessionRequest,
            _context: AcpSessionContext,
        ) -> AcpFuture<'_, ResumeSessionResponse> {
            panic!("backend must not receive a resume request")
        }

        fn list_sessions(
            &self,
            _request: ListSessionsRequest,
        ) -> AcpFuture<'_, ListSessionsResponse> {
            panic!("backend must not receive a list request")
        }

        fn close_session(
            &self,
            _request: CloseSessionRequest,
        ) -> AcpFuture<'_, CloseSessionResponse> {
            panic!("backend must not receive a close request")
        }

        fn prompt(
            &self,
            _request: PromptRequest,
            _context: AcpSessionContext,
        ) -> AcpFuture<'_, PromptResponse> {
            panic!("backend must not receive a prompt request")
        }

        fn set_mode(
            &self,
            _request: SetSessionModeRequest,
        ) -> AcpFuture<'_, SetSessionModeResponse> {
            panic!("backend must not receive a mode request")
        }

        fn set_config_option(
            &self,
            _request: SetSessionConfigOptionRequest,
        ) -> AcpFuture<'_, SetSessionConfigOptionResponse> {
            panic!("backend must not receive a configuration request")
        }

        fn cancel(&self, _notification: CancelNotification) -> AcpFuture<'_, ()> {
            let Some(control) = self.cancellation.clone() else {
                panic!("backend must not receive a cancellation")
            };
            Box::pin(async move {
                control.started.fetch_add(1, Ordering::SeqCst);
                control.release.cancelled().await;
                Ok(())
            })
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
        let bridge = AcpBridge::new(Arc::new(TestBackend::default()), AgentCapabilities::new());
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

    async fn write_cancellations(client: &mut (impl AsyncWrite + Unpin), count: usize) {
        for index in 0..count {
            let message = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "session/cancel",
                "params": {"sessionId": format!("fixture-{index}")},
            }))
            .expect("serialize cancellation");
            client
                .write_all(&message)
                .await
                .expect("write cancellation");
            client.write_all(b"\n").await.expect("frame cancellation");
        }
        client.flush().await.expect("flush cancellations");
    }

    async fn wait_for_cancellations(started: &AtomicUsize, expected: usize) {
        timeout(Duration::from_secs(1), async {
            while started.load(Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("expected {expected} cancellation calls"));
    }

    #[tokio::test]
    async fn saturated_cancellations_wait_for_a_permit_instead_of_disappearing() {
        let started = Arc::new(AtomicUsize::new(0));
        let release = CancellationToken::new();
        let backend = TestBackend {
            cancellation: Some(CancellationControl {
                started: Arc::clone(&started),
                release: release.clone(),
            }),
        };
        let (mut client, input) = duplex(4096);
        let bridge = AcpBridge::new(Arc::new(backend), AgentCapabilities::new());
        let server = tokio::spawn(bridge.serve(input, tokio::io::sink()));

        write_cancellations(&mut client, MAX_IN_FLIGHT_CANCELLATIONS + 1).await;
        wait_for_cancellations(&started, MAX_IN_FLIGHT_CANCELLATIONS).await;
        assert_eq!(started.load(Ordering::SeqCst), MAX_IN_FLIGHT_CANCELLATIONS);

        release.cancel();
        wait_for_cancellations(&started, MAX_IN_FLIGHT_CANCELLATIONS + 1).await;
        drop(client);

        timeout(Duration::from_secs(1), server)
            .await
            .expect("bridge must stop after every cancellation is delivered")
            .expect("bridge task must not panic")
            .expect("clean input close");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sustained_request_traffic_reaps_completed_dispatch_tasks() {
        const REQUEST_COUNT: usize = 1_024;

        let task_count_peak = Arc::new(AtomicUsize::new(0));
        let (mut client, input) = duplex(256 * 1024);
        let bridge = AcpBridge::new(Arc::new(TestBackend::default()), AgentCapabilities::new())
            .with_task_count_peak(Arc::clone(&task_count_peak));
        let server = tokio::spawn(bridge.serve(input, tokio::io::sink()));

        for id in 0..REQUEST_COUNT {
            let request = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "initialize",
                "params": InitializeRequest::new(ProtocolVersion::V1),
            }))
            .expect("serialize initialize");
            client.write_all(&request).await.expect("write initialize");
            client.write_all(b"\n").await.expect("frame initialize");
        }
        client.flush().await.expect("flush initialize traffic");
        drop(client);

        timeout(Duration::from_secs(3), server)
            .await
            .expect("sustained request traffic must shut down")
            .expect("bridge task must not panic")
            .expect("sustained requests must drain cleanly");
        assert!(
            task_count_peak.load(Ordering::SeqCst) <= MAX_TRACKED_DISPATCH_TASKS,
            "completed JoinSet entries must be reaped before admitting unbounded input"
        );
    }

    #[tokio::test]
    async fn saturated_cancellation_backpressure_has_a_bounded_eof_shutdown() {
        let started = Arc::new(AtomicUsize::new(0));
        let backend = TestBackend {
            cancellation: Some(CancellationControl {
                started: Arc::clone(&started),
                release: CancellationToken::new(),
            }),
        };
        let (mut client, input) = duplex(4096);
        let bridge = AcpBridge::new(Arc::new(backend), AgentCapabilities::new());
        let server = tokio::spawn(bridge.serve(input, tokio::io::sink()));

        write_cancellations(
            &mut client,
            MAX_IN_FLIGHT_CANCELLATIONS + MAX_PENDING_CANCELLATIONS,
        )
        .await;
        wait_for_cancellations(&started, MAX_IN_FLIGHT_CANCELLATIONS).await;
        drop(client);

        timeout(3 * DISCONNECT_DRAIN_TIMEOUT, server)
            .await
            .expect("EOF must stop a cancellation-saturated bridge")
            .expect("bridge task must not panic")
            .expect("forced cancellation drain is a clean shutdown");
    }

    #[tokio::test]
    async fn cancellation_queue_overflow_fails_the_connection_explicitly() {
        let started = Arc::new(AtomicUsize::new(0));
        let backend = TestBackend {
            cancellation: Some(CancellationControl {
                started: Arc::clone(&started),
                release: CancellationToken::new(),
            }),
        };
        let (mut client, input) = duplex(64 * 1024);
        let bridge = AcpBridge::new(Arc::new(backend), AgentCapabilities::new());
        let server = tokio::spawn(bridge.serve(input, tokio::io::sink()));

        write_cancellations(
            &mut client,
            MAX_IN_FLIGHT_CANCELLATIONS + MAX_PENDING_CANCELLATIONS + 1,
        )
        .await;

        let result = timeout(3 * DISCONNECT_DRAIN_TIMEOUT, server)
            .await
            .expect("overflow must terminate the bridge")
            .expect("bridge task must not panic");
        assert!(
            result.is_err(),
            "overflow must not silently discard a cancel"
        );
        drop(client);
    }

    #[tokio::test]
    async fn cancellation_saturation_preserves_a_following_framing_error() {
        let started = Arc::new(AtomicUsize::new(0));
        let backend = TestBackend {
            cancellation: Some(CancellationControl {
                started: Arc::clone(&started),
                release: CancellationToken::new(),
            }),
        };
        let (mut client, input) = duplex(4096);
        let bridge = AcpBridge::new(Arc::new(backend), AgentCapabilities::new());
        let server = tokio::spawn(bridge.serve(input, tokio::io::sink()));

        write_cancellations(&mut client, MAX_IN_FLIGHT_CANCELLATIONS + 1).await;
        client
            .write_all(b"{not-json}\n")
            .await
            .expect("write malformed frame");
        client.flush().await.expect("flush malformed frame");
        drop(client);

        let result = timeout(3 * DISCONNECT_DRAIN_TIMEOUT, server)
            .await
            .expect("framing error must terminate the bridge")
            .expect("bridge task must not panic");
        assert!(result.is_err(), "framing error must survive saturation");
    }
}

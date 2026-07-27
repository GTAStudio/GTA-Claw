use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const OUTBOUND_QUEUE_CAPACITY: usize = 64;

type PendingResponse = oneshot::Sender<std::result::Result<Value, ProtocolError>>;

/// JSON-RPC failure exchanged by ACP peers.
#[derive(Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct ProtocolError {
    /// Integer JSON-RPC or ACP-specific error code.
    pub code: i32,
    /// Concise error description.
    pub message: String,
    /// Optional structured diagnostic data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ProtocolError {
    /// Creates an error with an arbitrary JSON-RPC or ACP error code.
    #[must_use]
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Creates an error with structured diagnostic data.
    #[must_use]
    pub fn with_data(code: i32, message: impl Into<String>, data: Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }

    /// Creates a JSON-RPC parse error.
    #[must_use]
    pub fn parse_error() -> Self {
        Self::new(-32700, "Parse error")
    }

    /// Creates a JSON-RPC invalid-request error.
    #[must_use]
    pub fn invalid_request() -> Self {
        Self::new(-32600, "Invalid Request")
    }

    /// Creates a JSON-RPC method-not-found error.
    #[must_use]
    pub fn method_not_found() -> Self {
        Self::new(-32601, "Method not found")
    }

    /// Creates a JSON-RPC invalid-parameters error.
    #[must_use]
    pub fn invalid_params() -> Self {
        Self::new(-32602, "Invalid params")
    }

    /// Creates a JSON-RPC internal error.
    #[must_use]
    pub fn internal_error() -> Self {
        Self::new(-32603, "Internal error")
    }

    /// Creates an ACP authentication-required error.
    #[must_use]
    pub fn auth_required() -> Self {
        Self::new(-32000, "Authentication required")
    }

    /// Creates an ACP resource-not-found error.
    #[must_use]
    pub fn resource_not_found(uri: Option<String>) -> Self {
        uri.map_or_else(
            || Self::new(-32002, "Resource not found"),
            |uri| Self::with_data(-32002, "Resource not found", json!({ "uri": uri })),
        )
    }

    /// Creates an implementation-defined JSON-RPC server error.
    #[must_use]
    pub fn server_error(code: i32, message: impl Into<String>) -> Self {
        if (-32099..=-32000).contains(&code) {
            Self::new(code, message)
        } else {
            Self::internal_error()
        }
    }

    /// Adds structured diagnostic data without exposing it through `Debug` or `Display`.
    #[must_use]
    pub fn data(mut self, data: impl Into<Value>) -> Self {
        self.data = Some(data.into());
        self
    }

    pub(crate) fn disconnected() -> Self {
        Self::internal_error().data("ACP peer disconnected")
    }
}

impl fmt::Debug for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolError")
            .field("code", &self.code)
            .field("message", &self.message)
            .field("has_data", &self.data.is_some())
            .finish()
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for ProtocolError {}

struct PeerState {
    connected: bool,
    pending: HashMap<u64, PendingResponse>,
}

/// Correlation entry for one outstanding request.
///
/// Dropping it removes the entry, so a request future that is cancelled — by a
/// `select!` branch, a timeout, or an aborted task — cannot leave a waiter
/// behind in the pending map.
struct PendingRequest {
    state: Arc<Mutex<PeerState>>,
    id: u64,
}

impl PendingRequest {
    fn register(
        state: &Arc<Mutex<PeerState>>,
        id: u64,
        sender: PendingResponse,
    ) -> std::result::Result<Self, ProtocolError> {
        let mut locked = state
            .lock()
            .map_err(|_| ProtocolError::internal_error().data("ACP pending map poisoned"))?;
        if !locked.connected {
            return Err(ProtocolError::disconnected());
        }
        locked.pending.insert(id, sender);
        drop(locked);
        Ok(Self {
            state: Arc::clone(state),
            id,
        })
    }
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.pending.remove(&self.id);
        }
    }
}

struct Outbound {
    bytes: Vec<u8>,
    completion: oneshot::Sender<std::result::Result<(), ProtocolError>>,
}

#[derive(Clone)]
pub(crate) struct RpcPeer {
    outgoing: mpsc::Sender<Outbound>,
    state: Arc<Mutex<PeerState>>,
    next_id: Arc<AtomicU64>,
    disconnected: CancellationToken,
}

impl RpcPeer {
    pub(crate) fn new(writer: impl AsyncWrite + Send + Unpin + 'static) -> Self {
        let (outgoing, receiver) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
        let state = Arc::new(Mutex::new(PeerState {
            connected: true,
            pending: HashMap::new(),
        }));
        let disconnected = CancellationToken::new();
        tokio::spawn(writer_loop(
            writer,
            receiver,
            Arc::clone(&state),
            disconnected.clone(),
        ));
        Self {
            outgoing,
            state,
            next_id: Arc::new(AtomicU64::new(1)),
            disconnected,
        }
    }

    pub(crate) async fn request<P, R>(
        &self,
        method: &'static str,
        params: P,
    ) -> std::result::Result<R, ProtocolError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let params = serde_json::to_value(params)
            .map_err(|error| ProtocolError::internal_error().data(error.to_string()))?;
        let (sender, receiver) = oneshot::channel();
        let pending = PendingRequest::register(&self.state, id, sender)?;
        self.write(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .await?;
        let result = receiver
            .await
            .map_err(|_| ProtocolError::disconnected())??;
        drop(pending);
        serde_json::from_value(result)
            .map_err(|error| ProtocolError::invalid_request().data(error.to_string()))
    }

    pub(crate) async fn notify<P>(
        &self,
        method: &'static str,
        params: P,
    ) -> std::result::Result<(), ProtocolError>
    where
        P: Serialize,
    {
        let params = serde_json::to_value(params)
            .map_err(|error| ProtocolError::internal_error().data(error.to_string()))?;
        self.write(json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }))
        .await
    }

    pub(crate) async fn respond<R>(
        &self,
        id: Value,
        result: std::result::Result<R, ProtocolError>,
    ) -> std::result::Result<(), ProtocolError>
    where
        R: Serialize,
    {
        let message = match result {
            Ok(result) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result,
            }),
            Err(error) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": error,
            }),
        };
        self.write(message).await
    }

    pub(crate) fn resolve_response(
        &self,
        message: &Value,
    ) -> std::result::Result<(), ProtocolError> {
        let id = message
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(ProtocolError::invalid_request)?;
        let sender = self
            .state
            .lock()
            .map_err(|_| ProtocolError::internal_error().data("ACP pending map poisoned"))?
            .pending
            .remove(&id)
            .ok_or_else(ProtocolError::invalid_request)?;
        if message.get("jsonrpc") != Some(&Value::String("2.0".into()))
            || message.get("method").is_some()
            || (message.get("result").is_some() == message.get("error").is_some())
        {
            let _ = sender.send(Err(ProtocolError::invalid_request()));
            return Ok(());
        }
        let result = if let Some(error) = message.get("error") {
            serde_json::from_value(error.clone())
                .map(Err)
                .map_err(|error| ProtocolError::invalid_request().data(error.to_string()))?
        } else {
            Ok(message
                .get("result")
                .cloned()
                .ok_or_else(ProtocolError::invalid_request)?)
        };
        let _ = sender.send(result);
        Ok(())
    }

    pub(crate) fn mark_disconnected(&self) {
        disconnect_state(&self.state, &ProtocolError::disconnected());
        self.disconnected.cancel();
    }

    pub(crate) async fn disconnected(&self) {
        self.disconnected.cancelled().await;
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.connected)
    }

    async fn write(&self, message: Value) -> std::result::Result<(), ProtocolError> {
        let mut bytes = serde_json::to_vec(&message)
            .map_err(|error| ProtocolError::internal_error().data(error.to_string()))?;
        bytes.push(b'\n');
        let (completion, finished) = oneshot::channel();
        self.outgoing
            .send(Outbound { bytes, completion })
            .await
            .map_err(|_| ProtocolError::disconnected())?;
        finished.await.map_err(|_| ProtocolError::disconnected())?
    }
}

async fn writer_loop<W>(
    mut writer: W,
    mut receiver: mpsc::Receiver<Outbound>,
    state: Arc<Mutex<PeerState>>,
    disconnected: CancellationToken,
) where
    W: AsyncWrite + Send + Unpin + 'static,
{
    let writer_disconnected = disconnected.clone();
    let _disconnect_on_exit = disconnected.drop_guard();
    while let Some(outbound) = receiver.recv().await {
        let result = async {
            writer.write_all(&outbound.bytes).await?;
            writer.flush().await
        }
        .await
        .map_err(|error| ProtocolError::internal_error().data(error.to_string()));
        let failed = result.is_err();
        let error = result
            .as_ref()
            .err()
            .cloned()
            .unwrap_or_else(ProtocolError::disconnected);
        if failed {
            disconnect_state(&state, &error);
            writer_disconnected.cancel();
        }
        let _ = outbound.completion.send(result);
        if failed {
            while let Ok(outbound) = receiver.try_recv() {
                let _ = outbound.completion.send(Err(error.clone()));
            }
            return;
        }
    }
    disconnect_state(&state, &ProtocolError::disconnected());
}

fn disconnect_state(state: &Mutex<PeerState>, error: &ProtocolError) {
    let Ok(mut state) = state.lock() else {
        return;
    };
    state.connected = false;
    for (_, sender) in state.pending.drain() {
        let _ = sender.send(Err(error.clone()));
    }
}

pub(crate) async fn read_message<R>(
    reader: &mut R,
    frame: &mut Vec<u8>,
) -> std::result::Result<Option<Value>, ProtocolError>
where
    R: AsyncBufRead + Unpin,
{
    read_message_with_limit(reader, frame, MAX_FRAME_BYTES).await
}

async fn read_message_with_limit<R>(
    reader: &mut R,
    frame: &mut Vec<u8>,
    limit: usize,
) -> std::result::Result<Option<Value>, ProtocolError>
where
    R: AsyncBufRead + Unpin,
{
    frame.clear();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|error| ProtocolError::internal_error().data(error.to_string()))?;
        if available.is_empty() {
            if frame.is_empty() {
                return Ok(None);
            }
            break;
        }
        let (take, complete) = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or((available.len(), false), |position| (position + 1, true));
        if take > limit.saturating_sub(frame.len()) {
            return Err(ProtocolError::invalid_request().data("ACP frame exceeded its byte limit"));
        }
        frame.extend_from_slice(&available[..take]);
        reader.consume(take);
        if complete {
            break;
        }
    }
    if frame.last() == Some(&b'\n') {
        frame.pop();
    }
    if frame.last() == Some(&b'\r') {
        frame.pop();
    }
    if frame.is_empty() {
        return Err(ProtocolError::invalid_request().data("ACP frame was empty"));
    }
    serde_json::from_slice(frame)
        .map(Some)
        .map_err(|error| ProtocolError::parse_error().data(error.to_string()))
}

pub(crate) fn message_parts(
    message: &Value,
) -> std::result::Result<(&str, Value, Option<Value>), ProtocolError> {
    if !message.is_object()
        || message.get("jsonrpc") != Some(&Value::String("2.0".into()))
        || message.get("result").is_some()
        || message.get("error").is_some()
    {
        return Err(ProtocolError::invalid_request());
    }
    let method = message
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(ProtocolError::invalid_request)?;
    let id = message.get("id").cloned();
    if id.as_ref().is_some_and(|id| !valid_id(id)) {
        return Err(ProtocolError::invalid_request());
    }
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    if !params.is_null() && !params.is_object() && !params.is_array() {
        return Err(ProtocolError::invalid_request());
    }
    Ok((method, params, id))
}

pub(crate) fn response_id(message: &Value) -> Value {
    message
        .get("id")
        .filter(|id| valid_id(id))
        .cloned()
        .unwrap_or(Value::Null)
}

pub(crate) fn is_response_message(message: &Value) -> bool {
    message.get("method").is_none()
        && (message.get("result").is_some() || message.get("error").is_some())
}

fn valid_id(id: &Value) -> bool {
    id.is_null()
        || id.is_string()
        || id
            .as_number()
            .is_some_and(|number| number.is_i64() || number.is_u64())
}

pub(crate) fn decode<T: DeserializeOwned>(params: Value) -> std::result::Result<T, ProtocolError> {
    serde_json::from_value(params)
        .map_err(|error| ProtocolError::invalid_params().data(error.to_string()))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, BufReader, duplex};

    use super::*;

    #[tokio::test]
    async fn split_and_coalesced_frames_are_decoded_independently() {
        let (mut writer, reader) = duplex(512);
        let producer = tokio::spawn(async move {
            writer
                .write_all(br#"{"jsonrpc":"2.0","id":1,"res"#)
                .await
                .expect("write split prefix");
            tokio::task::yield_now().await;
            writer
                .write_all(
                    b"ult\":{\"value\":1}}\r\n{\"jsonrpc\":\"2.0\",\"method\":\"session/cancel\",\"params\":{\"sessionId\":\"fixture\"}}\n",
                )
                .await
                .expect("write split suffix and coalesced frame");
        });
        let mut reader = BufReader::new(reader);
        let mut frame = Vec::new();

        let first = read_message(&mut reader, &mut frame)
            .await
            .expect("first frame")
            .expect("first value");
        let second = read_message(&mut reader, &mut frame)
            .await
            .expect("second frame")
            .expect("second value");

        assert_eq!(
            first,
            json!({"jsonrpc": "2.0", "id": 1, "result": {"value": 1}})
        );
        assert_eq!(
            second,
            json!({
                "jsonrpc": "2.0",
                "method": "session/cancel",
                "params": {"sessionId": "fixture"}
            })
        );
        producer.await.expect("producer task");
    }

    #[tokio::test]
    async fn oversized_and_malformed_frames_fail_closed() {
        let (mut oversized_writer, oversized_reader) = duplex(64);
        oversized_writer
            .write_all(b"{\"tooLong\":true}\n")
            .await
            .expect("write oversized frame");
        let mut oversized_reader = BufReader::new(oversized_reader);
        let mut frame = Vec::new();
        let oversized = read_message_with_limit(&mut oversized_reader, &mut frame, 8)
            .await
            .expect_err("oversized frame must fail");

        let (mut malformed_writer, malformed_reader) = duplex(64);
        malformed_writer
            .write_all(b"{not-json}\n")
            .await
            .expect("write malformed frame");
        let mut malformed_reader = BufReader::new(malformed_reader);
        let malformed = read_message(&mut malformed_reader, &mut frame)
            .await
            .expect_err("malformed frame must fail");

        assert_eq!(oversized.code, -32600);
        assert_eq!(malformed.code, -32700);
    }

    #[test]
    fn error_debug_redacts_structured_data() {
        let error = ProtocolError::auth_required().data("secret-token-value");

        let output = format!("{error:?}");

        assert!(!output.contains("secret-token-value"));
        assert!(output.contains("has_data: true"));
    }

    #[test]
    fn request_ids_reject_boolean_and_fractional_values() {
        for id in [json!(false), json!(1.5), json!({}), json!([])] {
            let message = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "initialize",
                "params": {},
            });
            let error = message_parts(&message).expect_err("invalid request id");
            assert_eq!(error.code, -32600);
        }
    }

    fn pending_len(peer: &RpcPeer) -> usize {
        peer.state.lock().expect("pending map").pending.len()
    }

    #[tokio::test]
    async fn a_dropped_request_future_removes_its_pending_entry() {
        let (writer, reader) = duplex(1024);
        let peer = RpcPeer::new(writer);
        let mut reader = BufReader::new(reader);
        let mut frame = Vec::new();
        let mut request = Box::pin(peer.request::<_, Value>("initialize", json!({})));

        let sent = tokio::select! {
            _ = request.as_mut() => panic!("request must not resolve before a response arrives"),
            message = read_message(&mut reader, &mut frame) => message,
        }
        .expect("request frame")
        .expect("request value");

        assert_eq!(sent["id"], 1);
        assert_eq!(pending_len(&peer), 1);

        drop(request);

        assert_eq!(pending_len(&peer), 0);
        assert!(
            peer.resolve_response(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}))
                .is_err()
        );
    }
}

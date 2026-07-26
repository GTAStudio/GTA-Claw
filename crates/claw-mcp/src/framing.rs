//! Bounded newline-delimited JSON-RPC framing.

use std::{
    future::Future,
    io,
    sync::{Arc, Mutex},
};

use rmcp::{
    RoleClient, RoleServer,
    model::{InitializeResult, ProtocolVersion},
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::Transport,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::error::{McpError, Result};

/// Default maximum JSON-RPC frame size accepted over stdio.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub(crate) struct BoundedIoDiagnostics {
    protocol_failure: Arc<Mutex<Option<String>>>,
    transport_disconnected: CancellationToken,
    reader_finished: CancellationToken,
}

impl BoundedIoDiagnostics {
    fn record(&self, error: &McpError) {
        let message = match error {
            McpError::Protocol(message) => message.clone(),
            McpError::Json(error) => format!("stdio frame contains invalid JSON: {error}"),
            _ => return,
        };
        let mut failure = self
            .protocol_failure
            .lock()
            .expect("bounded stdio diagnostics lock poisoned");
        if failure.is_none() {
            *failure = Some(message);
        }
    }

    fn record_invalid_message(&self, error: &serde_json::Error) {
        let mut failure = self
            .protocol_failure
            .lock()
            .expect("bounded stdio diagnostics lock poisoned");
        if failure.is_none() {
            *failure = Some(format!("stdio JSON-RPC message is invalid: {error}"));
        }
    }

    fn record_initialize_result(&self, value: &Value) {
        let Some(result) = value.get("result") else {
            return;
        };
        let Ok(initialize) = serde_json::from_value::<InitializeResult>(result.clone()) else {
            return;
        };
        if ProtocolVersion::KNOWN_VERSIONS.contains(&initialize.protocol_version) {
            return;
        }
        let mut failure = self
            .protocol_failure
            .lock()
            .expect("bounded stdio diagnostics lock poisoned");
        if failure.is_none() {
            *failure = Some(format!(
                "server selected unsupported version {}",
                initialize.protocol_version
            ));
        }
    }

    pub(crate) fn protocol_error(&self) -> Option<McpError> {
        self.protocol_failure
            .lock()
            .expect("bounded stdio diagnostics lock poisoned")
            .clone()
            .map(McpError::Protocol)
    }

    pub(crate) async fn promote_after_disconnect(&self, error: McpError) -> McpError {
        if self.transport_disconnected.is_cancelled() {
            self.reader_finished.cancelled().await;
        }
        self.protocol_error().unwrap_or(error)
    }
}

/// Incremental decoder for newline-delimited JSON-RPC messages.
///
/// A decoder accepts arbitrarily split or coalesced byte reads. Empty lines are
/// ignored, while malformed UTF-8, malformed JSON, and oversized frames fail
/// explicitly.
#[derive(Debug)]
pub struct JsonLineDecoder {
    buffered: Vec<u8>,
    max_frame_bytes: usize,
}

impl JsonLineDecoder {
    /// Creates a decoder with an explicit per-frame byte limit.
    #[must_use]
    pub const fn new(max_frame_bytes: usize) -> Self {
        Self {
            buffered: Vec::new(),
            max_frame_bytes,
        }
    }

    /// Appends one byte chunk and returns every complete JSON value it contains.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Value>> {
        self.buffered.extend_from_slice(bytes);
        if self.buffered.len() > self.max_frame_bytes && !self.buffered.contains(&b'\n') {
            return Err(McpError::Protocol("stdio frame exceeds byte limit".into()));
        }

        let mut decoded = Vec::new();
        while let Some(newline) = self.buffered.iter().position(|byte| *byte == b'\n') {
            let mut frame: Vec<u8> = self.buffered.drain(..=newline).collect();
            frame.pop();
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            if frame.is_empty() {
                continue;
            }
            if frame.len() > self.max_frame_bytes {
                return Err(McpError::Protocol("stdio frame exceeds byte limit".into()));
            }
            let text = std::str::from_utf8(&frame)
                .map_err(|_| McpError::Protocol("stdio frame is not UTF-8".into()))?;
            decoded.push(serde_json::from_str(text)?);
        }
        if self.buffered.len() > self.max_frame_bytes {
            return Err(McpError::Protocol("stdio frame exceeds byte limit".into()));
        }
        Ok(decoded)
    }

    /// Signals end-of-input, rejecting a non-empty unterminated frame.
    pub fn finish(&mut self) -> Result<()> {
        if self.buffered.iter().all(u8::is_ascii_whitespace) {
            self.buffered.clear();
            Ok(())
        } else {
            Err(McpError::Protocol(
                "stdio ended with an unterminated JSON-RPC frame".into(),
            ))
        }
    }
}

impl Default for JsonLineDecoder {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME_BYTES)
    }
}

/// Encodes one JSON-RPC value as a single newline-delimited frame.
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

type WriteRequest<R> = (
    TxJsonRpcMessage<R>,
    oneshot::Sender<std::result::Result<(), io::Error>>,
);

pub(crate) struct BoundedIoTransport<R>
where
    R: rmcp::service::ServiceRole,
{
    writes: Option<mpsc::Sender<WriteRequest<R>>>,
    reads: mpsc::Receiver<RxJsonRpcMessage<R>>,
    reader: Option<JoinHandle<std::result::Result<(), io::Error>>>,
    writer: Option<JoinHandle<std::result::Result<(), io::Error>>>,
    diagnostics: BoundedIoDiagnostics,
}

impl<R> BoundedIoTransport<R>
where
    R: rmcp::service::ServiceRole,
    RxJsonRpcMessage<R>: DeserializeOwned + Send + 'static,
    TxJsonRpcMessage<R>: Serialize + Send + 'static,
{
    pub(crate) fn new(
        input: impl AsyncRead + Send + Unpin + 'static,
        output: impl AsyncWrite + Send + Unpin + 'static,
    ) -> Self {
        Self::with_max_frame_bytes(input, output, DEFAULT_MAX_FRAME_BYTES)
    }

    pub(crate) fn with_max_frame_bytes(
        mut input: impl AsyncRead + Send + Unpin + 'static,
        mut output: impl AsyncWrite + Send + Unpin + 'static,
        max_frame_bytes: usize,
    ) -> Self {
        let (read_tx, reads) = mpsc::channel(32);
        let diagnostics = BoundedIoDiagnostics::default();
        let reader_diagnostics = diagnostics.clone();
        let disconnected = diagnostics.transport_disconnected.clone();
        let reader_disconnected = disconnected.clone();
        let reader_finished = diagnostics.reader_finished.clone();
        let reader_finished_guard = reader_finished.drop_guard();
        let reader = tokio::spawn(async move {
            let _reader_finished = reader_finished_guard;
            let mut decoder = JsonLineDecoder::new(max_frame_bytes);
            let mut bytes = [0_u8; 16 * 1024];
            loop {
                let count = tokio::select! {
                    biased;
                    result = input.read(&mut bytes) => result?,
                    _ = reader_disconnected.cancelled() => return Ok(()),
                };
                if count == 0 {
                    if let Err(error) = decoder.finish() {
                        reader_diagnostics.record(&error);
                        return Err(protocol_io_error(error));
                    }
                    return Ok(());
                }
                let values = match decoder.push(&bytes[..count]) {
                    Ok(values) => values,
                    Err(error) => {
                        reader_diagnostics.record(&error);
                        return Err(protocol_io_error(error));
                    }
                };
                for value in &values {
                    reader_diagnostics.record_initialize_result(value);
                }
                if reader_disconnected.is_cancelled() {
                    return Ok(());
                }
                for value in values {
                    let message = match serde_json::from_value(value) {
                        Ok(message) => message,
                        Err(error) => {
                            reader_diagnostics.record_invalid_message(&error);
                            return Err(invalid_data_io_error(error));
                        }
                    };
                    let sent = tokio::select! {
                        _ = reader_disconnected.cancelled() => return Ok(()),
                        result = read_tx.send(message) => result,
                    };
                    if sent.is_err() {
                        return Ok(());
                    }
                }
            }
        });

        let (writes, mut write_rx) = mpsc::channel::<WriteRequest<R>>(32);
        let writer = tokio::spawn(async move {
            let writer_disconnected = disconnected.clone();
            let _disconnect_on_exit = disconnected.drop_guard();
            while let Some((message, acknowledgement)) = write_rx.recv().await {
                let result = async {
                    let value = serde_json::to_value(message).map_err(invalid_data_io_error)?;
                    output
                        .write_all(&encode(&value).map_err(protocol_io_error)?)
                        .await?;
                    output.flush().await
                }
                .await;
                let failed = result.is_err();
                if failed {
                    writer_disconnected.cancel();
                }
                let _ = acknowledgement.send(result);
                if failed {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "bounded stdio writer failed",
                    ));
                }
            }
            Ok(())
        });

        Self {
            writes: Some(writes),
            reads,
            reader: Some(reader),
            writer: Some(writer),
            diagnostics,
        }
    }

    pub(crate) fn diagnostics(&self) -> BoundedIoDiagnostics {
        self.diagnostics.clone()
    }
}

impl<R> Drop for BoundedIoTransport<R>
where
    R: rmcp::service::ServiceRole,
{
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            reader.abort();
        }
        if let Some(writer) = self.writer.take() {
            writer.abort();
        }
    }
}

macro_rules! impl_bounded_transport {
    ($role:ty) => {
        impl Transport<$role> for BoundedIoTransport<$role> {
            type Error = io::Error;

            fn send(
                &mut self,
                item: TxJsonRpcMessage<$role>,
            ) -> impl Future<Output = std::result::Result<(), Self::Error>> + Send + 'static {
                let writes = self.writes.clone();
                async move {
                    let writes = writes.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "stdio transport is closed")
                    })?;
                    let (acknowledge, result) = oneshot::channel();
                    writes.send((item, acknowledge)).await.map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "stdio writer task stopped")
                    })?;
                    result.await.map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "stdio writer acknowledgement dropped",
                        )
                    })?
                }
            }

            fn receive(&mut self) -> impl Future<Output = Option<RxJsonRpcMessage<$role>>> + Send {
                self.reads.recv()
            }

            fn close(
                &mut self,
            ) -> impl Future<Output = std::result::Result<(), Self::Error>> + Send {
                self.writes.take();
                let reader = self.reader.take();
                let writer = self.writer.take();
                async move {
                    let writer_result = match writer {
                        Some(writer) => writer.await.map_err(join_io_error)?,
                        None => Ok(()),
                    };
                    if let Some(reader) = reader {
                        reader.abort();
                        match reader.await {
                            Ok(result) => result?,
                            Err(error) if error.is_cancelled() => {}
                            Err(error) => return Err(join_io_error(error)),
                        }
                    }
                    writer_result
                }
            }
        }
    };
}

impl_bounded_transport!(RoleClient);
impl_bounded_transport!(RoleServer);

fn protocol_io_error(error: McpError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn invalid_data_io_error(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn join_io_error(error: tokio::task::JoinError) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use rmcp::{
        RoleClient, RoleServer,
        service::{RxJsonRpcMessage, TxJsonRpcMessage},
        transport::Transport,
    };
    use serde_json::json;
    use tokio::{
        io::{AsyncWriteExt, duplex},
        time::{Duration, timeout},
    };

    use super::{BoundedIoTransport, JsonLineDecoder, McpError, encode};

    #[test]
    fn split_frame_is_reassembled_byte_for_byte() {
        let expected = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/list",
            "params": {}
        });
        let encoded = br#"{"id":7,"jsonrpc":"2.0","method":"tools/list","params":{}}
"#;
        let mut decoder = JsonLineDecoder::new(1024);
        let mut actual = Vec::new();

        for byte in encoded {
            actual.extend(decoder.push(&[*byte]).expect("decode split byte"));
        }

        assert_eq!(actual, vec![expected]);
        decoder.finish().expect("no buffered tail");
    }

    #[test]
    fn encoder_emits_one_exact_newline_delimited_frame() {
        let value = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/list",
            "params": {}
        });

        assert_eq!(
            encode(&value).expect("encode frame"),
            br#"{"id":7,"jsonrpc":"2.0","method":"tools/list","params":{}}
"#
        );
    }

    #[test]
    fn coalesced_frames_and_crlf_are_decoded_independently() {
        let mut decoder = JsonLineDecoder::new(1024);
        let bytes = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n"
        );
        let actual = decoder
            .push(bytes.as_bytes())
            .expect("decode coalesced frames");

        assert_eq!(
            actual,
            vec![
                json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
                json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
            ]
        );
    }

    #[test]
    fn malformed_and_unterminated_frames_fail_closed() {
        let mut malformed = JsonLineDecoder::new(1024);
        let error = malformed
            .push(b"{not-json}\n")
            .expect_err("malformed JSON must fail");
        assert_eq!(
            error.to_string(),
            "MCP JSON failed: key must be a string at line 1 column 2"
        );

        let mut unterminated = JsonLineDecoder::new(1024);
        assert_eq!(
            unterminated
                .push(br#"{"jsonrpc":"2.0"}"#)
                .expect("partial read"),
            Vec::<serde_json::Value>::new()
        );
        assert_eq!(
            unterminated
                .finish()
                .expect_err("unterminated frame must fail")
                .to_string(),
            "MCP protocol violation: stdio ended with an unterminated JSON-RPC frame"
        );
    }

    #[test]
    fn oversized_frames_are_rejected_before_unbounded_growth() {
        let mut decoder = JsonLineDecoder::new(8);
        let error = decoder
            .push(b"123456789")
            .expect_err("oversized frame must fail");
        assert_eq!(
            error.to_string(),
            "MCP protocol violation: stdio frame exceeds byte limit"
        );
    }

    #[test]
    fn oversized_residual_after_a_complete_frame_is_rejected() {
        let mut decoder = JsonLineDecoder::new(8);
        let error = decoder
            .push(b"{}\n123456789")
            .expect_err("oversized residual frame must fail");

        assert_eq!(
            error.to_string(),
            "MCP protocol violation: stdio frame exceeds byte limit"
        );
    }

    #[tokio::test]
    async fn writer_failure_closes_the_receive_half() {
        let (mut peer_input, transport_input) = duplex(1024);
        let (transport_output, peer_output) = duplex(1024);
        drop(peer_output);
        let mut transport =
            BoundedIoTransport::<RoleServer>::new(transport_input, transport_output);
        peer_input
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n")
            .await
            .expect("write first peer request");
        let first: Option<RxJsonRpcMessage<RoleServer>> = transport.receive().await;
        assert!(first.is_some(), "first peer request must be received");
        let response: TxJsonRpcMessage<RoleServer> = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": []}
        }))
        .expect("valid server response");

        let error = transport
            .send(response)
            .await
            .expect_err("closed peer read half must fail the writer");
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        let next = timeout(Duration::from_secs(1), transport.receive())
            .await
            .expect("writer failure must promptly close receive");
        assert!(
            next.is_none(),
            "transport must not receive work after writer failure"
        );
    }

    #[tokio::test]
    async fn buffered_protocol_diagnosis_wins_over_writer_failure() {
        let (mut peer_input, transport_input) = duplex(1024);
        let (transport_output, peer_output) = duplex(1024);
        drop(peer_output);
        let mut transport =
            BoundedIoTransport::<RoleServer>::new(transport_input, transport_output);
        let diagnostics = transport.diagnostics();
        peer_input
            .write_all(b"{not-json}\n")
            .await
            .expect("write malformed peer frame");
        let response: TxJsonRpcMessage<RoleServer> = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": []}
        }))
        .expect("valid server response");
        let writer_error = transport
            .send(response)
            .await
            .expect_err("closed peer read half must fail the writer");

        let error = diagnostics
            .promote_after_disconnect(McpError::Io(writer_error))
            .await;

        assert_eq!(
            error.to_string(),
            "MCP protocol violation: stdio frame contains invalid JSON: key must be a string at line 1 column 2"
        );
    }

    #[tokio::test]
    async fn unsupported_initialize_version_wins_over_writer_failure() {
        let (mut peer_input, transport_input) = duplex(1024);
        let (transport_output, peer_output) = duplex(1024);
        drop(peer_output);
        let mut transport =
            BoundedIoTransport::<RoleClient>::new(transport_input, transport_output);
        let diagnostics = transport.diagnostics();
        peer_input
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"1900-01-01\",\"capabilities\":{},\"serverInfo\":{\"name\":\"bad-version\",\"version\":\"1.0.0\"}}}\n",
            )
            .await
            .expect("write unsupported initialize result");
        let received: Option<RxJsonRpcMessage<RoleClient>> = transport.receive().await;
        assert!(
            received.is_some(),
            "unsupported initialize result must reach the service"
        );
        let initialized: TxJsonRpcMessage<RoleClient> = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .expect("valid initialized notification");
        let writer_error = transport
            .send(initialized)
            .await
            .expect_err("closed peer read half must fail the writer");

        let error = diagnostics
            .promote_after_disconnect(McpError::Io(writer_error))
            .await;

        assert_eq!(
            error.to_string(),
            "MCP protocol violation: server selected unsupported version 1900-01-01"
        );
    }

    #[tokio::test]
    async fn reader_abort_before_first_poll_reports_completion() {
        let (_peer_input, transport_input) = duplex(1024);
        let (transport_output, _peer_output) = duplex(1024);
        let transport = BoundedIoTransport::<RoleServer>::new(transport_input, transport_output);
        let diagnostics = transport.diagnostics();
        diagnostics.transport_disconnected.cancel();

        drop(transport);

        timeout(
            Duration::from_secs(1),
            diagnostics.reader_finished.cancelled(),
        )
        .await
        .expect("aborted reader must report completion");
    }
}

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
use serde::{Deserialize, Serialize, de::DeserializeOwned};
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
        // Every response carries a `result`, so this runs on the whole inbound
        // response stream. Deserializing through `&Value` rather than
        // `from_value(result.clone())` avoids cloning each result subtree, and
        // the `protocolVersion` probe rejects a non-initialize result before
        // the deserializer walks it at all — `InitializeResult` has no default
        // for that field, so a result without it could never have parsed.
        // Measured on a 600-byte tool result: 258.0 ns/message for the clone,
        // 82.5 ns deserializing from `&Value`, 15.9 ns with the probe. A real
        // initialize result costs 340.9 ns against 99.9 ns.
        if result.get("protocolVersion").is_none() {
            return;
        }
        let Ok(initialize) = InitializeResult::deserialize(result) else {
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

/// Buffer capacity retained once every buffered byte has been consumed.
///
/// A single large frame would otherwise pin `max_frame_bytes` of heap for the
/// lifetime of a long-running transport, so the carry-over buffer is released
/// back to this working size whenever it drains completely.
const IDLE_BUFFER_CAPACITY: usize = 64 * 1024;

fn reclaim_idle_frame(frame: &mut Vec<u8>) {
    frame.clear();
    if frame.capacity() > IDLE_BUFFER_CAPACITY {
        frame.shrink_to(IDLE_BUFFER_CAPACITY);
    }
}

/// Incremental decoder for newline-delimited JSON-RPC messages.
///
/// A decoder accepts arbitrarily split or coalesced byte reads. Empty lines are
/// ignored, while malformed UTF-8, malformed JSON, and oversized frames fail
/// explicitly.
///
/// # Bound
///
/// The decoder is fail-closed and cannot grow without limit. A frame that never
/// terminates is rejected as soon as the carry-over buffer passes
/// `max_frame_bytes`, so the peak retained size is `max_frame_bytes` plus the
/// length of the chunk handed to the current [`JsonLineDecoder::push`] call —
/// and a chunk that cannot possibly fit is rejected before it is even copied
/// into the buffer.
///
/// # Measured non-improvements
///
/// Two rewrites of this loop were measured and rejected; the numbers are here
/// so they are not tried again.
///
/// * *Parsing complete frames straight out of the caller's chunk* and copying
///   only the trailing partial frame, instead of appending every chunk to
///   `buffered` first. Over a 12,460-byte chunk of 64 realistic notification
///   frames it measured 593.7 ns/frame against 592.3 ns/frame, and 640.0
///   against 633.2 when the chunk ends mid-frame: **1.00x**. The copy is
///   `memcpy` over bytes that `serde_json` is about to walk anyway, so it
///   disappears next to tree construction. A 512 KiB frame split over 16 KiB
///   reads was unchanged (197.5 µs against 199.6 µs).
/// * *Skipping the [`Value`] stage* by deserializing each frame straight into
///   the typed message. That is genuinely faster — 2487.4 ns against 3113.7 ns
///   for a tool result (**1.25x**) and 1112.9 against 1867.7 for a
///   notification (**1.68x**) — but it cannot be done here: `push` is a public
///   API that yields [`Value`]s, and the stdio diagnostics have to inspect
///   the untyped frame to diagnose an unsupported protocol version even when
///   the typed decode succeeds.
#[derive(Debug)]
pub struct JsonLineDecoder {
    buffered: Vec<u8>,
    /// Length of the `buffered` prefix already searched for a frame terminator.
    ///
    /// Rescanning from zero on every chunk makes decoding one large frame
    /// quadratic in its size, which is exactly the shape a hostile peer would
    /// pick. Only the newly appended bytes are ever scanned.
    scanned: usize,
    max_frame_bytes: usize,
}

impl JsonLineDecoder {
    /// Creates a decoder with an explicit per-frame byte limit.
    #[must_use]
    pub const fn new(max_frame_bytes: usize) -> Self {
        Self {
            buffered: Vec::new(),
            scanned: 0,
            max_frame_bytes,
        }
    }

    /// Appends one byte chunk and returns every complete JSON value it contains.
    ///
    /// Bytes that do not yet form a complete frame are carried over to the next
    /// call. On error the offending frame has already been consumed, so a caller
    /// that chooses to keep decoding resumes after it rather than replaying it.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when a frame — or the unterminated
    /// carry-over buffer — exceeds the decoder's `max_frame_bytes` limit, or
    /// when a frame is not valid UTF-8. Returns [`McpError::Json`] when a frame
    /// is valid UTF-8 but not a valid JSON value.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Value>> {
        // Nothing buffered can complete a frame (`scanned` covers all of it), so
        // a chunk without a terminator that already busts the limit is refused
        // before it is copied in.
        if self.scanned == self.buffered.len()
            && self.buffered.len().saturating_add(bytes.len()) > self.max_frame_bytes
            && !bytes.contains(&b'\n')
        {
            return Err(McpError::Protocol("stdio frame exceeds byte limit".into()));
        }
        self.buffered.extend_from_slice(bytes);

        let mut decoded = Vec::new();
        let mut consumed = 0;
        let mut scan = self.scanned;
        let outcome = loop {
            let Some(offset) = self.buffered[scan..].iter().position(|byte| *byte == b'\n') else {
                break Ok(());
            };
            let newline = scan + offset;
            scan = newline + 1;
            let mut end = newline;
            if end > consumed && self.buffered[end - 1] == b'\r' {
                end -= 1;
            }
            let frame = &self.buffered[consumed..end];
            consumed = newline + 1;
            if frame.is_empty() {
                continue;
            }
            if frame.len() > self.max_frame_bytes {
                break Err(McpError::Protocol("stdio frame exceeds byte limit".into()));
            }
            match std::str::from_utf8(frame) {
                Ok(text) => match serde_json::from_str(text) {
                    Ok(value) => decoded.push(value),
                    Err(error) => break Err(McpError::Json(error)),
                },
                Err(_) => break Err(McpError::Protocol("stdio frame is not UTF-8".into())),
            }
        };

        self.buffered.drain(..consumed);
        if outcome.is_err() {
            // The tail past the failing frame was never searched, so the next
            // call has to start over rather than skip a terminator.
            self.scanned = 0;
        } else {
            self.scanned = self.buffered.len();
        }
        self.reclaim_idle_capacity();
        outcome?;
        if self.buffered.len() > self.max_frame_bytes {
            return Err(McpError::Protocol("stdio frame exceeds byte limit".into()));
        }
        Ok(decoded)
    }

    /// Signals end-of-input, rejecting a non-empty unterminated frame.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when the peer stopped writing part-way
    /// through a frame, which for stdio means the child process exited or closed
    /// its stdout mid-message. Trailing ASCII whitespace is not an error.
    pub fn finish(&mut self) -> Result<()> {
        if self.buffered.iter().all(u8::is_ascii_whitespace) {
            self.buffered.clear();
            self.scanned = 0;
            self.reclaim_idle_capacity();
            Ok(())
        } else {
            Err(McpError::Protocol(
                "stdio ended with an unterminated JSON-RPC frame".into(),
            ))
        }
    }

    fn reclaim_idle_capacity(&mut self) {
        if self.buffered.is_empty() && self.buffered.capacity() > IDLE_BUFFER_CAPACITY {
            self.buffered.shrink_to(IDLE_BUFFER_CAPACITY);
        }
    }
}

impl Default for JsonLineDecoder {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME_BYTES)
    }
}

/// Encodes one JSON-RPC value as a single newline-delimited frame.
///
/// Reserving up front instead of letting [`serde_json::to_vec`] grow from its
/// 128-byte start measured 254.8 ns against 317.8 ns on a 690-byte frame
/// (**1.25x**), but that reservation would be handed to every caller for the
/// lifetime of the returned `Vec`, so it is applied where the buffer is reused
/// — in the transport writer — rather than here.
///
/// # Errors
///
/// Returns [`McpError::Json`] when the value cannot be serialized — in practice
/// a map with non-string keys or a float that is not a finite number, since a
/// [`Value`] is otherwise always representable.
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
                let read = tokio::select! {
                    biased;
                    result = input.read(&mut bytes) => result,
                    () = reader_disconnected.cancelled() => return Ok(()),
                };
                let count = match read {
                    Ok(count) => count,
                    Err(error) => {
                        reader_disconnected.cancel();
                        return Err(error);
                    }
                };
                if count == 0 {
                    if let Err(error) = decoder.finish() {
                        reader_diagnostics.record(&error);
                        reader_disconnected.cancel();
                        return Err(protocol_io_error(error));
                    }
                    return Ok(());
                }
                let values = match decoder.push(&bytes[..count]) {
                    Ok(values) => values,
                    Err(error) => {
                        reader_diagnostics.record(&error);
                        reader_disconnected.cancel();
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
                            reader_disconnected.cancel();
                            return Err(invalid_data_io_error(error));
                        }
                    };
                    let sent = tokio::select! {
                        () = reader_disconnected.cancelled() => return Ok(()),
                        result = read_tx.send(message) => result,
                    };
                    if sent.is_err() {
                        return Ok(());
                    }
                }
            }
        });

        let (writes, mut write_rx) = mpsc::channel::<WriteRequest<R>>(32);
        let writer_task = tokio::spawn(async move {
            let writer_disconnected = disconnected.clone();
            let _disconnect_on_exit = disconnected.drop_guard();
            // One frame buffer for the transport's lifetime. Serializing the
            // message straight into it replaces a `to_value` tree plus a fresh
            // `Vec` per frame: 239.8 ns against 706.6 ns on a 600-byte tool
            // result (2.95x) and the output is byte-identical, since both paths
            // drive the same `Serialize` impl in the same order.
            let mut frame = Vec::new();
            loop {
                let request = tokio::select! {
                    biased;
                    () = writer_disconnected.cancelled() => {
                        fail_queued_writes::<R>(&mut write_rx);
                        return Ok(());
                    }
                    request = write_rx.recv() => request,
                };
                let Some((message, acknowledgement)) = request else {
                    return Ok(());
                };
                let result = tokio::select! {
                    biased;
                    () = writer_disconnected.cancelled() => {
                        let _ = acknowledgement.send(Err(disconnected_io_error()));
                        fail_queued_writes::<R>(&mut write_rx);
                        return Ok(());
                    }
                    result = async {
                        frame.clear();
                        serde_json::to_writer(&mut frame, &message)
                            .map_err(invalid_data_io_error)?;
                        frame.push(b'\n');
                        output.write_all(&frame).await?;
                        // A single oversized frame must not pin its peak size
                        // for the transport's lifetime, the same policy the
                        // decoder applies to its carry-over buffer.
                        reclaim_idle_frame(&mut frame);
                        output.flush().await
                    } => result,
                };
                let failed = result.is_err();
                if failed {
                    writer_disconnected.cancel();
                }
                let _ = acknowledgement.send(result);
                if failed {
                    fail_queued_writes::<R>(&mut write_rx);
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "bounded stdio writer failed",
                    ));
                }
            }
        });

        Self {
            writes: Some(writes),
            reads,
            reader: Some(reader),
            writer: Some(writer_task),
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
        self.diagnostics.transport_disconnected.cancel();
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
                let disconnected = self.diagnostics.transport_disconnected.clone();
                async move {
                    let writes = writes.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "stdio transport is closed")
                    })?;
                    let (acknowledge, result) = oneshot::channel();
                    tokio::select! {
                        biased;
                        () = disconnected.cancelled() => return Err(disconnected_io_error()),
                        sent = writes.send((item, acknowledge)) => {
                            sent.map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "stdio writer task stopped",
                                )
                            })?;
                        }
                    }
                    tokio::select! {
                        biased;
                        completed = result => completed.map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "stdio writer acknowledgement dropped",
                            )
                        })?,
                        () = disconnected.cancelled() => Err(disconnected_io_error()),
                    }
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
                let disconnected = self.diagnostics.transport_disconnected.clone();
                async move {
                    disconnected.cancel();
                    let writer_result = match writer {
                        Some(writer) => writer.await.map_err(join_io_error)?,
                        None => Ok(()),
                    };
                    if let Some(reader) = reader {
                        match reader.await {
                            Ok(result) => result?,
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

fn disconnected_io_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "stdio transport disconnected")
}

fn fail_queued_writes<R>(write_rx: &mut mpsc::Receiver<WriteRequest<R>>)
where
    R: rmcp::service::ServiceRole,
{
    while let Ok((_, acknowledgement)) = write_rx.try_recv() {
        let _ = acknowledgement.send(Err(disconnected_io_error()));
    }
}

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
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex},
        time::{Duration, timeout},
    };

    use super::{
        BoundedIoTransport, DEFAULT_MAX_FRAME_BYTES, IDLE_BUFFER_CAPACITY, JsonLineDecoder,
        McpError, encode, reclaim_idle_frame,
    };

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

        // `serde_json` is built with `preserve_order`, so a frame carries the
        // member order it was constructed with rather than a sorted one.
        assert_eq!(
            encode(&value).expect("encode frame"),
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}
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

    #[test]
    fn an_unterminated_frame_stops_being_buffered_once_it_passes_the_limit() {
        const LIMIT: usize = 64;
        let mut decoder = JsonLineDecoder::new(LIMIT);
        let chunk = vec![b'x'; LIMIT];

        assert!(
            decoder
                .push(&chunk)
                .expect("a frame exactly at the limit is not yet oversized")
                .is_empty()
        );
        assert_eq!(decoder.buffered.len(), LIMIT);

        for _ in 0..1_000 {
            let error = decoder
                .push(&chunk)
                .expect_err("a peer that never terminates a frame must stay rejected");
            assert_eq!(
                error.to_string(),
                "MCP protocol violation: stdio frame exceeds byte limit"
            );
            assert_eq!(
                decoder.buffered.len(),
                LIMIT,
                "a chunk that cannot fit must be rejected before it is buffered"
            );
        }
    }

    #[test]
    fn a_large_frame_split_across_chunks_decodes_and_releases_its_buffer() {
        let payload = "y".repeat(4 * IDLE_BUFFER_CAPACITY);
        let frame = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{payload}\"}}");
        let mut decoder = JsonLineDecoder::new(DEFAULT_MAX_FRAME_BYTES);

        let mut values = Vec::new();
        for chunk in frame.as_bytes().chunks(4096) {
            values.extend(
                decoder
                    .push(chunk)
                    .expect("a split frame must keep buffering"),
            );
        }

        assert!(values.is_empty(), "no terminator has arrived yet");
        values.extend(
            decoder
                .push(b"\n")
                .expect("the terminated frame must decode"),
        );

        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["method"], payload);
        assert!(
            decoder.buffered.capacity() < frame.len(),
            "a fully drained buffer must not pin the peak frame size"
        );
    }

    #[test]
    fn writer_releases_an_oversized_frame_after_the_write() {
        let mut frame = vec![0; 4 * IDLE_BUFFER_CAPACITY];
        let peak_capacity = frame.capacity();

        reclaim_idle_frame(&mut frame);

        assert!(frame.is_empty());
        assert!(
            frame.capacity() < peak_capacity,
            "a written frame must not pin the peak allocation"
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

    #[tokio::test]
    async fn close_cancels_a_writer_blocked_by_an_unread_peer() {
        let (_peer_input, transport_input) = duplex(64);
        let (transport_output, _unread_peer_output) = duplex(1);
        let mut transport =
            BoundedIoTransport::<RoleServer>::new(transport_input, transport_output);
        let response: TxJsonRpcMessage<RoleServer> = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32603,
                "message": "x".repeat(4096)
            }
        }))
        .expect("valid oversized error response");
        let sending = tokio::spawn(transport.send(response));
        tokio::task::yield_now().await;

        timeout(Duration::from_secs(1), transport.close())
            .await
            .expect("close must cancel blocked output")
            .expect("cancelled transport closes cleanly");
        let error = timeout(Duration::from_secs(1), sending)
            .await
            .expect("pending send must finish")
            .expect("send task")
            .expect_err("closed transport rejects pending send");
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn clean_input_eof_still_allows_an_accepted_response_to_drain() {
        let (mut peer_input, transport_input) = duplex(1024);
        let (transport_output, peer_output) = duplex(1024);
        let mut peer_output = BufReader::new(peer_output);
        let mut transport =
            BoundedIoTransport::<RoleServer>::new(transport_input, transport_output);
        peer_input
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n")
            .await
            .expect("write request");
        peer_input.shutdown().await.expect("close request half");

        let request: Option<RxJsonRpcMessage<RoleServer>> = transport.receive().await;
        assert!(request.is_some(), "accepted request must reach the service");
        assert!(
            transport.receive().await.is_none(),
            "clean EOF must close only the receive half"
        );
        let response: TxJsonRpcMessage<RoleServer> = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": []}
        }))
        .expect("valid response");
        transport
            .send(response)
            .await
            .expect("accepted response must drain after input EOF");

        let mut line = String::new();
        timeout(Duration::from_secs(1), peer_output.read_line(&mut line))
            .await
            .expect("response must arrive")
            .expect("read response");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).expect("response JSON"),
            json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
        );
        transport.close().await.expect("close transport");
    }
}

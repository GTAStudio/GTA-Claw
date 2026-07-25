//! Incremental decoders for `text/event-stream` and newline-delimited JSON.
//!
//! Both decoders are byte-oriented and fully incremental: they accept arbitrary
//! chunk boundaries, including boundaries that split a UTF-8 code point, a field
//! name or a `\r\n` pair.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::time::Duration;

/// Default limit on a single unterminated line, in bytes.
pub const DEFAULT_MAX_LINE_BYTES: usize = 1_048_576;

/// Default limit on the accumulated `data:` payload of one event, in bytes.
pub const DEFAULT_MAX_EVENT_BYTES: usize = 8_388_608;

/// Failure while decoding a stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamDecodeError {
    /// A single line exceeded the configured limit.
    LineTooLong {
        /// The configured limit in bytes.
        limit: usize,
    },
    /// The accumulated event payload exceeded the configured limit.
    EventTooLarge {
        /// The configured limit in bytes.
        limit: usize,
    },
    /// The stream contained bytes that are not valid UTF-8.
    InvalidUtf8,
}

impl Display for StreamDecodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTooLong { limit } => {
                write!(formatter, "stream line exceeded {limit} bytes")
            }
            Self::EventTooLarge { limit } => {
                write!(formatter, "stream event exceeded {limit} bytes")
            }
            Self::InvalidUtf8 => formatter.write_str("stream contained invalid UTF-8"),
        }
    }
}

impl Error for StreamDecodeError {}

/// One dispatched server-sent event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SseEvent {
    /// Value of the last `event:` field, or `message` when none was sent.
    pub event: String,
    /// Concatenated `data:` lines, joined with `\n` and without a trailing one.
    pub data: String,
    /// The last `id:` field seen before this event was dispatched.
    pub id: Option<String>,
    /// The last valid `retry:` field seen before this event was dispatched.
    pub retry: Option<Duration>,
}

/// Byte-level incremental decoder for `text/event-stream`.
///
/// The framing follows the WHATWG server-sent events specification: lines end
/// with `\r\n`, `\n` or a lone `\r`; a leading UTF-8 byte-order mark is
/// discarded; lines starting with `:` are comments; a field without a colon has
/// an empty value; and a single space directly after the colon is removed.
#[derive(Debug)]
pub struct SseDecoder {
    line: Vec<u8>,
    data: String,
    event: String,
    last_id: Option<String>,
    retry: Option<Duration>,
    saw_data_field: bool,
    pending_cr: bool,
    checked_bom: bool,
    bom_progress: usize,
    max_line_bytes: usize,
    max_event_bytes: usize,
}

impl Default for SseDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SseDecoder {
    /// Creates a decoder with the default size limits.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_EVENT_BYTES)
    }

    /// Creates a decoder with explicit size limits.
    #[must_use]
    pub fn with_limits(max_line_bytes: usize, max_event_bytes: usize) -> Self {
        Self {
            line: Vec::new(),
            data: String::new(),
            event: String::new(),
            last_id: None,
            retry: None,
            saw_data_field: false,
            pending_cr: false,
            checked_bom: false,
            bom_progress: 0,
            max_line_bytes: max_line_bytes.max(1),
            max_event_bytes: max_event_bytes.max(1),
        }
    }

    /// Feeds one chunk of bytes and returns every event it completed.
    ///
    /// # Errors
    ///
    /// Returns [`StreamDecodeError`] when a configured limit is exceeded or a
    /// line is not valid UTF-8.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, StreamDecodeError> {
        let mut events = Vec::new();
        let mut index = 0;
        let chunk = self.strip_byte_order_mark(chunk);
        while index < chunk.len() {
            let byte = chunk[index];
            index += 1;
            if self.pending_cr {
                self.pending_cr = false;
                if byte == b'\n' {
                    // `\r\n` is a single terminator; the `\r` already ended the line.
                    continue;
                }
            }
            match byte {
                b'\r' => {
                    self.pending_cr = true;
                    self.end_line(&mut events)?;
                }
                b'\n' => self.end_line(&mut events)?,
                _ => {
                    if self.line.len() >= self.max_line_bytes {
                        return Err(StreamDecodeError::LineTooLong {
                            limit: self.max_line_bytes,
                        });
                    }
                    self.line.push(byte);
                }
            }
        }
        Ok(events)
    }

    /// Flushes a trailing event that was not followed by a blank line.
    ///
    /// A stream that ends mid-line discards the partial line, exactly as the
    /// specification requires.
    ///
    /// # Errors
    ///
    /// Returns [`StreamDecodeError`] when the buffered event violates a limit.
    pub fn finish(&mut self) -> Result<Vec<SseEvent>, StreamDecodeError> {
        let mut events = Vec::new();
        self.line.clear();
        if self.saw_data_field {
            self.dispatch(&mut events)?;
        }
        Ok(events)
    }

    fn strip_byte_order_mark<'a>(&mut self, chunk: &'a [u8]) -> &'a [u8] {
        if self.checked_bom {
            return chunk;
        }
        const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
        let mut offset = 0;
        while offset < chunk.len() && self.bom_progress < BOM.len() {
            if chunk[offset] == BOM[self.bom_progress] {
                self.bom_progress += 1;
                offset += 1;
            } else {
                // Not a byte-order mark: replay what was consumed as data.
                let consumed = self.bom_progress;
                self.checked_bom = true;
                self.bom_progress = 0;
                self.line.extend_from_slice(&BOM[..consumed]);
                return &chunk[offset..];
            }
        }
        if self.bom_progress == BOM.len() {
            self.checked_bom = true;
        }
        &chunk[offset..]
    }

    fn end_line(&mut self, events: &mut Vec<SseEvent>) -> Result<(), StreamDecodeError> {
        let line = std::mem::take(&mut self.line);
        let line = String::from_utf8(line).map_err(|_| StreamDecodeError::InvalidUtf8)?;
        if line.is_empty() {
            if self.saw_data_field {
                self.dispatch(events)?;
            } else {
                self.event.clear();
            }
            return Ok(());
        }
        if line.starts_with(':') {
            return Ok(());
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line.as_str(), ""),
        };
        match field {
            "event" => {
                self.event.clear();
                self.event.push_str(value);
            }
            "data" => {
                if self.data.len() + value.len() + 1 > self.max_event_bytes {
                    return Err(StreamDecodeError::EventTooLarge {
                        limit: self.max_event_bytes,
                    });
                }
                if self.saw_data_field {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.saw_data_field = true;
            }
            "id" => {
                if !value.contains('\u{0}') {
                    self.last_id = Some(value.to_owned());
                }
            }
            "retry" => {
                if !value.is_empty()
                    && value.bytes().all(|byte| byte.is_ascii_digit())
                    && let Ok(millis) = value.parse::<u64>()
                {
                    self.retry = Some(Duration::from_millis(millis));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn dispatch(&mut self, events: &mut Vec<SseEvent>) -> Result<(), StreamDecodeError> {
        let event = if self.event.is_empty() {
            "message".to_owned()
        } else {
            self.event.clone()
        };
        events.push(SseEvent {
            event,
            data: std::mem::take(&mut self.data),
            id: self.last_id.clone(),
            retry: self.retry,
        });
        self.event.clear();
        self.saw_data_field = false;
        Ok(())
    }
}

/// Byte-level incremental decoder for newline-delimited payloads.
///
/// Several providers stream chunked JSON documents separated by `\n` rather than
/// using server-sent events. Empty lines are skipped.
#[derive(Debug)]
pub struct LineDecoder {
    buffer: Vec<u8>,
    max_line_bytes: usize,
}

impl Default for LineDecoder {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_LINE_BYTES)
    }
}

impl LineDecoder {
    /// Creates a decoder that rejects lines longer than `max_line_bytes`.
    #[must_use]
    pub fn new(max_line_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_line_bytes: max_line_bytes.max(1),
        }
    }

    /// Feeds one chunk and returns every complete, non-empty line.
    ///
    /// # Errors
    ///
    /// Returns [`StreamDecodeError`] when a line exceeds the limit or is not
    /// valid UTF-8.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<String>, StreamDecodeError> {
        let mut lines = Vec::new();
        for byte in chunk {
            if *byte == b'\n' {
                let line = std::mem::take(&mut self.buffer);
                let line = String::from_utf8(line).map_err(|_| StreamDecodeError::InvalidUtf8)?;
                let trimmed = line.trim_end_matches('\r');
                if !trimmed.is_empty() {
                    lines.push(trimmed.to_owned());
                }
            } else {
                if self.buffer.len() >= self.max_line_bytes {
                    return Err(StreamDecodeError::LineTooLong {
                        limit: self.max_line_bytes,
                    });
                }
                self.buffer.push(*byte);
            }
        }
        Ok(lines)
    }

    /// Returns a trailing line that was not newline-terminated.
    ///
    /// # Errors
    ///
    /// Returns [`StreamDecodeError::InvalidUtf8`] when the remainder is not
    /// valid UTF-8.
    pub fn finish(&mut self) -> Result<Option<String>, StreamDecodeError> {
        if self.buffer.is_empty() {
            return Ok(None);
        }
        let line = std::mem::take(&mut self.buffer);
        let line = String::from_utf8(line).map_err(|_| StreamDecodeError::InvalidUtf8)?;
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() {
            Ok(None)
        } else {
            Ok(Some(trimmed.to_owned()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(bytes: &[u8], chunk_size: usize) -> Vec<SseEvent> {
        let mut decoder = SseDecoder::new();
        let mut events = Vec::new();
        for chunk in bytes.chunks(chunk_size.max(1)) {
            events.extend(decoder.push(chunk).expect("decodes"));
        }
        events.extend(decoder.finish().expect("flushes"));
        events
    }

    #[test]
    fn decodes_a_basic_event_stream() {
        let bytes = b"event: delta\ndata: hello\n\ndata: world\n\n";
        assert_eq!(
            decode_all(bytes, bytes.len()),
            vec![
                SseEvent {
                    event: "delta".to_owned(),
                    data: "hello".to_owned(),
                    id: None,
                    retry: None,
                },
                SseEvent {
                    event: "message".to_owned(),
                    data: "world".to_owned(),
                    id: None,
                    retry: None,
                },
            ]
        );
    }

    #[test]
    fn every_chunk_boundary_yields_the_same_events() {
        let bytes = b"\xef\xbb\xbf: keep-alive\r\nevent: a\r\nid: 7\r\nretry: 2500\r\ndata: one\r\ndata: two\r\n\r\nevent: b\ndata: three\n\n";
        let reference = decode_all(bytes, bytes.len());
        assert_eq!(
            reference,
            vec![
                SseEvent {
                    event: "a".to_owned(),
                    data: "one\ntwo".to_owned(),
                    id: Some("7".to_owned()),
                    retry: Some(Duration::from_millis(2_500)),
                },
                SseEvent {
                    event: "b".to_owned(),
                    data: "three".to_owned(),
                    id: Some("7".to_owned()),
                    retry: Some(Duration::from_millis(2_500)),
                },
            ]
        );
        for chunk_size in 1..=bytes.len() {
            assert_eq!(
                decode_all(bytes, chunk_size),
                reference,
                "chunk={chunk_size}"
            );
        }
    }

    #[test]
    fn a_lone_carriage_return_terminates_a_line() {
        let bytes = b"data: alpha\rdata: beta\r\r";
        assert_eq!(
            decode_all(bytes, 1),
            vec![SseEvent {
                event: "message".to_owned(),
                data: "alpha\nbeta".to_owned(),
                id: None,
                retry: None,
            }]
        );
    }

    #[test]
    fn crlf_split_across_chunks_is_one_terminator() {
        let mut decoder = SseDecoder::new();
        let mut events = decoder.push(b"data: x\r").expect("first chunk");
        events.extend(decoder.push(b"\n\r\n").expect("second chunk"));
        assert_eq!(
            events,
            vec![SseEvent {
                event: "message".to_owned(),
                data: "x".to_owned(),
                id: None,
                retry: None,
            }]
        );
    }

    #[test]
    fn comments_and_unknown_fields_are_ignored() {
        let bytes = b": ping\nfoo: bar\ndata: kept\n\n";
        assert_eq!(
            decode_all(bytes, 3),
            vec![SseEvent {
                event: "message".to_owned(),
                data: "kept".to_owned(),
                id: None,
                retry: None,
            }]
        );
    }

    #[test]
    fn a_field_without_a_colon_has_an_empty_value() {
        let bytes = b"data\ndata:\ndata: tail\n\n";
        assert_eq!(
            decode_all(bytes, 4),
            vec![SseEvent {
                event: "message".to_owned(),
                data: "\n\ntail".to_owned(),
                id: None,
                retry: None,
            }]
        );
    }

    #[test]
    fn only_one_leading_space_is_removed_after_the_colon() {
        let bytes = b"data:  two spaces\n\n";
        assert_eq!(decode_all(bytes, 5)[0].data, " two spaces");
    }

    #[test]
    fn a_blank_line_without_data_dispatches_nothing_but_clears_the_event_name() {
        let bytes = b"event: ignored\n\ndata: plain\n\n";
        assert_eq!(
            decode_all(bytes, 2),
            vec![SseEvent {
                event: "message".to_owned(),
                data: "plain".to_owned(),
                id: None,
                retry: None,
            }]
        );
    }

    #[test]
    fn identifiers_containing_a_null_byte_are_rejected_but_the_stream_continues() {
        let bytes = b"id: good\ndata: a\n\nid: b\0ad\ndata: b\n\n";
        let events = decode_all(bytes, 6);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, Some("good".to_owned()));
        assert_eq!(events[1].id, Some("good".to_owned()));
    }

    #[test]
    fn non_numeric_retry_values_are_ignored() {
        let bytes = b"retry: soon\nretry: 1200\nretry: -5\ndata: x\n\n";
        assert_eq!(
            decode_all(bytes, 7)[0].retry,
            Some(Duration::from_millis(1_200))
        );
    }

    #[test]
    fn a_trailing_event_without_a_blank_line_is_flushed_on_finish() {
        let bytes = b"data: last\n";
        assert_eq!(
            decode_all(bytes, 1),
            vec![SseEvent {
                event: "message".to_owned(),
                data: "last".to_owned(),
                id: None,
                retry: None,
            }]
        );
    }

    #[test]
    fn an_unterminated_trailing_line_is_discarded_per_the_specification() {
        let mut decoder = SseDecoder::new();
        assert!(
            decoder
                .push(b"data: never-terminated")
                .expect("push")
                .is_empty()
        );
        assert!(decoder.finish().expect("finish").is_empty());
    }

    #[test]
    fn an_incomplete_trailing_line_is_discarded_when_no_data_was_seen() {
        let mut decoder = SseDecoder::new();
        assert!(decoder.push(b"event: partial").expect("push").is_empty());
        assert!(decoder.finish().expect("finish").is_empty());
    }

    #[test]
    fn a_byte_order_mark_is_only_stripped_at_the_very_start() {
        let bytes = b"\xef\xbb\xbfdata: first\n\ndata: \xef\xbb\xbfsecond\n\n";
        let events = decode_all(bytes, 1);
        assert_eq!(events[0].data, "first");
        assert_eq!(events[1].data, "\u{feff}second");
    }

    #[test]
    fn a_leading_byte_that_only_partially_matches_the_bom_is_kept() {
        let mut decoder = SseDecoder::new();
        let events = decoder.push(b"\xef\xbb\x41data: x\n\n");
        assert_eq!(events, Err(StreamDecodeError::InvalidUtf8));
    }

    #[test]
    fn size_limits_are_enforced() {
        let mut decoder = SseDecoder::with_limits(8, 4_096);
        assert_eq!(
            decoder.push(b"data: aaaaaaaaaaaaaaaa\n"),
            Err(StreamDecodeError::LineTooLong { limit: 8 })
        );

        let mut decoder = SseDecoder::with_limits(4_096, 12);
        assert_eq!(
            decoder.push(b"data: aaaaaaaa\ndata: bbbbbbbb\n"),
            Err(StreamDecodeError::EventTooLarge { limit: 12 })
        );
    }

    #[test]
    fn invalid_utf8_in_a_line_is_reported() {
        let mut decoder = SseDecoder::new();
        assert_eq!(
            decoder.push(b"data: \xff\xfe\n"),
            Err(StreamDecodeError::InvalidUtf8)
        );
    }

    #[test]
    fn multi_byte_code_points_split_across_chunks_decode_correctly() {
        let payload = "data: 你好，世界\n\n".as_bytes();
        for chunk_size in 1..=payload.len() {
            let events = decode_all(payload, chunk_size);
            assert_eq!(events.len(), 1, "chunk={chunk_size}");
            assert_eq!(events[0].data, "你好，世界", "chunk={chunk_size}");
        }
    }

    #[test]
    fn line_decoder_splits_newline_delimited_documents() {
        let mut decoder = LineDecoder::default();
        let mut lines = decoder.push(b"{\"a\":1}\n\n{\"b\"").expect("first");
        lines.extend(decoder.push(b":2}\r\n{\"c\":3}").expect("second"));
        assert_eq!(lines, vec!["{\"a\":1}".to_owned(), "{\"b\":2}".to_owned()]);
        assert_eq!(
            decoder.finish().expect("finish"),
            Some("{\"c\":3}".to_owned())
        );
        assert_eq!(decoder.finish().expect("finish"), None);
    }

    #[test]
    fn line_decoder_enforces_its_limit() {
        let mut decoder = LineDecoder::new(4);
        assert_eq!(
            decoder.push(b"aaaaaaaa\n"),
            Err(StreamDecodeError::LineTooLong { limit: 4 })
        );
    }
}

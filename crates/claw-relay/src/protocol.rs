use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One Chrome tab explicitly shared with the relay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelayTab {
    /// Chrome tab identity.
    pub tab_id: u64,
    /// Current tab URL.
    pub url: String,
    /// Current title.
    pub title: String,
    /// Whether the tab is active.
    pub active: bool,
}

/// Strict extension-to-relay wire message.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "type")]
pub enum ExtensionMessage {
    /// Mandatory first frame.
    Hello {
        /// Browser user agent.
        user_agent: String,
        /// Browser product version.
        browser_version: String,
        /// Extension version.
        extension_version: String,
        /// Complete shared-tab snapshot.
        tabs: Vec<RelayTab>,
    },
    /// Complete shared-tab refresh.
    Tabs {
        /// Complete shared-tab snapshot.
        tabs: Vec<RelayTab>,
    },
    /// CDP event from one attached tab.
    #[serde(rename = "cdpEvent")]
    CdpEvent {
        /// Chrome tab identity.
        tab_id: u64,
        /// Optional child debugger session.
        #[serde(default)]
        session_id: Option<String>,
        /// CDP event method.
        method: String,
        /// Optional CDP parameters.
        #[serde(default)]
        params: Option<Value>,
    },
    /// Successful extension command result.
    Result {
        /// Relay command sequence.
        seq: u64,
        /// Optional command result.
        #[serde(default)]
        result: Option<Value>,
    },
    /// Failed extension command.
    Error {
        /// Relay command sequence.
        seq: u64,
        /// Failure message.
        message: String,
    },
    /// Debugger detached outside relay control.
    Detached {
        /// Chrome tab identity.
        tab_id: u64,
        /// Chrome detach reason.
        reason: String,
    },
    /// Keepalive response.
    Pong,
}

/// Strict CDP request frame accepted from an automation client.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CdpRequest {
    /// Client request identity.
    pub id: u64,
    /// Exact CDP method.
    pub method: String,
    /// Optional CDP parameters.
    #[serde(default)]
    pub params: Option<Value>,
    /// Optional flattened debugger session.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Decodes one complete bounded extension text frame.
///
/// # Errors
///
/// Returns [`FrameError::InvalidBound`] when `max_frame_bytes` is zero,
/// [`FrameError::TooLarge`] when the complete frame exceeds that bound,
/// [`FrameError::InvalidUtf8`] when the text frame is not UTF-8, and
/// [`FrameError::InvalidJson`] when the frame is not a JSON object, carries no
/// known `type` discriminant, or holds any key outside the exact set that
/// discriminant allows. Unknown keys are refused rather than ignored, so an
/// extension cannot smuggle a field past the strict message shape.
pub fn decode_extension_frame(
    bytes: &[u8],
    max_frame_bytes: usize,
) -> Result<ExtensionMessage, FrameError> {
    let value: Value = decode(bytes, max_frame_bytes)?;
    let object = value.as_object().ok_or(FrameError::InvalidJson)?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(FrameError::InvalidJson)?;
    let allowed: &[&str] = match kind {
        "hello" => &[
            "type",
            "userAgent",
            "browserVersion",
            "extensionVersion",
            "tabs",
        ],
        "tabs" => &["type", "tabs"],
        "cdpEvent" => &["type", "tabId", "sessionId", "method", "params"],
        "result" => &["type", "seq", "result"],
        "error" => &["type", "seq", "message"],
        "detached" => &["type", "tabId", "reason"],
        "pong" => &["type"],
        _ => return Err(FrameError::InvalidJson),
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(FrameError::InvalidJson);
    }
    serde_json::from_value(value).map_err(|_| FrameError::InvalidJson)
}

/// Decodes one complete bounded CDP text frame.
///
/// # Errors
///
/// Returns [`FrameError::InvalidBound`] when `max_frame_bytes` is zero,
/// [`FrameError::TooLarge`] when the complete frame exceeds that bound,
/// [`FrameError::InvalidUtf8`] when the text frame is not UTF-8, and
/// [`FrameError::InvalidJson`] when the frame is not a [`CdpRequest`] — a
/// missing `id` or `method`, a wrong field type, or any unknown field.
pub fn decode_cdp_frame(bytes: &[u8], max_frame_bytes: usize) -> Result<CdpRequest, FrameError> {
    decode(bytes, max_frame_bytes)
}

fn decode<T>(bytes: &[u8], max_frame_bytes: usize) -> Result<T, FrameError>
where
    T: for<'de> Deserialize<'de>,
{
    if max_frame_bytes == 0 {
        return Err(FrameError::InvalidBound);
    }
    if bytes.len() > max_frame_bytes {
        return Err(FrameError::TooLarge {
            actual: bytes.len(),
            limit: max_frame_bytes,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| FrameError::InvalidUtf8)?;
    serde_json::from_str(text).map_err(|_| FrameError::InvalidJson)
}

/// Complete-frame decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// Byte bound must be positive.
    InvalidBound,
    /// Complete message exceeded the configured bound.
    TooLarge {
        /// Received bytes.
        actual: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Text frame was not UTF-8.
    InvalidUtf8,
    /// JSON or strict message shape was invalid.
    InvalidJson,
}

impl Display for FrameError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBound => formatter.write_str("relay frame bound must be positive"),
            Self::TooLarge { actual, limit } => {
                write!(formatter, "relay frame is {actual} bytes; limit is {limit}")
            }
            Self::InvalidUtf8 => formatter.write_str("relay text frame is not UTF-8"),
            Self::InvalidJson => formatter.write_str("relay frame is not a valid strict message"),
        }
    }
}

impl Error for FrameError {}

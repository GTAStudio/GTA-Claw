//! Frozen `OpenClaw` conversation projection exposed through MCP.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime},
};

use rmcp::{
    ErrorData,
    model::{
        CallToolRequestParams, CallToolResult, ContentBlock, JsonObject, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::sync::Notify;

use crate::{
    error::{McpError, Result},
    server::{McpBackend, OperationContext},
};

const EVENT_QUEUE_LIMIT: usize = 1_000;
const CONVERSATIONS_LIST_LIMIT: usize = 500;
const MESSAGES_READ_LIMIT: usize = 200;
const PENDING_APPROVAL_DEFAULT_TTL_MS: i64 = 30 * 60 * 1_000;

/// Gateway routing context used to derive an MCP conversation.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryContext {
    /// Channel provider identifier.
    pub channel: Option<String>,
    /// Provider-native recipient identifier.
    pub to: Option<String>,
    /// Provider account identifier.
    pub account_id: Option<String>,
    /// Optional thread identifier.
    pub thread_id: Option<Value>,
}

/// Gateway origin context used as the lowest-priority routing fallback.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginContext {
    /// Origin provider identifier.
    pub provider: Option<String>,
    /// Origin account identifier.
    pub account_id: Option<String>,
    /// Origin thread identifier.
    pub thread_id: Option<Value>,
}

/// Session row accepted by the compatibility projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRow {
    /// Stable GTA-Claw session key.
    pub key: String,
    /// Direct channel field retained by older Gateway responses.
    pub channel: Option<String>,
    /// Last known channel.
    pub last_channel: Option<String>,
    /// Last known recipient.
    pub last_to: Option<String>,
    /// Last known account.
    pub last_account_id: Option<String>,
    /// Last known thread.
    pub last_thread_id: Option<Value>,
    /// Preferred delivery route.
    pub delivery_context: Option<DeliveryContext>,
    /// Session origin.
    pub origin: Option<OriginContext>,
    /// Optional operator label.
    pub label: Option<String>,
    /// Optional display name.
    pub display_name: Option<String>,
    /// Optional derived title.
    pub derived_title: Option<String>,
    /// Optional last-message preview.
    pub last_message_preview: Option<String>,
    /// Last update time in Unix milliseconds.
    pub updated_at: Option<i64>,
}

/// Reply-capable conversation shape frozen by `OpenClaw` 2026.7.2.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationDescriptor {
    /// Stable session key.
    pub session_key: String,
    /// Lowercase channel identifier.
    pub channel: String,
    /// Provider recipient.
    pub to: String,
    /// Optional provider account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// Optional provider thread.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<Value>,
    /// Optional operator label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Optional display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional derived title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_title: Option<String>,
    /// Optional last-message preview.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_message_preview: Option<String>,
    /// Last update time, explicitly null when unavailable.
    pub updated_at: Option<i64>,
}

/// Converts a Gateway session row into a reply-capable conversation.
#[must_use]
pub fn project_conversation(row: &SessionRow) -> Option<ConversationDescriptor> {
    let delivery = row.delivery_context.as_ref();
    let origin = row.origin.as_ref();
    let channel = first_text([
        delivery.and_then(|value| value.channel.as_deref()),
        row.last_channel.as_deref(),
        row.channel.as_deref(),
        origin.and_then(|value| value.provider.as_deref()),
    ])?
    .to_ascii_lowercase();
    let to = first_text([
        delivery.and_then(|value| value.to.as_deref()),
        row.last_to.as_deref(),
    ])?;
    let account_id = first_text([
        delivery.and_then(|value| value.account_id.as_deref()),
        row.last_account_id.as_deref(),
        origin.and_then(|value| value.account_id.as_deref()),
    ]);
    let thread_id = delivery
        .and_then(|value| value.thread_id.clone())
        .or_else(|| row.last_thread_id.clone())
        .or_else(|| origin.and_then(|value| value.thread_id.clone()));

    Some(ConversationDescriptor {
        session_key: row.key.clone(),
        channel,
        to,
        account_id,
        thread_id,
        label: trimmed(row.label.as_deref()),
        display_name: trimmed(row.display_name.as_deref()),
        derived_title: trimmed(row.derived_title.as_deref()),
        last_message_preview: trimmed(row.last_message_preview.as_deref()),
        updated_at: row.updated_at,
    })
}

fn first_text<const N: usize>(values: [Option<&str>; N]) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .find_map(|value| trimmed(Some(value)))
}

fn trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// One conversation message as returned by the Gateway history API.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectedMessage {
    /// Optional visible message identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Message actor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Raw structured message content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    /// Additional upstream-compatible message properties.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Returns non-text content blocks from a projected message.
#[must_use]
pub fn attachments(message: &ProjectedMessage) -> Vec<Value> {
    message
        .content
        .as_ref()
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| {
                    item.as_object().is_some_and(|object| {
                        object.get("type").and_then(Value::as_str) != Some("text")
                    })
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Future returned by the Gateway conversation projection port.
pub type ConversationFuture<'a> = Pin<Box<dyn Future<Output = Result<Value>> + Send + 'a>>;

/// Narrow Gateway request port used by the MCP conversation projection.
pub trait ConversationGatewayPort: Send + Sync + 'static {
    /// Sends one named Gateway request and returns its JSON result.
    fn request<'a>(&'a self, method: &'static str, params: Value) -> ConversationFuture<'a>;
}

/// Optional filters accepted by the upstream `conversations_list` tool.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListConversationsOptions {
    /// Maximum rows to ask the Gateway for, clamped to 1 through 500.
    pub limit: Option<usize>,
    /// Optional Gateway session search expression.
    pub search: Option<String>,
    /// Optional channel filter applied after route projection.
    pub channel: Option<String>,
    /// Whether the Gateway should derive titles.
    pub include_derived_titles: Option<bool>,
    /// Whether the Gateway should include last-message previews.
    pub include_last_message: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SessionListResult {
    #[serde(default)]
    sessions: Vec<SessionRow>,
}

#[derive(Debug, Deserialize)]
struct SessionDescribeResult {
    session: Option<SessionRow>,
}

#[derive(Debug, Deserialize)]
struct ChatHistoryResult {
    #[serde(default)]
    messages: Vec<ProjectedMessage>,
}

/// Upstream-compatible conversation operations backed by the Gateway port.
pub struct ConversationProjection {
    gateway: Arc<dyn ConversationGatewayPort>,
    approvals: Mutex<PendingApprovalQueue>,
    events: Mutex<ConversationEventQueue>,
    event_notify: Notify,
}

impl fmt::Debug for ConversationProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConversationProjection")
            .finish_non_exhaustive()
    }
}

impl ConversationProjection {
    /// Creates a conversation projection over a Gateway request port.
    #[must_use]
    pub fn new(gateway: Arc<dyn ConversationGatewayPort>) -> Self {
        Self {
            gateway,
            approvals: Mutex::new(PendingApprovalQueue::default()),
            events: Mutex::new(ConversationEventQueue::default()),
            event_notify: Notify::new(),
        }
    }

    /// Lists reply-capable conversations through `sessions.list`.
    ///
    /// # Errors
    ///
    /// Returns the Gateway port's error when the `sessions.list` request fails,
    /// and [`McpError::Json`] when the Gateway answers with a payload whose
    /// `sessions` array does not deserialize into session rows. Sessions that
    /// carry no usable channel or recipient are skipped, not reported as errors.
    pub async fn list_conversations(
        &self,
        options: ListConversationsOptions,
    ) -> Result<Vec<ConversationDescriptor>> {
        let limit = options
            .limit
            .unwrap_or(50)
            .clamp(1, CONVERSATIONS_LIST_LIMIT);
        let mut params = Map::from_iter([
            ("limit".into(), json!(limit)),
            (
                "includeDerivedTitles".into(),
                json!(options.include_derived_titles.unwrap_or(true)),
            ),
            (
                "includeLastMessage".into(),
                json!(options.include_last_message.unwrap_or(true)),
            ),
        ]);
        if let Some(search) = options.search {
            params.insert("search".into(), Value::String(search));
        }
        let response: SessionListResult = serde_json::from_value(
            self.gateway
                .request("sessions.list", Value::Object(params))
                .await?,
        )?;
        let requested_channel =
            trimmed(options.channel.as_deref()).map(|value| value.to_lowercase());
        Ok(response
            .sessions
            .iter()
            .filter_map(project_conversation)
            .filter(|conversation| {
                requested_channel
                    .as_ref()
                    .is_none_or(|channel| conversation.channel == *channel)
            })
            .collect())
    }

    /// Resolves one reply-capable conversation through `sessions.describe`.
    ///
    /// # Errors
    ///
    /// Returns the Gateway port's error when the `sessions.describe` request
    /// fails, and [`McpError::Json`] when its payload does not deserialize into
    /// a session row. A blank key, an unknown session, and a session with no
    /// reply route all yield `Ok(None)`.
    pub async fn get_conversation(
        &self,
        session_key: &str,
    ) -> Result<Option<ConversationDescriptor>> {
        let Some(session_key) = trimmed(Some(session_key)) else {
            return Ok(None);
        };
        let response: SessionDescribeResult = serde_json::from_value(
            self.gateway
                .request(
                    "sessions.describe",
                    json!({
                        "key": session_key,
                        "includeDerivedTitles": true,
                        "includeLastMessage": true
                    }),
                )
                .await?,
        )?;
        Ok(response.session.as_ref().and_then(project_conversation))
    }

    /// Reads recent messages through `sessions.get`.
    ///
    /// # Errors
    ///
    /// Returns the Gateway port's error when the `sessions.get` request fails,
    /// and [`McpError::Json`] when its `messages` array does not deserialize.
    /// `limit` is clamped to 1 through 200 rather than rejected.
    pub async fn read_messages(
        &self,
        session_key: &str,
        limit: Option<usize>,
    ) -> Result<Vec<ProjectedMessage>> {
        let limit = limit.unwrap_or(20).clamp(1, MESSAGES_READ_LIMIT);
        let response: ChatHistoryResult = serde_json::from_value(
            self.gateway
                .request("sessions.get", json!({"key": session_key, "limit": limit}))
                .await?,
        )?;
        Ok(response.messages)
    }

    /// Sends a reply through the route resolved by `sessions.describe`.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when the session has no reply-capable
    /// route — it does not exist, or it never recorded a channel and recipient —
    /// or when the operating system refuses the randomness used for the send's
    /// idempotency key. Returns the Gateway port's error when either the route
    /// lookup or the `send` request fails, and [`McpError::Json`] when the
    /// route lookup payload does not deserialize.
    pub async fn send_message(&self, session_key: &str, text: &str) -> Result<Value> {
        let conversation = self.get_conversation(session_key).await?.ok_or_else(|| {
            McpError::Protocol(format!("conversation not found for session {session_key}"))
        })?;
        let mut params = Map::from_iter([
            ("to".into(), Value::String(conversation.to)),
            ("channel".into(), Value::String(conversation.channel)),
            ("message".into(), Value::String(text.to_owned())),
            ("sessionKey".into(), Value::String(conversation.session_key)),
            (
                "idempotencyKey".into(),
                Value::String(crate::secure_random::uuid_v4()?),
            ),
        ]);
        if let Some(account_id) = conversation.account_id {
            params.insert("accountId".into(), Value::String(account_id));
        }
        if let Some(thread_id) = conversation.thread_id {
            params.insert(
                "threadId".into(),
                Value::String(stringify_thread_id(thread_id)),
            );
        }
        self.gateway.request("send", Value::Object(params)).await
    }

    /// Tracks one locally visible approval request.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when the approval identifier is empty or
    /// only whitespace, and [`McpError::Lifecycle`] when the approval lock was
    /// poisoned by an earlier panic while it was held.
    pub fn track_pending_approval(&self, approval: PendingApproval) -> Result<()> {
        self.approvals
            .lock()
            .map_err(|_| McpError::Lifecycle("pending approval lock poisoned".into()))?
            .track(approval)
    }

    /// Lists non-expired approvals in creation order.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Lifecycle`] when the approval lock was poisoned by an
    /// earlier panic while it was held.
    pub fn list_pending_approvals(&self, now_ms: i64) -> Result<Vec<PendingApproval>> {
        self.approvals
            .lock()
            .map_err(|_| McpError::Lifecycle("pending approval lock poisoned".into()))
            .map(|mut approvals| approvals.list_open(now_ms))
    }

    /// Resolves an approval through the matching Gateway method.
    ///
    /// The local entry is dropped only after the Gateway accepts the decision,
    /// so a failed resolution leaves the approval visible and retryable.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when the identifier is empty or only
    /// whitespace, the Gateway port's error when it rejects the resolution — an
    /// unknown or already-resolved approval — and [`McpError::Lifecycle`] when
    /// the approval lock was poisoned.
    pub async fn respond_to_approval(
        &self,
        kind: ApprovalKind,
        id: &str,
        decision: ApprovalDecision,
    ) -> Result<Value> {
        let id = id.trim();
        if id.is_empty() {
            return Err(McpError::Protocol(
                "approval identifier must not be empty".into(),
            ));
        }
        let method = match kind {
            ApprovalKind::Exec => "exec.approval.resolve",
            ApprovalKind::Plugin => "plugin.approval.resolve",
        };
        let result = self
            .gateway
            .request(method, json!({"id": id, "decision": decision}))
            .await?;
        self.approvals
            .lock()
            .map_err(|_| McpError::Lifecycle("pending approval lock poisoned".into()))?
            .remove(kind, id);
        Ok(result)
    }

    /// Adds one live event and wakes matching long-poll callers.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Lifecycle`] when the event lock was poisoned by an
    /// earlier panic while it was held. The queue itself never rejects an event:
    /// it retains the newest 1,000 and discards older ones.
    pub fn push_event(&self, event: ConversationEvent) -> Result<()> {
        self.events
            .lock()
            .map_err(|_| McpError::Lifecycle("conversation event lock poisoned".into()))?
            .push(event);
        self.event_notify.notify_waiters();
        Ok(())
    }

    /// Allocates the next monotonic event cursor.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Lifecycle`] when the event lock was poisoned by an
    /// earlier panic while it was held.
    pub fn next_event_cursor(&self) -> Result<u64> {
        self.events
            .lock()
            .map_err(|_| McpError::Lifecycle("conversation event lock poisoned".into()))
            .map(|mut events| events.next_cursor())
    }

    /// Polls queued events with the frozen cursor and session filtering rules.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Lifecycle`] when the event lock was poisoned by an
    /// earlier panic while it was held. A cursor past the end of the queue
    /// returns no events rather than an error.
    pub fn poll_events(
        &self,
        after_cursor: u64,
        session_key: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<ConversationEvent>, u64)> {
        self.events
            .lock()
            .map_err(|_| McpError::Lifecycle("conversation event lock poisoned".into()))
            .map(|events| events.poll(after_cursor, session_key, limit))
    }

    /// Waits for one matching event, returning `None` at the bounded deadline.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Lifecycle`] when the event lock was poisoned by an
    /// earlier panic while it was held. Reaching `timeout_duration` without a
    /// matching event is `Ok(None)`, not an error.
    pub async fn wait_for_event(
        &self,
        after_cursor: u64,
        session_key: Option<&str>,
        timeout_duration: Duration,
    ) -> Result<Option<ConversationEvent>> {
        let wait = async {
            loop {
                let notified = self.event_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let (events, _) = self.poll_events(after_cursor, session_key, 1)?;
                if let Some(event) = events.into_iter().next() {
                    return Ok(event);
                }
                notified.await;
            }
        };
        let Ok(result) = tokio::time::timeout(timeout_duration, wait).await else {
            return Ok(None);
        };
        result.map(Some)
    }
}

fn stringify_thread_id(thread_id: Value) -> String {
    match thread_id {
        Value::String(value) => value,
        other => other.to_string(),
    }
}

/// Approval family exposed by the conversation projection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalKind {
    /// Command execution approval.
    Exec,
    /// Plugin approval.
    Plugin,
}

/// Decision accepted by the Gateway approval resolver.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalDecision {
    /// Allow this request once.
    AllowOnce,
    /// Allow this request and future equivalent requests.
    AllowAlways,
    /// Deny this request.
    Deny,
}

/// Open approval projected to MCP clients.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingApproval {
    /// Approval family.
    pub kind: ApprovalKind,
    /// Stable approval identifier.
    pub id: String,
    /// Raw approval request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Map<String, Value>>,
    /// Creation time in Unix milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_ms: Option<i64>,
    /// Expiry time in Unix milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
}

/// Locally tracked approval requests awaiting an MCP decision.
#[derive(Debug, Default)]
pub struct PendingApprovalQueue {
    approvals: BTreeMap<(ApprovalKind, String), TrackedPendingApproval>,
}

#[derive(Debug)]
struct TrackedPendingApproval {
    approval: PendingApproval,
    tracked_at_ms: i64,
}

impl PendingApprovalQueue {
    /// Adds or replaces an approval after normalizing its identifier.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when the identifier is empty or only
    /// whitespace once trimmed, since such an approval could never be matched by
    /// a later resolve.
    pub fn track(&mut self, approval: PendingApproval) -> Result<()> {
        self.track_at(approval, unix_time_ms())
    }

    fn track_at(&mut self, mut approval: PendingApproval, tracked_at_ms: i64) -> Result<()> {
        trim_in_place(&mut approval.id);
        if approval.id.is_empty() {
            return Err(McpError::Protocol(
                "approval identifier must not be empty".into(),
            ));
        }
        self.approvals.insert(
            (approval.kind, approval.id.clone()),
            TrackedPendingApproval {
                approval,
                tracked_at_ms,
            },
        );
        Ok(())
    }

    /// Removes an approval after a successful Gateway resolution.
    pub fn remove(&mut self, kind: ApprovalKind, id: &str) -> Option<PendingApproval> {
        self.approvals
            .remove(&(kind, id.trim().to_owned()))
            .map(|tracked| tracked.approval)
    }

    /// Sweeps expired approvals and returns the rest in creation order.
    pub fn list_open(&mut self, now_ms: i64) -> Vec<PendingApproval> {
        self.approvals.retain(|_, tracked| {
            tracked.approval.expires_at_ms.unwrap_or_else(|| {
                tracked
                    .tracked_at_ms
                    .saturating_add(PENDING_APPROVAL_DEFAULT_TTL_MS)
            }) > now_ms
        });
        let mut approvals = self
            .approvals
            .values()
            .map(|tracked| tracked.approval.clone())
            .collect::<Vec<_>>();
        approvals.sort_by(|left, right| {
            left.created_at_ms
                .unwrap_or(0)
                .cmp(&right.created_at_ms.unwrap_or(0))
                .then_with(|| left.kind.cmp(&right.kind))
                .then_with(|| left.id.cmp(&right.id))
        });
        approvals
    }
}

fn trim_in_place(value: &mut String) {
    value.truncate(value.trim_end().len());
    value.drain(..value.len() - value.trim_start().len());
}

fn unix_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

/// Cursor-addressed live event projected to MCP.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConversationEvent {
    /// A live session message.
    Message {
        /// Monotonic event cursor.
        cursor: u64,
        /// Stable session key.
        #[serde(rename = "sessionKey")]
        session_key: String,
        /// Optional reply-capable conversation.
        #[serde(skip_serializing_if = "Option::is_none")]
        conversation: Option<Box<ConversationDescriptor>>,
        /// Optional message identifier.
        #[serde(rename = "messageId", skip_serializing_if = "Option::is_none")]
        message_id: Option<String>,
        /// Optional message sequence.
        #[serde(rename = "messageSeq", skip_serializing_if = "Option::is_none")]
        message_seq: Option<u64>,
        /// Optional role.
        #[serde(skip_serializing_if = "Option::is_none")]
        role: Option<String>,
        /// Optional first text block.
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        /// Raw Gateway payload.
        raw: Value,
    },
    /// A Claude channel permission request.
    ClaudePermissionRequest {
        /// Monotonic event cursor.
        cursor: u64,
        /// Request identifier.
        #[serde(rename = "requestId")]
        request_id: String,
        /// Tool name.
        #[serde(rename = "toolName")]
        tool_name: String,
        /// Human-readable description.
        description: String,
        /// Input preview.
        #[serde(rename = "inputPreview")]
        input_preview: String,
    },
    /// Raw execution approval event.
    ExecApprovalRequested {
        /// Monotonic event cursor.
        cursor: u64,
        /// Raw Gateway payload.
        raw: Map<String, Value>,
    },
    /// Raw execution approval resolution.
    ExecApprovalResolved {
        /// Monotonic event cursor.
        cursor: u64,
        /// Raw Gateway payload.
        raw: Map<String, Value>,
    },
    /// Raw plugin approval event.
    PluginApprovalRequested {
        /// Monotonic event cursor.
        cursor: u64,
        /// Raw Gateway payload.
        raw: Map<String, Value>,
    },
    /// Raw plugin approval resolution.
    PluginApprovalResolved {
        /// Monotonic event cursor.
        cursor: u64,
        /// Raw Gateway payload.
        raw: Map<String, Value>,
    },
}

impl ConversationEvent {
    const fn cursor(&self) -> u64 {
        match self {
            Self::Message { cursor, .. }
            | Self::ClaudePermissionRequest { cursor, .. }
            | Self::ExecApprovalRequested { cursor, .. }
            | Self::ExecApprovalResolved { cursor, .. }
            | Self::PluginApprovalRequested { cursor, .. }
            | Self::PluginApprovalResolved { cursor, .. } => *cursor,
        }
    }

    fn session_key(&self) -> Option<&str> {
        match self {
            Self::Message { session_key, .. } => Some(session_key),
            _ => None,
        }
    }
}

/// Bounded event queue with cursor and session filtering.
#[derive(Debug)]
pub struct ConversationEventQueue {
    next_cursor: u64,
    events: VecDeque<ConversationEvent>,
    /// Whether every buffered event is in non-decreasing cursor order.
    ///
    /// [`ConversationEventQueue::push`] accepts a caller-supplied cursor, so
    /// ordering is a property of the traffic rather than an invariant. It holds
    /// for cursors handed out by [`ConversationEventQueue::next_cursor`], which
    /// is what lets a poll skip straight to the first unseen event.
    ordered: bool,
}

impl Default for ConversationEventQueue {
    fn default() -> Self {
        Self {
            next_cursor: 0,
            events: VecDeque::new(),
            ordered: true,
        }
    }
}

impl ConversationEventQueue {
    /// Allocates the next monotonic cursor.
    pub const fn next_cursor(&mut self) -> u64 {
        self.next_cursor += 1;
        self.next_cursor
    }

    /// Adds an event while retaining at most 1,000 entries.
    pub fn push(&mut self, event: ConversationEvent) {
        match self.events.back() {
            None => self.ordered = true,
            Some(last) if last.cursor() > event.cursor() => self.ordered = false,
            Some(_) => {}
        }
        self.next_cursor = self.next_cursor.max(event.cursor());
        self.events.push_back(event);
        while self.events.len() > EVENT_QUEUE_LIMIT {
            self.events.pop_front();
        }
    }

    /// Returns events newer than a cursor, optionally restricted to one session.
    ///
    /// A long poll re-runs this on every wakeup with a cursor at the tail of a
    /// queue that holds up to 1,000 events, so an ordered queue is bisected
    /// rather than scanned from the front: 108.3 ns against 363.7 ns per poll
    /// (**3.4x**) for a tail cursor over a full queue. Polling from the middle
    /// for 20 events is 1926.1 ns against 2062.8 ns (**1.07x**), where cloning
    /// the matches dominates. Out-of-order cursors fall back to the scan, which
    /// `partition_point` cannot answer correctly.
    #[must_use]
    pub fn poll(
        &self,
        after_cursor: u64,
        session_key: Option<&str>,
        limit: usize,
    ) -> (Vec<ConversationEvent>, u64) {
        let limit = limit.clamp(1, 200);
        let start = if self.ordered {
            self.events
                .partition_point(|event| event.cursor() <= after_cursor)
        } else {
            0
        };
        let events: Vec<_> = self
            .events
            .range(start..)
            .filter(|event| event.cursor() > after_cursor)
            .filter(|event| session_key.is_none() || event.session_key() == session_key)
            .take(limit)
            .cloned()
            .collect();
        let next_cursor = events
            .last()
            .map_or(after_cursor, ConversationEvent::cursor);
        (events, next_cursor)
    }
}

/// MCP backend exposing the frozen `OpenClaw` conversation tool surface.
#[derive(Debug)]
pub struct ConversationMcpBackend {
    projection: Arc<ConversationProjection>,
}

impl ConversationMcpBackend {
    /// Creates an MCP conversation backend over a Gateway projection.
    #[must_use]
    pub const fn new(projection: Arc<ConversationProjection>) -> Self {
        Self { projection }
    }

    fn tools() -> Vec<Tool> {
        // The nine schemas are literals, so they are built once and handed out
        // as `Arc` clones: 84.8 ns against 4217.7 ns per `tools/list`
        // (**50x**), since `Tool` holds its schema behind an `Arc` and its name
        // and description as `Cow::Borrowed`.
        static TOOLS: OnceLock<Vec<Tool>> = OnceLock::new();
        TOOLS.get_or_init(Self::build_tools).clone()
    }

    fn build_tools() -> Vec<Tool> {
        vec![
            conversation_tool(
                "conversations_list",
                "List OpenClaw channel-backed conversations available through session routes.",
                json!({
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                        "search": {"type": "string"},
                        "channel": {"type": "string"},
                        "includeDerivedTitles": {"type": "boolean"},
                        "includeLastMessage": {"type": "boolean"}
                    }
                }),
            ),
            conversation_tool(
                "conversation_get",
                "Get one OpenClaw conversation by session key.",
                json!({
                    "type": "object",
                    "properties": {"session_key": {"type": "string", "minLength": 1}},
                    "required": ["session_key"]
                }),
            ),
            conversation_tool(
                "messages_read",
                "Read recent messages for one OpenClaw conversation.",
                json!({
                    "type": "object",
                    "properties": {
                        "session_key": {"type": "string", "minLength": 1},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200}
                    },
                    "required": ["session_key"]
                }),
            ),
            conversation_tool(
                "attachments_fetch",
                "List non-text attachments for a message in one OpenClaw conversation.",
                json!({
                    "type": "object",
                    "properties": {
                        "session_key": {"type": "string", "minLength": 1},
                        "message_id": {"type": "string", "minLength": 1},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200}
                    },
                    "required": ["session_key", "message_id"]
                }),
            ),
            conversation_tool(
                "events_poll",
                "Poll queued OpenClaw conversation events since a cursor.",
                json!({
                    "type": "object",
                    "properties": {
                        "after_cursor": {"type": "integer", "minimum": 0},
                        "session_key": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200}
                    }
                }),
            ),
            conversation_tool(
                "events_wait",
                "Wait for the next queued OpenClaw conversation event.",
                json!({
                    "type": "object",
                    "properties": {
                        "after_cursor": {"type": "integer", "minimum": 0},
                        "session_key": {"type": "string"},
                        "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 300_000}
                    }
                }),
            ),
            conversation_tool(
                "messages_send",
                "Send a message back through the same OpenClaw conversation route.",
                json!({
                    "type": "object",
                    "properties": {
                        "session_key": {"type": "string", "minLength": 1},
                        "text": {"type": "string", "minLength": 1}
                    },
                    "required": ["session_key", "text"]
                }),
            ),
            conversation_tool(
                "permissions_list_open",
                "List open OpenClaw exec or plugin approval requests visible through the Gateway.",
                json!({"type": "object", "properties": {}}),
            ),
            conversation_tool(
                "permissions_respond",
                "Allow or deny one pending OpenClaw exec or plugin approval request.",
                json!({
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": ["exec", "plugin"]},
                        "id": {"type": "string", "minLength": 1},
                        "decision": {
                            "type": "string",
                            "enum": ["allow-once", "allow-always", "deny"]
                        }
                    },
                    "required": ["kind", "id", "decision"]
                }),
            ),
        ]
    }

    async fn call(
        &self,
        request: CallToolRequestParams,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let name = request.name.as_ref();
        match name {
            "conversations_list" => {
                let arguments: ConversationsListArguments =
                    parse_tool_arguments(request.arguments)?;
                let limit = optional_bounded(arguments.limit, 500, "limit")?;
                let conversations = self
                    .projection
                    .list_conversations(ListConversationsOptions {
                        limit,
                        search: arguments.search,
                        channel: arguments.channel,
                        include_derived_titles: arguments.include_derived_titles,
                        include_last_message: arguments.include_last_message,
                    })
                    .await
                    .map_err(projection_error)?;
                structured_summary(
                    "conversations",
                    conversations.len(),
                    json!({"conversations": conversations}),
                )
            }
            "conversation_get" => {
                let arguments: SessionArguments = parse_tool_arguments(request.arguments)?;
                Ok(
                    match self
                        .projection
                        .get_conversation(&arguments.session_key)
                        .await
                        .map_err(projection_error)?
                    {
                        Some(conversation) => structured_result(
                            format!("conversation {}", conversation.session_key),
                            json!({"conversation": conversation}),
                        ),
                        None => error_result(format!(
                            "conversation not found: {}",
                            arguments.session_key
                        )),
                    },
                )
            }
            "messages_read" => {
                let arguments: ReadArguments = parse_tool_arguments(request.arguments)?;
                let limit = optional_bounded(arguments.limit, 200, "limit")?;
                let messages = self
                    .projection
                    .read_messages(&arguments.session_key, limit)
                    .await
                    .map_err(projection_error)?;
                structured_summary("messages", messages.len(), json!({"messages": messages}))
            }
            "attachments_fetch" => {
                let arguments: AttachmentArguments = parse_tool_arguments(request.arguments)?;
                let limit = optional_bounded(arguments.limit, 200, "limit")?.or(Some(100));
                let messages = self
                    .projection
                    .read_messages(&arguments.session_key, limit)
                    .await
                    .map_err(projection_error)?;
                Ok(
                    match messages.into_iter().find(|message| {
                        resolve_message_id(message) == Some(arguments.message_id.as_str())
                    }) {
                        Some(message) => {
                            let attachments = attachments(&message);
                            structured_result(
                                format!("attachments: {}", attachments.len()),
                                json!({"attachments": attachments, "message": message}),
                            )
                        }
                        None => {
                            error_result(format!("message not found: {}", arguments.message_id))
                        }
                    },
                )
            }
            "events_poll" => {
                let arguments: EventPollArguments = parse_tool_arguments(request.arguments)?;
                let limit = bounded_or_default(arguments.limit, 20, 200, "limit")?;
                let (events, next_cursor) = self
                    .projection
                    .poll_events(
                        arguments.after_cursor.unwrap_or(0),
                        arguments.session_key.as_deref(),
                        limit,
                    )
                    .map_err(projection_error)?;
                Ok(structured_result(
                    format!("events: {}", events.len()),
                    json!({"events": events, "next_cursor": next_cursor}),
                ))
            }
            "events_wait" => {
                let arguments: EventWaitArguments = parse_tool_arguments(request.arguments)?;
                let timeout_ms =
                    bounded_or_default(arguments.timeout_ms, 30_000, 300_000, "timeout_ms")?;
                let event = self
                    .projection
                    .wait_for_event(
                        arguments.after_cursor.unwrap_or(0),
                        arguments.session_key.as_deref(),
                        Duration::from_millis(timeout_ms as u64),
                    )
                    .await
                    .map_err(projection_error)?;
                let text = event.as_ref().map_or_else(
                    || "timeout".to_owned(),
                    |event| format!("event {}", event.cursor()),
                );
                Ok(structured_result(text, json!({"event": event})))
            }
            "messages_send" => {
                let arguments: SendArguments = parse_tool_arguments(request.arguments)?;
                let result = self
                    .projection
                    .send_message(&arguments.session_key, &arguments.text)
                    .await
                    .map_err(projection_error)?;
                Ok(structured_result("sent", json!({"result": result})))
            }
            "permissions_list_open" => {
                let _: EmptyArguments = parse_tool_arguments(request.arguments)?;
                let approvals = self
                    .projection
                    .list_pending_approvals(unix_time_ms())
                    .map_err(projection_error)?;
                Ok(structured_result(
                    format!("approvals: {}", approvals.len()),
                    json!({"approvals": approvals}),
                ))
            }
            "permissions_respond" => {
                let arguments: PermissionArguments = parse_tool_arguments(request.arguments)?;
                let result = self
                    .projection
                    .respond_to_approval(arguments.kind, &arguments.id, arguments.decision)
                    .await
                    .map_err(projection_error)?;
                Ok(structured_result(
                    "approval resolved",
                    json!({"result": result}),
                ))
            }
            _ => Err(ErrorData::method_not_found::<
                rmcp::model::CallToolRequestMethod,
            >()),
        }
    }
}

impl McpBackend for ConversationMcpBackend {
    fn server_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.server_info.name = "gta-claw-conversations".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: OperationContext,
    ) -> std::result::Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: Self::tools(),
            ..ListToolsResult::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: OperationContext,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.call(request).await
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConversationsListArguments {
    limit: Option<usize>,
    search: Option<String>,
    channel: Option<String>,
    include_derived_titles: Option<bool>,
    include_last_message: Option<bool>,
}

#[derive(Deserialize)]
struct SessionArguments {
    session_key: String,
}

#[derive(Deserialize)]
struct ReadArguments {
    session_key: String,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct AttachmentArguments {
    session_key: String,
    message_id: String,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct EventPollArguments {
    after_cursor: Option<u64>,
    session_key: Option<String>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct EventWaitArguments {
    after_cursor: Option<u64>,
    session_key: Option<String>,
    timeout_ms: Option<usize>,
}

#[derive(Deserialize)]
struct SendArguments {
    session_key: String,
    text: String,
}

#[derive(Deserialize)]
struct PermissionArguments {
    kind: ApprovalKind,
    id: String,
    decision: ApprovalDecision,
}

#[derive(Deserialize)]
struct EmptyArguments {}

fn conversation_tool(name: &'static str, description: &'static str, schema: Value) -> Tool {
    Tool::new(name, description, object_literal(schema))
}

fn object_literal(value: Value) -> JsonObject {
    match value {
        Value::Object(object) => object,
        _ => unreachable!("conversation tool schemas are object literals"),
    }
}

fn parse_tool_arguments<T: for<'de> Deserialize<'de>>(
    arguments: Option<JsonObject>,
) -> std::result::Result<T, ErrorData> {
    serde_json::from_value(Value::Object(arguments.unwrap_or_default()))
        .map_err(|error| ErrorData::invalid_params(error.to_string(), None))
}

fn optional_bounded(
    value: Option<usize>,
    maximum: usize,
    name: &str,
) -> std::result::Result<Option<usize>, ErrorData> {
    value
        .map(|value| {
            if (1..=maximum).contains(&value) {
                Ok(value)
            } else {
                Err(ErrorData::invalid_params(
                    format!("{name} must be between 1 and {maximum}"),
                    None,
                ))
            }
        })
        .transpose()
}

fn bounded_or_default(
    value: Option<usize>,
    default: usize,
    maximum: usize,
    name: &str,
) -> std::result::Result<usize, ErrorData> {
    Ok(optional_bounded(value, maximum, name)?.unwrap_or(default))
}

fn resolve_message_id(message: &ProjectedMessage) -> Option<&str> {
    message.id.as_deref().or_else(|| {
        message
            .extra
            .get("__openclaw")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("id"))
            .and_then(Value::as_str)
    })
}

/// Renders the frozen `text` summary and reuses the same tree as the
/// structured payload.
///
/// The tree is not a serialize-only intermediate: [`CallToolResult`] carries
/// `structured_content` as a [`Value`], so it has to exist. Pretty-printing a
/// borrowed `Serialize` view instead of the tree — the rewrite that pays off
/// when a `json!` tree exists only to be written out — measured 6767.6 ns
/// against 6855.2 ns for 50 conversations (**1.01x**), because the formatter,
/// not the tree walk, is the cost.
fn structured_summary(
    label: &str,
    count: usize,
    structured: Value,
) -> std::result::Result<CallToolResult, ErrorData> {
    let pretty = serde_json::to_string_pretty(&structured)
        .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
    Ok(structured_result(
        format!("{label}: {count}\n\n{pretty}"),
        structured,
    ))
}

fn structured_result(text: impl Into<String>, structured: Value) -> CallToolResult {
    let mut result = CallToolResult::success(vec![ContentBlock::text(text.into())]);
    result.structured_content = Some(structured);
    result.is_error = None;
    result
}

fn error_result(text: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text.into())])
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "used directly as the `map_err` conversion function, whose argument is by value; a reference signature would force a closure at every call site"
)]
fn projection_error(error: McpError) -> ErrorData {
    ErrorData::internal_error(error.to_string(), None)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[derive(Debug)]
    struct RecordingGateway {
        requests: Mutex<Vec<(&'static str, Value)>>,
        responses: Mutex<VecDeque<Value>>,
    }

    impl RecordingGateway {
        fn new(responses: Vec<Value>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
            }
        }
    }

    impl ConversationGatewayPort for RecordingGateway {
        fn request<'a>(&'a self, method: &'static str, params: Value) -> ConversationFuture<'a> {
            self.requests
                .lock()
                .expect("request lock")
                .push((method, params));
            let response = self
                .responses
                .lock()
                .expect("response lock")
                .pop_front()
                .ok_or_else(|| McpError::Protocol("fixture response queue exhausted".into()));
            Box::pin(async move { response })
        }
    }

    fn session_row() -> SessionRow {
        SessionRow {
            key: "agent:main:signal:42".into(),
            channel: Some("ignored".into()),
            last_channel: Some("Telegram".into()),
            last_to: Some(" chat-9 ".into()),
            last_account_id: Some("account-7".into()),
            last_thread_id: Some(json!(12)),
            delivery_context: None,
            origin: Some(OriginContext {
                provider: Some("signal".into()),
                account_id: Some("origin-account".into()),
                thread_id: Some(json!("origin-thread")),
            }),
            label: None,
            display_name: Some("Team chat".into()),
            derived_title: Some("Release".into()),
            last_message_preview: Some("Ship it".into()),
            updated_at: Some(1_721_000_000_000),
        }
    }

    #[test]
    fn conversation_shape_matches_frozen_channel_contract() {
        let projected = project_conversation(&session_row()).expect("reply-capable route");
        let actual = serde_json::to_value(projected).expect("serialize projection");

        assert_eq!(
            actual,
            json!({
                "sessionKey": "agent:main:signal:42",
                "channel": "telegram",
                "to": "chat-9",
                "accountId": "account-7",
                "threadId": 12,
                "displayName": "Team chat",
                "derivedTitle": "Release",
                "lastMessagePreview": "Ship it",
                "updatedAt": 1_721_000_000_000_i64
            })
        );
    }

    #[test]
    fn projection_fails_closed_without_a_reply_route() {
        let mut row = session_row();
        row.last_to = None;
        assert_eq!(project_conversation(&row), None);
    }

    #[test]
    fn attachments_preserve_non_text_blocks_exactly() {
        let message = ProjectedMessage {
            id: Some("m-1".into()),
            role: Some("user".into()),
            content: Some(json!([
                {"type": "text", "text": "hello"},
                {"type": "image", "data": "aGVsbG8=", "mimeType": "image/png"},
                {"type": "resource", "uri": "file:///tmp/report.pdf"},
                "not-an-attachment",
                42,
                null
            ])),
            extra: BTreeMap::new(),
        };

        assert_eq!(
            attachments(&message),
            vec![
                json!({"type": "image", "data": "aGVsbG8=", "mimeType": "image/png"}),
                json!({"type": "resource", "uri": "file:///tmp/report.pdf"})
            ]
        );
    }

    #[test]
    fn approvals_without_explicit_expiry_use_the_upstream_tracking_ttl() {
        let mut approvals = PendingApprovalQueue::default();
        approvals
            .track_at(
                PendingApproval {
                    kind: ApprovalKind::Exec,
                    id: "implicit-expiry".into(),
                    request: None,
                    created_at_ms: None,
                    expires_at_ms: None,
                },
                1_000,
            )
            .expect("approval tracked");

        assert_eq!(
            approvals.list_open(1_000 + PENDING_APPROVAL_DEFAULT_TTL_MS - 1),
            vec![PendingApproval {
                kind: ApprovalKind::Exec,
                id: "implicit-expiry".into(),
                request: None,
                created_at_ms: None,
                expires_at_ms: None,
            }]
        );
        assert_eq!(
            approvals.list_open(1_000 + PENDING_APPROVAL_DEFAULT_TTL_MS),
            Vec::<PendingApproval>::new()
        );
    }

    #[tokio::test]
    async fn gateway_operations_match_frozen_list_read_send_and_approval_shapes() {
        let row = serde_json::to_value(session_row()).expect("session row JSON");
        let gateway = Arc::new(RecordingGateway::new(vec![
            json!({
                "sessions": [
                    row.clone(),
                    {
                        "key": "not-routable",
                        "lastChannel": "telegram",
                        "updatedAt": null
                    }
                ]
            }),
            json!({"session": row.clone()}),
            json!({
                "messages": [{
                    "id": "message-1",
                    "role": "assistant",
                    "content": [{"type": "text", "text": "done"}],
                    "__openclaw": {"id": "metadata-message-1"}
                }]
            }),
            json!({"session": row}),
            json!({"messageId": "sent-1"}),
            json!({"resolved": true}),
        ]));
        let projection = ConversationProjection::new(gateway.clone());

        let conversations = projection
            .list_conversations(ListConversationsOptions {
                limit: Some(999),
                search: Some("release".into()),
                channel: Some(" TELEGRAM ".into()),
                include_derived_titles: None,
                include_last_message: Some(false),
            })
            .await
            .expect("conversation list");
        assert_eq!(conversations.len(), 1);
        assert_eq!(
            serde_json::to_value(&conversations[0]).expect("conversation JSON"),
            json!({
                "sessionKey": "agent:main:signal:42",
                "channel": "telegram",
                "to": "chat-9",
                "accountId": "account-7",
                "threadId": 12,
                "displayName": "Team chat",
                "derivedTitle": "Release",
                "lastMessagePreview": "Ship it",
                "updatedAt": 1_721_000_000_000_i64
            })
        );
        let conversation = projection
            .get_conversation(" agent:main:signal:42 ")
            .await
            .expect("conversation lookup")
            .expect("conversation exists");
        assert_eq!(conversation, conversations[0]);
        let messages = projection
            .read_messages("agent:main:signal:42", Some(0))
            .await
            .expect("message history");
        assert_eq!(
            serde_json::to_value(messages).expect("messages JSON"),
            json!([{
                "id": "message-1",
                "role": "assistant",
                "content": [{"type": "text", "text": "done"}],
                "__openclaw": {"id": "metadata-message-1"}
            }])
        );
        assert_eq!(
            projection
                .send_message("agent:main:signal:42", "reply")
                .await
                .expect("message send"),
            json!({"messageId": "sent-1"})
        );

        projection
            .track_pending_approval(PendingApproval {
                kind: ApprovalKind::Plugin,
                id: " plugin-2 ".into(),
                request: Some(Map::from_iter([("plugin".into(), json!("calendar"))])),
                created_at_ms: Some(20),
                expires_at_ms: Some(200),
            })
            .expect("plugin approval tracked");
        projection
            .track_pending_approval(PendingApproval {
                kind: ApprovalKind::Exec,
                id: "exec-1".into(),
                request: Some(Map::from_iter([("command".into(), json!("cargo test"))])),
                created_at_ms: Some(10),
                expires_at_ms: Some(200),
            })
            .expect("exec approval tracked");
        projection
            .track_pending_approval(PendingApproval {
                kind: ApprovalKind::Exec,
                id: "expired".into(),
                request: None,
                created_at_ms: Some(5),
                expires_at_ms: Some(50),
            })
            .expect("expired approval tracked");
        assert_eq!(
            serde_json::to_value(
                projection
                    .list_pending_approvals(100)
                    .expect("approval list")
            )
            .expect("approval JSON"),
            json!([
                {
                    "kind": "exec",
                    "id": "exec-1",
                    "request": {"command": "cargo test"},
                    "createdAtMs": 10,
                    "expiresAtMs": 200
                },
                {
                    "kind": "plugin",
                    "id": "plugin-2",
                    "request": {"plugin": "calendar"},
                    "createdAtMs": 20,
                    "expiresAtMs": 200
                }
            ])
        );
        assert_eq!(
            projection
                .respond_to_approval(
                    ApprovalKind::Plugin,
                    "plugin-2",
                    ApprovalDecision::AllowOnce,
                )
                .await
                .expect("approval response"),
            json!({"resolved": true})
        );
        assert_eq!(
            projection
                .list_pending_approvals(100)
                .expect("approval list after response")
                .len(),
            1
        );

        let requests = std::mem::take(&mut *gateway.requests.lock().expect("request lock"));
        assert_eq!(requests.len(), 6);
        assert_eq!(
            requests[0],
            (
                "sessions.list",
                json!({
                    "limit": 500,
                    "search": "release",
                    "includeDerivedTitles": true,
                    "includeLastMessage": false
                })
            )
        );
        assert_eq!(
            requests[1],
            (
                "sessions.describe",
                json!({
                    "key": "agent:main:signal:42",
                    "includeDerivedTitles": true,
                    "includeLastMessage": true
                })
            )
        );
        assert_eq!(
            requests[2],
            (
                "sessions.get",
                json!({"key": "agent:main:signal:42", "limit": 1})
            )
        );
        assert_eq!(
            requests[3],
            (
                "sessions.describe",
                json!({
                    "key": "agent:main:signal:42",
                    "includeDerivedTitles": true,
                    "includeLastMessage": true
                })
            )
        );
        let mut send_params = requests[4].1.clone();
        let idempotency_key = send_params
            .as_object_mut()
            .expect("send params object")
            .remove("idempotencyKey")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .expect("send idempotency key");
        let key = idempotency_key.as_bytes();
        assert_eq!(key.len(), 36);
        assert_eq!(
            (&key[8], &key[13], &key[18], &key[23]),
            (&b'-', &b'-', &b'-', &b'-')
        );
        assert_eq!(key[14], b'4');
        assert!(matches!(key[19], b'8' | b'9' | b'a' | b'b'));
        assert!(key.iter().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_hexdigit()
        }));
        assert_eq!(
            (&requests[4].0, send_params),
            (
                &"send",
                json!({
                    "to": "chat-9",
                    "channel": "telegram",
                    "accountId": "account-7",
                    "threadId": "12",
                    "message": "reply",
                    "sessionKey": "agent:main:signal:42"
                })
            )
        );
        assert_eq!(
            requests[5],
            (
                "plugin.approval.resolve",
                json!({"id": "plugin-2", "decision": "allow-once"})
            )
        );
    }

    #[test]
    fn event_polling_uses_cursor_session_and_limit() {
        let mut queue = ConversationEventQueue::default();
        queue.push(ConversationEvent::Message {
            cursor: 1,
            session_key: "s-1".into(),
            conversation: None,
            message_id: Some("m-1".into()),
            message_seq: Some(1),
            role: Some("user".into()),
            text: Some("one".into()),
            raw: json!({"sessionKey": "s-1"}),
        });
        queue.push(ConversationEvent::Message {
            cursor: 2,
            session_key: "s-2".into(),
            conversation: None,
            message_id: Some("m-2".into()),
            message_seq: Some(2),
            role: Some("assistant".into()),
            text: Some("two".into()),
            raw: json!({"sessionKey": "s-2"}),
        });

        let (events, cursor) = queue.poll(0, Some("s-2"), 20);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].cursor(), 2);
        assert_eq!(cursor, 2);
    }

    #[tokio::test]
    async fn event_wait_wakes_for_the_first_matching_session_event() {
        let projection = Arc::new(ConversationProjection::new(Arc::new(
            RecordingGateway::new(Vec::new()),
        )));
        let waiting = {
            let projection = Arc::clone(&projection);
            tokio::spawn(async move {
                projection
                    .wait_for_event(0, Some("target"), Duration::from_secs(1))
                    .await
            })
        };
        tokio::task::yield_now().await;
        projection
            .push_event(ConversationEvent::Message {
                cursor: 1,
                session_key: "other".into(),
                conversation: None,
                message_id: Some("ignored".into()),
                message_seq: None,
                role: Some("user".into()),
                text: Some("ignored".into()),
                raw: json!({"sessionKey": "other"}),
            })
            .expect("unmatched event queued");
        projection
            .push_event(ConversationEvent::Message {
                cursor: 2,
                session_key: "target".into(),
                conversation: None,
                message_id: Some("matched".into()),
                message_seq: Some(3),
                role: Some("assistant".into()),
                text: Some("ready".into()),
                raw: json!({"sessionKey": "target"}),
            })
            .expect("matching event queued");

        assert_eq!(
            waiting
                .await
                .expect("wait task joins")
                .expect("event wait succeeds"),
            Some(ConversationEvent::Message {
                cursor: 2,
                session_key: "target".into(),
                conversation: None,
                message_id: Some("matched".into()),
                message_seq: Some(3),
                role: Some("assistant".into()),
                text: Some("ready".into()),
                raw: json!({"sessionKey": "target"}),
            })
        );
    }

    #[tokio::test]
    async fn conversation_backend_registers_and_executes_the_frozen_tool_surface() {
        let projection = Arc::new(ConversationProjection::new(Arc::new(
            RecordingGateway::new(Vec::new()),
        )));
        projection
            .push_event(ConversationEvent::ExecApprovalResolved {
                cursor: 7,
                raw: Map::from_iter([("id".into(), json!("approval-1"))]),
            })
            .expect("event queued");
        let backend = ConversationMcpBackend::new(projection);

        assert_eq!(
            ConversationMcpBackend::tools()
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<Vec<_>>(),
            vec![
                "conversations_list",
                "conversation_get",
                "messages_read",
                "attachments_fetch",
                "events_poll",
                "events_wait",
                "messages_send",
                "permissions_list_open",
                "permissions_respond"
            ]
        );
        let result = backend
            .call(
                CallToolRequestParams::new("events_wait").with_arguments(Map::from_iter([
                    ("after_cursor".into(), json!(6)),
                    ("timeout_ms".into(), json!(100)),
                ])),
            )
            .await
            .expect("events_wait tool succeeds");

        assert_eq!(
            serde_json::to_value(result).expect("tool result JSON"),
            json!({
                "content": [{"type": "text", "text": "event 7"}],
                "structuredContent": {
                    "event": {
                        "type": "exec_approval_resolved",
                        "cursor": 7,
                        "raw": {"id": "approval-1"}
                    }
                }
            })
        );
    }
}

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use claw_gateway_client::{
    AuthorizationExpectation, ClientMetadata, ClientTimeouts, ConnectionEpoch, ConnectionState,
    GatewayClient, GatewayClientConfig, GatewayCredential, ReconnectPolicy,
};
use claw_observability::tracing;
use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, ClientId, ClientMode, Codec, GatewayMethodName, Name, RequestId,
    resolve_core_method,
};
use claw_security::authorization::{Role, Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;
use rand_core::{TryCryptoRng, TryRng};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use url::Url;

use crate::diagnostics::{bool_field, sanitize};
use crate::model::{Prompt, RunState, SessionSummary, ToolActivity, TranscriptEntry};

const MAX_SESSIONS: usize = 1_000;
const MAX_DIFF_LINES: usize = 10_000;
const MAX_ARTIFACTS: usize = 1_000;
const MAX_PREVIEW_LINES: usize = 2_000;
const MAX_EVENT_TEXT_BYTES: usize = 16 * 1024;
const MAX_LABEL_BYTES: usize = 1_024;
const WORKER_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// Scopes this client asks the Gateway to grant, in request order.
const REQUESTED_SCOPES: &str = "operator.read,operator.write,operator.approvals";

/// Runtime configuration for the Gateway worker.
#[derive(Clone)]
pub struct GatewayOptions {
    /// Gateway WebSocket endpoint.
    pub url: Url,
    /// Optional shared token.
    pub token: Option<String>,
    /// Explicit OS-protected device profile; absent means process-local identity.
    pub device_profile: Option<String>,
}

/// Formats without the token. A derived `Debug` would put the shared secret into
/// any log line, panic message, or bug report that formats these options.
impl fmt::Debug for GatewayOptions {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayOptions")
            .field("url", &endpoint_label(&self.url))
            .field(
                "token",
                &if self.token.is_some() {
                    "<redacted>"
                } else {
                    "<none>"
                },
            )
            .finish_non_exhaustive()
    }
}

/// Renders an endpoint for humans without its userinfo, query, or fragment,
/// any of which can carry a credential.
#[must_use]
pub fn endpoint_label(url: &Url) -> String {
    let origin = url.origin();
    if origin.is_tuple() {
        origin.ascii_serialization()
    } else {
        url.scheme().to_owned()
    }
}

/// Bounded structured notes operation, separate from ordinary model input.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryCommand {
    arguments: Value,
}

impl fmt::Debug for MemoryCommand {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryCommand")
            .field("action", &self.arguments["action"])
            .field("arguments", &"[REDACTED]")
            .finish()
    }
}

impl MemoryCommand {
    /// Keeps bounded structured memory data separate from ordinary chat input.
    ///
    /// # Errors
    /// Refuses unknown actions, non-object data and oversized encoded commands.
    /// The server still validates action fields, authority and notebook revisions.
    pub fn new(arguments: Value) -> Result<Self, &'static str> {
        if !valid_memory_arguments(&arguments) {
            return Err("Memory command action or parameters are invalid");
        }
        let command = Self { arguments };
        if command.message().len() > 16 * 1024 {
            return Err("Memory command exceeds the encoded 16 KiB input limit");
        }
        Ok(command)
    }

    pub(crate) fn action(&self) -> &str {
        self.arguments["action"].as_str().unwrap_or("unknown")
    }

    pub(crate) fn message(&self) -> String {
        format!(
            "!tool {}",
            json!({"name":"memory_notes","arguments":self.arguments})
        )
    }
}

/// Metadata-only draft for a memory action selected in the command palette.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryDraft {
    arguments: Value,
}

impl MemoryDraft {
    pub(crate) fn parse(palette: &str) -> Result<Self, &'static str> {
        let fields: Vec<_> = palette.split_whitespace().collect();
        let Some(action) = fields.get(1) else {
            return Err("A memory action is required");
        };
        let number = |value: &str| {
            value
                .parse::<u64>()
                .map_err(|_| "Memory revision, offset or limit must be an unsigned integer")
        };
        let arguments = match (action.to_ascii_lowercase().as_str(), &fields[2..]) {
            ("list", []) => json!({"action":"list"}),
            ("list", [limit]) => json!({"action":"list","limit":number(limit)?}),
            ("list", [limit, after, revision]) => {
                json!({"action":"list","limit":number(limit)?,"after":after,"revision":number(revision)?})
            }
            ("get", [id]) => json!({"action":"get","id":id}),
            ("get", [id, revision, offset]) => {
                json!({"action":"get","id":id,"revision":number(revision)?,"offset":number(offset)?})
            }
            ("search", []) => json!({"action":"search","limit":8}),
            ("search", [limit]) => json!({"action":"search","limit":number(limit)?}),
            ("save", [id, kind, revision]) => {
                json!({"action":"save","id":id,"kind":kind,"expectedRevision":number(revision)?})
            }
            ("delete", [id, revision]) => {
                json!({"action":"delete","id":id,"expectedRevision":number(revision)?})
            }
            ("export", [revision]) => json!({"action":"export","revision":number(revision)?}),
            ("export", [revision, offset]) => {
                json!({"action":"export","revision":number(revision)?,"offset":number(offset)?})
            }
            ("import", [revision]) => {
                json!({"action":"import","expectedRevision":number(revision)?,"overwrite":false})
            }
            ("import", [revision, "overwrite"]) => {
                json!({"action":"import","expectedRevision":number(revision)?,"overwrite":true})
            }
            _ => return Err("Memory action has missing, extra or unsupported parameters"),
        };
        let draft = Self { arguments };
        let probe = match draft.action() {
            "search" | "save" => "draft",
            "import" => r#"{"schemaVersion":1,"notebook":{"revision":0,"entries":[]}}"#,
            _ => "",
        };
        draft.finish(probe)?;
        Ok(draft)
    }

    pub(crate) fn action(&self) -> &str {
        self.arguments["action"].as_str().unwrap_or("unknown")
    }

    pub(crate) fn input_limit(&self) -> usize {
        match self.action() {
            "search" => 4_096,
            "save" => 8_192,
            "import" => 16 * 1024,
            _ => 0,
        }
    }

    pub(crate) fn finish(&self, input: &str) -> Result<MemoryCommand, &'static str> {
        if input.len() > self.input_limit() {
            return Err("Memory input exceeds its UTF-8 byte limit");
        }
        let mut arguments = self.arguments.clone();
        match self.action() {
            "save" => arguments["content"] = json!(input),
            "search" => arguments["query"] = json!(input),
            "import" => {
                let archive: MemoryArchiveInput = serde_json::from_str(input).map_err(
                    |_| "Memory archive must be closed, unambiguous schema-version-1 JSON",
                )?;
                arguments["archive"] = serde_json::to_value(archive)
                    .map_err(|_| "Memory archive cannot be encoded")?;
            }
            _ => {}
        }
        MemoryCommand::new(arguments)
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MemoryArchiveInput {
    schema_version: u64,
    notebook: MemoryNotebookInput,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct MemoryNotebookInput {
    revision: u64,
    entries: Vec<MemoryEntryInput>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MemoryEntryInput {
    id: String,
    kind: String,
    content: String,
    source_session: String,
    revision: u64,
}

fn valid_memory_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || index > 0 && matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_memory_text(text: &str, limit: usize) -> bool {
    !text.trim().is_empty()
        && text.len() <= limit
        && !text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn valid_memory_kind(kind: &str) -> bool {
    matches!(kind, "fact" | "preference" | "procedure")
}

fn valid_memory_arguments(arguments: &Value) -> bool {
    let Some(object) = arguments.as_object() else {
        return false;
    };
    let optional_number = |field: &str, default: u64, maximum: u64| {
        arguments
            .get(field)
            .map_or(Some(default), Value::as_u64)
            .is_some_and(|number| number <= maximum)
    };
    let revision = arguments["revision"].as_u64().is_some();
    let valid_id = arguments["id"].as_str().is_some_and(valid_memory_id);
    let expected = arguments["expectedRevision"].as_u64().is_some();
    let (fields, valid): (&[&str], bool) = match arguments["action"].as_str() {
        Some("list") => (
            &["action", "after", "revision", "limit"],
            optional_number("limit", 16, 32)
                && arguments["limit"] != 0
                && arguments
                    .get("revision")
                    .is_none_or(|value| value.as_u64().is_some())
                && arguments
                    .get("after")
                    .is_none_or(|value| value.as_str().is_some_and(valid_memory_id) && revision),
        ),
        Some("get") => (
            &["action", "id", "offset", "revision"],
            valid_id
                && optional_number("offset", 0, 8_192)
                && arguments
                    .get("revision")
                    .is_none_or(|value| value.as_u64().is_some())
                && (arguments["offset"].as_u64().unwrap_or(0) == 0 || revision),
        ),
        Some("search") => (
            &["action", "query", "limit"],
            optional_number("limit", 8, 8)
                && arguments["limit"] != 0
                && arguments["query"]
                    .as_str()
                    .is_some_and(|query| valid_memory_text(query, 4_096)),
        ),
        Some("save") => (
            &["action", "id", "kind", "content", "expectedRevision"],
            valid_id
                && expected
                && arguments["kind"].as_str().is_some_and(valid_memory_kind)
                && arguments["content"]
                    .as_str()
                    .is_some_and(|content| valid_memory_text(content, 8_192)),
        ),
        Some("delete") => (&["action", "id", "expectedRevision"], valid_id && expected),
        Some("export") => (
            &["action", "revision", "offset"],
            revision && optional_number("offset", 0, 4 * 1024 * 1024),
        ),
        Some("import") => (
            &["action", "archive", "expectedRevision", "overwrite"],
            expected
                && arguments.get("overwrite").is_none_or(Value::is_boolean)
                && serde_json::from_value::<MemoryArchiveInput>(arguments["archive"].clone())
                    .is_ok_and(|archive| {
                        archive.schema_version == 1
                            && archive.notebook.entries.len() <= 256
                            && archive
                                .notebook
                                .entries
                                .windows(2)
                                .all(|pair| pair[0].id < pair[1].id)
                            && archive.notebook.entries.iter().all(|entry| {
                                valid_memory_id(&entry.id)
                                    && valid_memory_kind(&entry.kind)
                                    && valid_memory_text(&entry.content, 8_192)
                                    && !entry.source_session.trim().is_empty()
                                    && entry.source_session.len() <= 256
                                    && !entry.source_session.chars().any(char::is_control)
                                    && entry.revision > 0
                                    && entry.revision <= archive.notebook.revision
                            })
                    }),
        ),
        _ => return false,
    };
    valid && object.keys().all(|field| fields.contains(&field.as_str()))
}

/// A retained-text cursor bound to the terminal run observed by the UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialPageRequest {
    /// Session whose run the user has already observed.
    pub session_id: String,
    /// Exact durable run identity.
    pub run_id: String,
    /// Exact terminal revision previously observed.
    pub revision: u64,
    /// Bound turn ordinal.
    pub turn: u64,
    /// Observed terminal state; a page must not change it.
    pub state: RunState,
    /// UTF-8 byte offset requested.
    pub offset: usize,
    /// Original total length required for a continuation.
    pub total_bytes: Option<usize>,
    /// Whole-content digest required after the first page.
    pub sha256: Option<String>,
}

impl PartialPageRequest {
    fn parameters(&self) -> Result<Value, WorkerError> {
        if !valid_run_id(&self.run_id)
            || self.session_id.is_empty()
            || self.session_id.len() > 128
            || self.session_id.chars().any(char::is_control)
            || self.revision == 0
            || self.offset > 4 * 1024 * 1024
            || !matches!(
                self.state,
                RunState::Completed
                    | RunState::CompletedWithChanges
                    | RunState::Cancelled
                    | RunState::Failed
                    | RunState::OutcomeUnknown
            )
            || (self.offset > 0 && (self.sha256.is_none() || self.total_bytes.is_none()))
            || self
                .total_bytes
                .is_some_and(|total| total > 4 * 1024 * 1024 || self.offset > total)
            || self
                .sha256
                .as_ref()
                .is_some_and(|digest| !valid_run_id(digest))
        {
            return Err(WorkerError("Invalid partial-text page request".to_owned()));
        }
        let mut parameters = json!({"runId":self.run_id,"partialPage":{"revision":self.revision,"offset":self.offset}});
        if let Some(digest) = &self.sha256 {
            parameters["partialPage"]["sha256"] = json!(digest);
        }
        Ok(parameters)
    }
}

/// One validated page of retained, unconfirmed visible text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialPage {
    /// Original validated request, including its session/run/revision binding.
    pub request: PartialPageRequest,
    /// Untrusted visible text; never a completed assistant message.
    pub text: String,
    /// Exclusive byte end before display sanitization.
    pub end_offset: usize,
    /// Next byte offset, absent at the end of the retained text.
    pub next_offset: Option<usize>,
    /// Total retained byte length.
    pub total_bytes: usize,
    /// Pinned whole-content digest, not independent verification of a later page.
    pub sha256: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PartialRunWire {
    run_id: String,
    session_id: String,
    revision: u64,
    turn: Option<u64>,
    status: String,
    durable: bool,
    acknowledged: bool,
    automatic_replay: bool,
    partial: PartialTextWire,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PartialTextWire {
    available: bool,
    text: Option<String>,
    offset: Option<usize>,
    next_offset: Option<usize>,
    total_bytes: Option<usize>,
    sha256: Option<String>,
    message_complete: Option<bool>,
    untrusted: Option<bool>,
    reasoning_included: Option<bool>,
    tool_arguments_included: Option<bool>,
}

fn partial_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(64);
    for byte in ring::digest::digest(&ring::digest::SHA256, bytes).as_ref() {
        write!(encoded, "{byte:02x}").expect("string digest");
    }
    encoded
}

fn parse_partial_page(
    value: Value,
    request: PartialPageRequest,
) -> Result<PartialPage, WorkerError> {
    let invalid =
        || WorkerError("Partial page changed identity, bounds, safety flags or digest".to_owned());
    request.parameters()?;
    if value.to_string().len() > MAX_EVENT_TEXT_BYTES {
        return Err(invalid());
    }
    let reply: PartialRunWire = serde_json::from_value(value).map_err(|_| invalid())?;
    if reply.run_id != request.run_id
        || reply.session_id != request.session_id
        || reply.revision != request.revision
        || reply.turn != Some(request.turn)
        || !reply.durable
        || reply.acknowledged
        || reply.automatic_replay
        || !matches!(
            reply.status.as_str(),
            "completed" | "completed_with_changes" | "cancelled" | "failed" | "outcome_unknown"
        )
        || RunState::parse(&reply.status) != request.state
    {
        return Err(invalid());
    }
    let page = reply.partial;
    if !page.available {
        return Err(WorkerError(
            "No retained partial text is available for this run".to_owned(),
        ));
    }
    let text = page.text.ok_or_else(invalid)?;
    let total_bytes = page.total_bytes.ok_or_else(invalid)?;
    let sha256 = page.sha256.ok_or_else(invalid)?;
    let end_offset = request.offset.checked_add(text.len()).ok_or_else(invalid)?;
    if page.offset != Some(request.offset)
        || text.len() > 2048
        || total_bytes > 4 * 1024 * 1024
        || request
            .total_bytes
            .is_some_and(|expected| expected != total_bytes)
        || end_offset > total_bytes
        || !valid_run_id(&sha256)
        || request
            .sha256
            .as_ref()
            .is_some_and(|digest| *digest != sha256)
        || page.message_complete != Some(false)
        || page.untrusted != Some(true)
        || page.reasoning_included != Some(false)
        || page.tool_arguments_included != Some(false)
        || page.next_offset.map_or(end_offset != total_bytes, |next| {
            text.is_empty() || next != end_offset || next >= total_bytes
        })
        || (request.offset == 0
            && end_offset == total_bytes
            && partial_sha256(text.as_bytes()) != sha256)
    {
        return Err(invalid());
    }
    Ok(PartialPage {
        request,
        text,
        end_offset,
        next_offset: page.next_offset,
        total_bytes,
        sha256,
    })
}

/// Commands sent from the render loop to background Gateway work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UiCommand {
    /// An effectful command bound to the connection actually observed by its caller.
    ForConnection {
        /// Monotonic worker connection identity, not a reusable peer request ID.
        connection_id: u64,
        /// Original command; nested envelopes are refused.
        command: Box<Self>,
    },
    /// Sends one native message with a retained idempotency identity.
    SendMessage {
        /// Session selected by the user.
        session_id: String,
        /// Complete user input.
        text: String,
        /// Unique key retained when delivery is uncertain.
        idempotency_key: String,
    },
    /// Submits an explicitly selected memory operation after capability discovery.
    InvokeMemory {
        /// Current session that receives the durable command result.
        session_id: String,
        /// Structured operation, never passed to a model as ordinary prose.
        command: MemoryCommand,
        /// Original key retained for explicit reconciliation after disconnect.
        idempotency_key: String,
    },
    /// Reads one durable run without re-executing it.
    QueryRun {
        /// Session expected to own the result.
        session_id: String,
        /// Exact durable run identity.
        run_id: String,
    },
    /// Reads one explicitly requested page without acknowledging or replaying the run.
    ReadPartial(PartialPageRequest),
    /// Cancels only the observed run.
    AbortRun {
        /// Session expected to own the running turn.
        session_id: String,
        /// Exact run that may be cancelled.
        run_id: String,
    },
    /// Acknowledges a complete result already delivered to the UI.
    AcknowledgeRun {
        /// Run whose complete result reached the UI.
        run_id: String,
        /// Exact terminal revision received.
        revision: u64,
    },
    /// Reads the next bounded run-recovery page for the current selection.
    RecoverRuns(String),
    /// Reload session summaries.
    Refresh,
    /// Subscribe to and load one session.
    SelectSession(String),
    /// Load a session diff.
    LoadDiff(String),
    /// Load session artifacts.
    LoadArtifacts(String),
    /// Resolve an approval request.
    ResolveApproval {
        /// Approval identifier.
        id: String,
        /// Whether the request is approved.
        approved: bool,
        /// Public fingerprint of the preview the operator actually reviewed.
        preview_fingerprint: String,
    },
    /// Submit an answer to an agent question.
    Answer {
        /// Session identifier.
        session_id: String,
        /// Question identifier.
        question_id: String,
        /// User response.
        text: String,
    },
    /// Stop all Gateway work.
    Shutdown,
}

impl UiCommand {
    /// Binds a command to a previously observed ready connection.
    #[must_use]
    pub fn for_connection(self, connection_id: u64) -> Self {
        Self::ForConnection {
            connection_id,
            command: Box::new(self),
        }
    }

    pub(crate) const fn requires_connection(&self) -> bool {
        matches!(
            self,
            Self::SendMessage { .. }
                | Self::InvokeMemory { .. }
                | Self::ReadPartial(_)
                | Self::AbortRun { .. }
                | Self::AcknowledgeRun { .. }
                | Self::ResolveApproval { .. }
                | Self::Answer { .. }
                | Self::ForConnection { .. }
        )
    }
}

/// Data emitted by the background worker for synchronous model updates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerEvent {
    /// One verified page, separate from complete run results and their ACK eligibility.
    PartialPage(PartialPage),
    /// Durable receipt for an explicitly keyed user message.
    Accepted {
        /// Session echoed by the durable receipt.
        session_id: String,
        /// Server's durable run identity.
        run_id: String,
        /// Original client submission key.
        idempotency_key: String,
    },
    /// The command has no definitive receipt and must retain its original key.
    SendUnconfirmed {
        /// Original key that must be retained for reconciliation.
        idempotency_key: String,
    },
    /// This attempt was refused before submission, without resolving earlier attempts.
    SendNotSent {
        /// Key of the retained input.
        idempotency_key: String,
        /// Content-free reason for refusing this attempt.
        reason: String,
    },
    /// A complete durable run snapshot, scoped to its session.
    NativeRun {
        /// Verified session of this result.
        session_id: String,
        /// Verified durable run identity.
        run_id: String,
        /// Conservative display classification.
        state: RunState,
        /// Server turn ordinal, absent before the run is bound to a turn.
        turn: Option<u64>,
        /// Complete terminal text, absent while still active.
        text: Option<String>,
        /// Exact durable record revision.
        revision: u64,
    },
    /// Another recovery page is ready after the current page has been rendered.
    RecoveryAvailable(String),
    /// The server confirmed an exact result ACK; also releases UI command backpressure.
    ResultAcknowledged {
        /// Verified durable run identity.
        run_id: String,
        /// Verified terminal revision.
        revision: u64,
    },
    /// Redaction-safe connection state.
    Connection(String),
    /// A ready connection identity that must accompany every effectful command.
    Ready {
        /// Monotonic worker-owned identity.
        connection_id: u64,
        /// Safe connection summary.
        description: String,
    },
    /// Complete session snapshot.
    Sessions(Vec<SessionSummary>),
    /// Complete retained history for one explicitly selected native session.
    History {
        /// Session whose checkpoint was read.
        session_id: String,
        /// Bounded complete messages, never silently truncated.
        messages: Vec<TranscriptEntry>,
    },
    /// One streaming transcript item.
    Message {
        /// Exact session declared by the event.
        session_id: String,
        /// Complete bounded transcript item.
        message: TranscriptEntry,
    },
    /// One tool timeline item.
    Tool {
        /// Exact session declared by the event.
        session_id: String,
        /// Bounded tool activity.
        tool: ToolActivity,
    },
    /// A question or legacy prompt bound to one selected session.
    SessionPrompt {
        /// Exact session declared by the event.
        session_id: String,
        /// Bounded interactive request.
        prompt: Prompt,
    },
    /// An approval or question.
    Prompt(Prompt),
    /// Withdraw one pending approval, without clearing an unrelated prompt.
    PromptDismissed(String),
    /// Unified diff lines.
    Diff {
        /// Session selected by the original request.
        session_id: String,
        /// Bounded unified diff lines.
        lines: Vec<String>,
    },
    /// Artifact labels.
    Artifacts {
        /// Session selected by the original request.
        session_id: String,
        /// Bounded artifact labels.
        artifacts: Vec<String>,
    },
    /// Textual preview of the first artifact.
    ArtifactContent {
        /// Session selected by the original request.
        session_id: String,
        /// Bounded preview lines.
        lines: Vec<String>,
    },
    /// Non-fatal status or error text.
    Notice(String),
}

/// Starts Gateway work on the active Tokio runtime over bounded channels.
///
/// Whether the connection path is reported is decided by the process-wide
/// subscriber [`crate::diagnostics::install`] sets up, so this signature stays
/// free of a diagnostic channel and callers cannot route records anywhere else.
#[must_use]
pub fn spawn_gateway_worker(options: GatewayOptions) -> GatewayWorker {
    let (command_sender, command_receiver) = mpsc::channel(32);
    let (event_sender, event_receiver) = mpsc::channel(256);
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let endpoint = endpoint_label(&options.url);
    let task = tokio::spawn(async move {
        run_worker(
            options,
            command_receiver,
            event_sender,
            shutdown_receiver,
            endpoint,
        )
        .await;
    });
    GatewayWorker {
        commands: command_sender,
        events: event_receiver,
        shutdown: Some(shutdown_sender),
        task,
    }
}

/// Owned Gateway worker resources.
///
/// Keeping the task handle makes shutdown observable and prevents a failed
/// connection attempt from surviving after the terminal UI has exited.
pub struct GatewayWorker {
    /// Bounded command input.
    pub commands: mpsc::Sender<UiCommand>,
    /// Bounded event output.
    pub events: mpsc::Receiver<WorkerEvent>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl GatewayWorker {
    /// Cancels Gateway work and waits for a bounded graceful shutdown.
    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        drop(self.commands);
        if tokio::time::timeout(WORKER_SHUTDOWN_GRACE, &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
            let _ = self.task.await;
        }
    }
}

async fn run_worker(
    options: GatewayOptions,
    mut commands: mpsc::Receiver<UiCommand>,
    sender: mpsc::Sender<WorkerEvent>,
    mut shutdown: oneshot::Receiver<()>,
    endpoint: String,
) {
    tracing::debug!(
        action = "endpoint.resolve",
        outcome = "success",
        endpoint = sanitize(&endpoint),
        endpoint.scheme = options.url.scheme(),
        transport.tls = bool_field(options.url.scheme() == "wss"),
        // Only where the token came from is reportable; the token itself never
        // leaves `GatewayOptions`.
        auth.source = if options.token.is_some() {
            "environment"
        } else {
            "none"
        },
    );
    let mut connection_id = 0_u64;
    loop {
        let Some(next) = connection_id.checked_add(1) else {
            return;
        };
        connection_id = next;
        if sender
            .send(WorkerEvent::Connection(
                "Gateway: connecting (bounded retries)".to_owned(),
            ))
            .await
            .is_err()
        {
            return;
        }
        match run_connection(
            options.clone(),
            &mut commands,
            &sender,
            &mut shutdown,
            &endpoint,
            connection_id,
        )
        .await
        {
            Ok(ConnectionExit::Shutdown) => return,
            Ok(ConnectionExit::Disconnected) => {
                if !report_unavailable(&sender, &endpoint, "connection closed by the Gateway").await
                {
                    return;
                }
            }
            Err(error) => {
                if !report_unavailable(&sender, &endpoint, &error.to_string()).await {
                    return;
                }
            }
        }

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => return,
                command = commands.recv() => {
                    match command {
                        Some(UiCommand::Refresh) => break,
                        Some(UiCommand::Shutdown) | None => return,
                        Some(_) => {
                            if sender.send(WorkerEvent::Notice(
                                "Gateway unavailable; press r to retry".to_owned()
                            )).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn report_unavailable(
    sender: &mpsc::Sender<WorkerEvent>,
    endpoint: &str,
    error: &str,
) -> bool {
    if sender
        .send(WorkerEvent::Connection(
            "Gateway: unavailable (press r to retry)".to_owned(),
        ))
        .await
        .is_err()
    {
        return false;
    }
    sender
        .send(WorkerEvent::Notice(format!(
            "Gateway: {} (tried {endpoint}; start the gateway or check --gateway, then press r)",
            bounded_text(error, MAX_LABEL_BYTES)
        )))
        .await
        .is_ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionExit {
    Shutdown,
    Disconnected,
}

struct GatewaySession<'a> {
    client: &'a GatewayClient,
    connection_id: u64,
    epoch: ConnectionEpoch,
    persistent_identity: bool,
    previews: Mutex<BTreeMap<String, String>>,
    selected: Mutex<Option<String>>,
    complete_results: Mutex<BTreeMap<String, u64>>,
    recovery: Mutex<Option<RunRecovery>>,
}

async fn run_connection(
    options: GatewayOptions,
    commands: &mut mpsc::Receiver<UiCommand>,
    sender: &mpsc::Sender<WorkerEvent>,
    shutdown: &mut oneshot::Receiver<()>,
    endpoint: &str,
    connection_id: u64,
) -> Result<ConnectionExit, WorkerError> {
    let identity_result = if let Some(profile) = options.device_profile.clone() {
        if !options.url.username().is_empty()
            || options.url.password().is_some()
            || options.url.query().is_some()
            || options.url.fragment().is_some()
        {
            return Err(WorkerError(
                "Persistent identity requires a credential-free canonical Gateway endpoint"
                    .to_owned(),
            ));
        }
        let endpoint = options.url.as_str().to_owned();
        let task = tokio::task::spawn_blocking(move || {
            let store = claw_platform::identity::native_store()?;
            let root = claw_platform::identity::native_lock_directory()?;
            claw_platform::identity::DeviceProfile::new(&endpoint, &profile, root)?
                .load_or_create(store.as_ref())
        });
        tokio::select! {
            biased;
            _ = &mut *shutdown => return Ok(ConnectionExit::Shutdown),
            result = tokio::time::timeout(Duration::from_secs(10), task) => {
                result.map_err(|_| WorkerError("Device profile lookup timed out; retry the same profile".to_owned()))?
                    .map_err(|_| WorkerError("Device profile task failed; no ephemeral fallback is permitted".to_owned()))?
                    .map_err(|_| WorkerError("Device profile could not be loaded safely; no ephemeral fallback is permitted".to_owned()))
            }
        }
    } else {
        generate_identity()
    };
    let identity = match identity_result {
        Ok(identity) => {
            // No part of the generated key material is reportable, so only the
            // mode is recorded.
            tracing::debug!(
                action = "identity.generate",
                outcome = "success",
                endpoint = sanitize(endpoint),
                identity.mode = if options.device_profile.is_some() {
                    "native-profile"
                } else {
                    "ephemeral"
                },
            );
            Arc::new(identity)
        }
        Err(error) => {
            tracing::debug!(
                action = "identity.generate",
                outcome = "failure",
                endpoint = sanitize(endpoint),
                failure.reason = sanitize(&error.to_string()),
            );
            return Err(error);
        }
    };
    let mut config = GatewayClientConfig::new(options.url, identity);
    config.credential = options.token.map_or(GatewayCredential::None, |token| {
        GatewayCredential::Token(SecretString::from(token))
    });
    config.role = Role::Operator;
    config.scopes = ScopeSet::from_scopes([
        Scope::OperatorRead,
        Scope::OperatorWrite,
        Scope::OperatorApprovals,
    ]);
    config.authorization_expectation = AuthorizationExpectation::ExactRequested;
    config.client = ClientMetadata {
        id: ClientId::Tui,
        display_name: Some(Name::new("GTA Claw terminal", 64).expect("static client name")),
        version: Name::new(env!("CARGO_PKG_VERSION"), 64).expect("package version"),
        platform: Name::new(std::env::consts::OS, 64).expect("target OS"),
        device_family: None,
        model_identifier: None,
        mode: ClientMode::Ui,
        instance_id: None,
    };
    config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 2,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_millis(500),
        max_jitter: Duration::from_millis(50),
    };
    config.timeouts = ClientTimeouts {
        connect: Duration::from_secs(10),
        authentication: Duration::from_secs(10),
        request: Duration::from_secs(20),
        shutdown: Duration::from_secs(3),
    };

    let (client, mut gateway_events) = match GatewayClient::start(config) {
        Ok(started) => {
            tracing::debug!(
                action = "client.start",
                outcome = "success",
                endpoint = sanitize(endpoint),
                client.mode = "ui",
                scopes.requested = REQUESTED_SCOPES,
                expectation.mode = "exact_requested",
            );
            started
        }
        Err(error) => {
            let error = WorkerError(error.to_string());
            tracing::debug!(
                action = "client.start",
                outcome = "failure",
                endpoint = sanitize(endpoint),
                failure.reason = sanitize(&error.to_string()),
            );
            return Err(error);
        }
    };
    let ready_result = tokio::select! {
        biased;
        _ = &mut *shutdown => {
            let teardown = client
                .shutdown()
                .await
                .map_err(|error| WorkerError(error.to_string()));
            record_client_shutdown(endpoint, &teardown);
            return connection_exit_after_teardown(ConnectionExit::Shutdown, teardown);
        }
        ready = client.wait_ready() => ready,
    };
    let ready = match ready_result {
        Ok(ready) => ready,
        Err(error) => {
            let state = connection_label(&client.state());
            tracing::debug!(
                action = "connection.ready",
                outcome = "failure",
                endpoint = sanitize(endpoint),
                connection.state = state,
                failure.reason = sanitize(&error.to_string()),
            );
            let _ = client.shutdown().await;
            return Err(WorkerError(format!("{error} while {state}")));
        }
    };
    tracing::debug!(
        action = "connection.ready",
        outcome = "success",
        endpoint = sanitize(endpoint),
        protocol.negotiated = ready.info.protocol.get(),
    );
    tracing::debug!(
        action = "authorization.grant",
        outcome = "success",
        endpoint = sanitize(endpoint),
        role.granted = sanitize(&ready.info.role),
        scopes.granted = sanitize(&ready.info.scopes.join(",")),
        scopes.requested = REQUESTED_SCOPES,
        expectation.mode = "exact_requested",
    );
    tracing::trace!(
        action = "connection.epoch",
        outcome = "success",
        endpoint = sanitize(endpoint),
        connection.epoch = ready.epoch.get(),
        connection.max_payload_bytes = ready.info.max_payload_bytes,
    );
    if sender
        .send(WorkerEvent::Ready {
            connection_id,
            description: format!(
                "Gateway: ready (protocol {}, epoch {})",
                ready.info.protocol.get(),
                ready.epoch.get()
            ),
        })
        .await
        .is_err()
    {
        let _ = client.shutdown().await;
        return Err(WorkerError("render loop stopped".to_owned()));
    }

    let mut request_sequence = 1_u64;
    let session = GatewaySession {
        client: &client,
        connection_id,
        epoch: ready.epoch,
        persistent_identity: options.device_profile.is_some(),
        previews: Mutex::new(BTreeMap::new()),
        selected: Mutex::new(None),
        complete_results: Mutex::new(BTreeMap::new()),
        recovery: Mutex::new(None),
    };
    let mut connection_state = client.subscribe_state();
    if let Err(error) = send_sessions(&session, sender, &mut request_sequence, endpoint).await {
        let _ = client.shutdown().await;
        return Err(error);
    }
    let outcome = loop {
        tokio::select! {
            biased;
            _ = &mut *shutdown => break ConnectionExit::Shutdown,
            changed = connection_state.changed() => {
                if changed.is_err() || !matches!(&*connection_state.borrow(), ConnectionState::Ready(current) if current.epoch == session.epoch) {
                    break ConnectionExit::Disconnected;
                }
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    break ConnectionExit::Shutdown;
                };
                if matches!(command, UiCommand::Shutdown) {
                    break ConnectionExit::Shutdown;
                }
                if let Err(error) = handle_command(
                    &session,
                    sender,
                    &mut request_sequence,
                    command,
                    endpoint,
                ).await {
                    let _ = sender.send(WorkerEvent::Notice(error.to_string())).await;
                }
            }
            event = gateway_events.recv() => {
                let Some(event) = event else {
                    break ConnectionExit::Disconnected;
                };
                if event.epoch() != session.epoch { break ConnectionExit::Disconnected; }
                let frame = event.into_frame();
                if frame.event().as_str() == "chat"
                    && let Some(payload) = frame.payload().value().and_then(|payload| Codec::authenticated().decode_opaque::<Value>(payload).ok())
                    && payload["resultAvailable"] == true
                {
                    let selected = session.selected.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
                    if let Some(selected) = selected && payload["sessionId"].as_str() == Some(selected.as_str())
                        && let Some(run_id) = payload["runId"].as_str()
                        && let Err(error) = send_native_run(&session, sender, &mut request_sequence, &selected, run_id, endpoint).await
                    { let _ = sender.send(WorkerEvent::Notice(error.to_string())).await; }
                    continue;
                }
                if frame.event().as_str() == "exec.approval.requested" {
                    if let Some(payload) = frame.payload().value().and_then(|payload| Codec::authenticated().decode_opaque::<Value>(payload).ok())
                        && let Some(id) = payload["id"].as_str().filter(|id| !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control))
                        && let Err(error) = send_approval_preview(&session, sender, &mut request_sequence, id, endpoint).await
                    { let _ = sender.send(WorkerEvent::Notice(error.to_string())).await; }
                    continue;
                }
                if frame.event().as_str() == "exec.approval.resolved" {
                    if let Some(payload) = frame.payload().value().and_then(|payload| Codec::authenticated().decode_opaque::<Value>(payload).ok())
                        && let Some(id) = payload["id"].as_str().filter(|id| id.len() <= 128)
                    {
                        session.previews.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(id);
                        let _ = sender.send(WorkerEvent::PromptDismissed(id.to_owned())).await;
                    }
                    continue;
                }
                if let Some(mapped) = map_gateway_event(&frame)
                    && sender.send(mapped).await.is_err()
                {
                    break ConnectionExit::Shutdown;
                }
            }
        }
    };
    drop(session);
    let teardown = client
        .shutdown()
        .await
        .map_err(|error| WorkerError(error.to_string()));
    record_client_shutdown(endpoint, &teardown);
    connection_exit_after_teardown(outcome, teardown)
}

/// Reports one graceful client teardown without taking part in it.
///
/// The teardown result is borrowed, so which error wins stays a decision of
/// [`connection_exit_after_teardown`] alone.
fn record_client_shutdown(endpoint: &str, teardown: &Result<(), WorkerError>) {
    match teardown {
        Ok(()) => tracing::debug!(
            action = "client.shutdown",
            outcome = "success",
            endpoint = sanitize(endpoint),
        ),
        Err(error) => tracing::debug!(
            action = "client.shutdown",
            outcome = "failure",
            endpoint = sanitize(endpoint),
            failure.reason = sanitize(&error.to_string()),
        ),
    }
}

fn connection_exit_after_teardown(
    outcome: ConnectionExit,
    teardown: Result<(), WorkerError>,
) -> Result<ConnectionExit, WorkerError> {
    if outcome == ConnectionExit::Shutdown {
        return Ok(outcome);
    }
    teardown?;
    Ok(outcome)
}

async fn send_message(
    client: &GatewaySession<'_>,
    sender: &mpsc::Sender<WorkerEvent>,
    sequence: &mut u64,
    session_id: String,
    text: String,
    idempotency_key: String,
    endpoint: &str,
) -> Result<(), WorkerError> {
    if session_id.is_empty()
        || session_id.len() > 128
        || session_id.chars().any(char::is_control)
        || text.trim().is_empty()
        || text.len() > 16 * 1024
        || idempotency_key.is_empty()
        || idempotency_key.len() > 128
        || idempotency_key.chars().any(char::is_control)
    {
        return refuse_submission(
            sender,
            idempotency_key,
            "Native message or idempotency key exceeds its contract",
        )
        .await;
    }
    *client
        .selected
        .lock()
        .map_err(|_| WorkerError("Session selection is unavailable".to_owned()))? =
        Some(session_id.clone());
    let receipt = request_json(
        client,
        sequence,
        "chat.send",
        &json!({"sessionKey":session_id,"message":text,"idempotencyKey":idempotency_key}),
        endpoint,
    )
    .await;
    let receipt = match receipt {
        Ok(receipt)
            if receipt["durable"] == true
                && receipt["sessionId"].as_str() == Some(session_id.as_str())
                && receipt["runId"].as_str().is_some_and(valid_run_id)
                && (!text.starts_with("!tool ")
                    || receipt["status"] == "accepted"
                        && receipt["revision"]
                            .as_u64()
                            .is_some_and(|revision| revision > 0)
                        && matches!(
                            receipt["phase"].as_str(),
                            Some("queued" | "executing" | "finished" | "outcome_unknown")
                        )) =>
        {
            receipt
        }
        _ => {
            sender
                .send(WorkerEvent::SendUnconfirmed { idempotency_key })
                .await
                .map_err(|_| WorkerError("render loop stopped".to_owned()))?;
            return Err(WorkerError("Message receipt is unconfirmed. Reconcile or retry only the original key; never create a new key for this input.".to_owned()));
        }
    };
    let run_id = receipt["runId"]
        .as_str()
        .ok_or_else(|| WorkerError("Missing durable run identity".to_owned()))?
        .to_owned();
    sender
        .send(WorkerEvent::Accepted {
            session_id: session_id.clone(),
            run_id: run_id.clone(),
            idempotency_key,
        })
        .await
        .map_err(|_| WorkerError("render loop stopped".to_owned()))?;
    send_native_run(client, sender, sequence, &session_id, &run_id, endpoint).await
}

async fn refuse_submission(
    sender: &mpsc::Sender<WorkerEvent>,
    idempotency_key: String,
    reason: &str,
) -> Result<(), WorkerError> {
    sender
        .send(WorkerEvent::SendNotSent {
            idempotency_key,
            reason: reason.to_owned(),
        })
        .await
        .map_err(|_| WorkerError("render loop stopped".to_owned()))
}

async fn handle_command(
    client: &GatewaySession<'_>,
    sender: &mpsc::Sender<WorkerEvent>,
    sequence: &mut u64,
    command: UiCommand,
    endpoint: &str,
) -> Result<(), WorkerError> {
    let (connection_id, command) = match command {
        UiCommand::ForConnection {
            connection_id,
            command,
        } => (Some(connection_id), *command),
        command => (None, command),
    };
    if matches!(command, UiCommand::ForConnection { .. })
        || (command.requires_connection() && connection_id != Some(client.connection_id))
    {
        if let UiCommand::SendMessage {
            idempotency_key, ..
        }
        | UiCommand::InvokeMemory {
            idempotency_key, ..
        } = &command
        {
            sender
                .send(WorkerEvent::SendNotSent {
                    idempotency_key: idempotency_key.clone(),
                    reason:
                        "Command belongs to an unobserved or previous connection; no RPC was sent"
                            .to_owned(),
                })
                .await
                .map_err(|_| WorkerError("render loop stopped".to_owned()))?;
        }
        return Err(WorkerError(
            "Command belongs to an unobserved or previous connection; no RPC was sent".to_owned(),
        ));
    }
    match command {
        UiCommand::ForConnection { .. } => Err(WorkerError(
            "Nested connection command is invalid".to_owned(),
        )),
        UiCommand::InvokeMemory {
            session_id,
            command,
            idempotency_key,
        } => {
            if !client.persistent_identity {
                return refuse_submission(sender, idempotency_key, "Memory requires an explicit persistent --device-profile; no memory command was sent").await;
            }
            let checked = async {
                let health = request_json(client, sequence, "health", &json!({}), endpoint).await?;
                let direct = &health["native"]["directTool"];
                let memory = &health["native"]["explicitMemory"];
                if health["ok"] != true
                    || health["protocol"] != 4
                    || health["native"]["schemaVersion"] != 1
                    || direct["version"] != 1
                    || direct["prefix"] != "!tool "
                    || direct["modelInvoked"] != false
                    || direct["authenticated"] != true
                    || direct["durableRuns"] != true
                    || direct["accepting"] != true
                    || direct["approvalPolicy"] != "per-tool"
                    || memory["enabled"] != true
                    || memory["accepting"] != true
                    || memory["requiresApproval"] != true
                    || memory["partition"] != "source/subject/account"
                    || memory["automaticContextInjection"] != false
                    || matches!(command.action(), "export" | "import")
                        && memory["archiveSchemaVersion"] != 1
                {
                    return Err(WorkerError(
                        "Native model-free memory is unavailable; no memory command was sent"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
            .await;
            if let Err(error) = checked {
                return refuse_submission(sender, idempotency_key, &error.0).await;
            }
            send_message(
                client,
                sender,
                sequence,
                session_id,
                command.message(),
                idempotency_key,
                endpoint,
            )
            .await
        }
        UiCommand::SendMessage {
            session_id,
            text,
            idempotency_key,
        } => {
            if text.lines().any(|line| {
                line.trim_start()
                    .get(..5)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("!tool"))
            }) {
                return refuse_submission(sender, idempotency_key, "Direct tools require a typed command with capability verification; no message was sent").await;
            }
            send_message(
                client,
                sender,
                sequence,
                session_id,
                text,
                idempotency_key,
                endpoint,
            )
            .await
        }
        UiCommand::QueryRun { session_id, run_id } => {
            send_native_run(client, sender, sequence, &session_id, &run_id, endpoint).await
        }
        UiCommand::ReadPartial(request) => {
            let parameters = request.parameters()?;
            let value = request_json(client, sequence, "agent.wait", &parameters, endpoint).await?;
            let page = parse_partial_page(value, request)?;
            sender
                .send(WorkerEvent::PartialPage(page))
                .await
                .map_err(|_| WorkerError("render loop stopped".to_owned()))
        }
        UiCommand::AbortRun { session_id, run_id } => {
            if !valid_run_id(&run_id) {
                return Err(WorkerError("Invalid run identity".to_owned()));
            }
            request_json(
                client,
                sequence,
                "chat.abort",
                &json!({"sessionKey":session_id,"runId":run_id}),
                endpoint,
            )
            .await?;
            send_native_run(client, sender, sequence, &session_id, &run_id, endpoint).await
        }
        UiCommand::AcknowledgeRun { run_id, revision } => {
            if client
                .complete_results
                .lock()
                .map_err(|_| WorkerError("Run display state is unavailable".to_owned()))?
                .get(&run_id)
                != Some(&revision)
            {
                return Err(WorkerError(
                    "Cannot acknowledge a result that was not delivered completely".to_owned(),
                ));
            }
            let receipt = request_json(
                client,
                sequence,
                "agent.wait",
                &json!({"runId":run_id,"acknowledgeRevision":revision}),
                endpoint,
            )
            .await?;
            if receipt["runId"].as_str() != Some(run_id.as_str())
                || receipt["revision"].as_u64() != Some(revision)
                || receipt["acknowledged"] != true
                || receipt["durable"] != true
            {
                return Err(WorkerError(
                    "Result acknowledgement is unconfirmed; the original run must be reconciled"
                        .to_owned(),
                ));
            }
            client
                .complete_results
                .lock()
                .map_err(|_| WorkerError("Run display state is unavailable".to_owned()))?
                .remove(&run_id);
            sender
                .send(WorkerEvent::ResultAcknowledged { run_id, revision })
                .await
                .map_err(|_| WorkerError("render loop stopped".to_owned()))
        }
        UiCommand::Refresh => send_sessions(client, sender, sequence, endpoint).await,
        UiCommand::RecoverRuns(session_id) => {
            send_recovery_page(client, sender, sequence, &session_id, endpoint).await
        }
        UiCommand::SelectSession(session_id) => {
            *client
                .selected
                .lock()
                .map_err(|_| WorkerError("Session selection is unavailable".to_owned()))? =
                Some(session_id.clone());
            let history = request_json(
                client,
                sequence,
                "chat.history",
                &json!({"sessionKey":session_id}),
                endpoint,
            )
            .await?;
            if history["sessionKey"].as_str() != Some(session_id.as_str()) {
                return Err(WorkerError("History belongs to another session".to_owned()));
            }
            let items = history["messages"]
                .as_array()
                .filter(|items| items.len() <= 256)
                .ok_or_else(|| {
                    WorkerError("History exceeds the retained native window".to_owned())
                })?;
            let mut messages = Vec::with_capacity(items.len());
            for item in items {
                let role = item["role"]
                    .as_str()
                    .filter(|role| !role.is_empty() && role.len() <= 128)
                    .ok_or_else(|| WorkerError("History contains an invalid role".to_owned()))?;
                let text = item["text"]
                    .as_str()
                    .filter(|text| text.len() <= MAX_EVENT_TEXT_BYTES)
                    .ok_or_else(|| {
                        WorkerError(
                            "History contains a message too large to display completely".to_owned(),
                        )
                    })?;
                messages.push(TranscriptEntry {
                    role: role.to_owned(),
                    text: text.to_owned(),
                });
            }
            sender
                .send(WorkerEvent::History {
                    session_id: session_id.clone(),
                    messages,
                })
                .await
                .map_err(|_| WorkerError("render loop stopped".to_owned()))?;
            send_pending_approval(client, sender, sequence, &session_id, endpoint).await?;
            *client
                .recovery
                .lock()
                .map_err(|_| WorkerError("Run recovery state is unavailable".to_owned()))? =
                Some(RunRecovery {
                    session_id: session_id.clone(),
                    after: None,
                    active_after: None,
                    pending_done: false,
                    active_done: false,
                    pages: 0,
                });
            send_recovery_page(client, sender, sequence, &session_id, endpoint).await
        }
        UiCommand::LoadDiff(session_id) => {
            let value = request_json(
                client,
                sequence,
                "sessions.diff",
                &json!({"sessionId": session_id}),
                endpoint,
            )
            .await?;
            let lines = value
                .get("diff")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .lines()
                .take(MAX_DIFF_LINES)
                .map(|line| bounded_text(line, MAX_EVENT_TEXT_BYTES))
                .collect();
            sender
                .send(WorkerEvent::Diff { session_id, lines })
                .await
                .map_err(|_| WorkerError("render loop stopped".to_owned()))
        }
        UiCommand::LoadArtifacts(session_id) => {
            let value = request_json(
                client,
                sequence,
                "artifacts.list",
                &json!({"sessionId": session_id}),
                endpoint,
            )
            .await?;
            let entries = value
                .get("artifacts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(MAX_ARTIFACTS)
                .filter_map(|item| {
                    let name = item
                        .get("name")
                        .or_else(|| item.get("path"))
                        .and_then(Value::as_str)
                        .map(|name| bounded_text(name, MAX_LABEL_BYTES))?;
                    let id = item
                        .get("id")
                        .or_else(|| item.get("artifactId"))
                        .or_else(|| item.get("path"))
                        .and_then(Value::as_str)
                        .map_or_else(|| name.clone(), |id| bounded_text(id, MAX_LABEL_BYTES));
                    Some((name, id))
                })
                .collect::<Vec<_>>();
            sender
                .send(WorkerEvent::Artifacts {
                    session_id: session_id.clone(),
                    artifacts: entries.iter().map(|(name, _)| name.clone()).collect(),
                })
                .await
                .map_err(|_| WorkerError("render loop stopped".to_owned()))?;
            if let Some((_, artifact_id)) = entries.first() {
                let preview = request_json(
                    client,
                    sequence,
                    "artifacts.get",
                    &json!({"sessionId": session_id, "artifactId": artifact_id}),
                    endpoint,
                )
                .await?;
                sender
                    .send(WorkerEvent::ArtifactContent {
                        session_id,
                        lines: artifact_preview(&preview),
                    })
                    .await
                    .map_err(|_| WorkerError("render loop stopped".to_owned()))?;
            }
            Ok(())
        }
        UiCommand::ResolveApproval {
            id,
            approved,
            preview_fingerprint,
        } => {
            if client
                .previews
                .lock()
                .map_err(|_| WorkerError("Approval display state is unavailable".to_owned()))?
                .get(&id)
                != Some(&preview_fingerprint)
            {
                return Err(WorkerError(
                    "Approval was not reviewed on this connection; refresh its preview".to_owned(),
                ));
            }
            let preview = request_json(
                client,
                sequence,
                "exec.approval.get",
                &json!({"id": id}),
                endpoint,
            )
            .await?;
            let Some(Prompt::Approval {
                preview_fingerprint: Some(current),
                ..
            }) = complete_approval_preview(&preview, &id)
            else {
                return Err(WorkerError(
                    "Approval preview is incomplete or exceeds the display limit".to_owned(),
                ));
            };
            if current != preview_fingerprint {
                return Err(WorkerError(
                    "Approval preview changed; review the current request".to_owned(),
                ));
            }
            let _ = request_json(
                client,
                sequence,
                "approval.resolve",
                &json!({
                    "id": id,
                    "decision": if approved { "approve" } else { "deny" },
                    "bindingToken": preview["bindingToken"],
                }),
                endpoint,
            )
            .await?;
            client
                .previews
                .lock()
                .map_err(|_| WorkerError("Approval display state is unavailable".to_owned()))?
                .remove(&id);
            sender
                .send(WorkerEvent::Notice(if approved {
                    "Approval accepted".to_owned()
                } else {
                    "Approval denied".to_owned()
                }))
                .await
                .map_err(|_| WorkerError("render loop stopped".to_owned()))?;
            if let Some(session) = preview["sessionId"].as_str() {
                send_pending_approval(client, sender, sequence, session, endpoint).await?;
            }
            Ok(())
        }
        UiCommand::Answer {
            session_id,
            question_id,
            text,
        } => {
            let _ = request_json(
                client,
                sequence,
                "sessions.send",
                &json!({
                    "sessionId": session_id,
                    "questionId": question_id,
                    "message": text
                }),
                endpoint,
            )
            .await?;
            Ok(())
        }
        UiCommand::Shutdown => Ok(()),
    }
}

async fn send_sessions(
    client: &GatewaySession<'_>,
    sender: &mpsc::Sender<WorkerEvent>,
    sequence: &mut u64,
    endpoint: &str,
) -> Result<(), WorkerError> {
    let value = request_json(client, sequence, "sessions.list", &json!({}), endpoint).await?;
    sender
        .send(WorkerEvent::Sessions(parse_sessions(&value)))
        .await
        .map_err(|_| WorkerError("render loop stopped".to_owned()))
}

fn valid_run_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone)]
struct RunRecovery {
    session_id: String,
    after: Option<String>,
    active_after: Option<String>,
    pending_done: bool,
    active_done: bool,
    pages: usize,
}

fn recovery_cursor(value: &Value, previous: Option<&str>) -> Result<Option<String>, WorkerError> {
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_str()
        .filter(|cursor| valid_run_id(cursor) && previous.is_none_or(|previous| *cursor > previous))
        .map(|cursor| Some(cursor.to_owned()))
        .ok_or_else(|| WorkerError("Run recovery cursor is invalid or did not advance".to_owned()))
}

async fn send_recovery_page(
    client: &GatewaySession<'_>,
    sender: &mpsc::Sender<WorkerEvent>,
    sequence: &mut u64,
    session_id: &str,
    endpoint: &str,
) -> Result<(), WorkerError> {
    let mut recovery = client
        .recovery
        .lock()
        .map_err(|_| WorkerError("Run recovery state is unavailable".to_owned()))?
        .clone()
        .filter(|recovery| {
            recovery.session_id == session_id && !(recovery.pending_done && recovery.active_done)
        })
        .ok_or_else(|| WorkerError("No recovery page is pending for this session".to_owned()))?;
    if recovery.pages >= 512 {
        return Err(WorkerError(
            "Run recovery reached its bounded page limit; remaining results are retained"
                .to_owned(),
        ));
    }
    let mut parameters = json!({"sessionKey":session_id});
    if let Some(after) = &recovery.after {
        parameters["after"] = json!(after);
    }
    if let Some(after) = &recovery.active_after {
        parameters["activeAfter"] = json!(after);
    }
    let results = request_json(client, sequence, "sessions.get", &parameters, endpoint).await?;
    if results["sessionKey"].as_str() != Some(session_id) {
        return Err(WorkerError(
            "Run recovery belongs to another session".to_owned(),
        ));
    }
    for (field, cursor, done, next) in [
        (
            "pendingRuns",
            &mut recovery.after,
            &mut recovery.pending_done,
            "nextCursor",
        ),
        (
            "activeRuns",
            &mut recovery.active_after,
            &mut recovery.active_done,
            "nextActiveCursor",
        ),
    ] {
        if *done {
            continue;
        }
        let runs = results[field]
            .as_array()
            .filter(|runs| runs.len() <= 32)
            .ok_or_else(|| WorkerError("Native run recovery page exceeds its bound".to_owned()))?;
        let following = recovery_cursor(&results[next], cursor.as_deref())?;
        for run in runs {
            let run_id = run["runId"]
                .as_str()
                .filter(|run_id| valid_run_id(run_id))
                .ok_or_else(|| WorkerError("Invalid recovery run identity".to_owned()))?;
            if run["sessionId"].as_str() != Some(session_id) {
                return Err(WorkerError(
                    "Recovery run belongs to another session".to_owned(),
                ));
            }
            send_native_run(client, sender, sequence, session_id, run_id, endpoint).await?;
        }
        *done = following.is_none();
        if following.is_some() {
            *cursor = following;
        }
    }
    recovery.pages += 1;
    let more = !(recovery.pending_done && recovery.active_done);
    *client
        .recovery
        .lock()
        .map_err(|_| WorkerError("Run recovery state is unavailable".to_owned()))? = Some(recovery);
    if more {
        sender
            .send(WorkerEvent::RecoveryAvailable(session_id.to_owned()))
            .await
            .map_err(|_| WorkerError("render loop stopped".to_owned()))?;
    }
    Ok(())
}

async fn send_native_run(
    client: &GatewaySession<'_>,
    sender: &mpsc::Sender<WorkerEvent>,
    sequence: &mut u64,
    session_id: &str,
    run_id: &str,
    endpoint: &str,
) -> Result<(), WorkerError> {
    if !valid_run_id(run_id) {
        return Err(WorkerError("Invalid durable run identity".to_owned()));
    }
    let run = request_json(
        client,
        sequence,
        "agent.wait",
        &json!({"runId":run_id,"timeoutMs":0}),
        endpoint,
    )
    .await?;
    if run["runId"].as_str() != Some(run_id)
        || run["sessionId"].as_str() != Some(session_id)
        || run["durable"] != true
    {
        return Err(WorkerError(
            "Run result belongs to another session or lacks durability confirmation".to_owned(),
        ));
    }
    let revision = run["revision"]
        .as_u64()
        .filter(|revision| *revision > 0)
        .ok_or_else(|| WorkerError("Run revision is invalid".to_owned()))?;
    let status = run["result"]["status"]
        .as_str()
        .or_else(|| run["status"].as_str())
        .unwrap_or("outcome_unknown");
    let state = if status == "executing" {
        RunState::Running
    } else {
        RunState::parse(status)
    };
    let text = if run["result"].is_null() {
        None
    } else {
        if !matches!(run["phase"].as_str(), Some("finished" | "outcome_unknown")) {
            return Err(WorkerError(
                "Non-terminal run carried a final result".to_owned(),
            ));
        }
        Some(
            run["result"]["text"]
                .as_str()
                .filter(|text| text.len() <= MAX_EVENT_TEXT_BYTES)
                .ok_or_else(|| {
                    WorkerError(
                        "Run result exceeds the complete display limit; it was not acknowledged"
                            .to_owned(),
                    )
                })?
                .to_owned(),
        )
    };
    if text.is_some() {
        let mut results = client
            .complete_results
            .lock()
            .map_err(|_| WorkerError("Run display state is unavailable".to_owned()))?;
        if results.len() >= MAX_SESSIONS && !results.contains_key(run_id) {
            return Err(WorkerError(
                "Unacknowledged display capacity reached".to_owned(),
            ));
        }
        results.insert(run_id.to_owned(), revision);
    }
    sender
        .send(WorkerEvent::NativeRun {
            session_id: session_id.to_owned(),
            run_id: run_id.to_owned(),
            state,
            turn: run["turn"].as_u64(),
            text,
            revision,
        })
        .await
        .map_err(|_| WorkerError("render loop stopped".to_owned()))
}

async fn send_approval_preview(
    client: &GatewaySession<'_>,
    sender: &mpsc::Sender<WorkerEvent>,
    sequence: &mut u64,
    id: &str,
    endpoint: &str,
) -> Result<(), WorkerError> {
    let preview = request_json(
        client,
        sequence,
        "exec.approval.get",
        &json!({"id": id}),
        endpoint,
    )
    .await?;
    let prompt = complete_approval_preview(&preview, id).ok_or_else(|| {
        WorkerError("Approval preview is incomplete or exceeds the display limit".to_owned())
    })?;
    if let Prompt::Approval {
        preview_fingerprint: Some(fingerprint),
        ..
    } = &prompt
    {
        let mut previews = client
            .previews
            .lock()
            .map_err(|_| WorkerError("Approval display state is unavailable".to_owned()))?;
        if previews.len() >= 64 && !previews.contains_key(id) {
            return Err(WorkerError(
                "Pending approval display limit reached".to_owned(),
            ));
        }
        previews.insert(id.to_owned(), fingerprint.clone());
    }
    sender
        .send(WorkerEvent::Prompt(prompt))
        .await
        .map_err(|_| WorkerError("render loop stopped".to_owned()))
}

async fn send_pending_approval(
    client: &GatewaySession<'_>,
    sender: &mpsc::Sender<WorkerEvent>,
    sequence: &mut u64,
    session: &str,
    endpoint: &str,
) -> Result<(), WorkerError> {
    let pending = request_json(
        client,
        sequence,
        "exec.approval.list",
        &json!({"sessionId": session}),
        endpoint,
    )
    .await?;
    let requests = pending["requests"]
        .as_array()
        .filter(|requests| requests.len() <= 32)
        .ok_or_else(|| {
            WorkerError("Gateway returned an invalid pending approval page".to_owned())
        })?;
    if let Some(id) = requests
        .first()
        .and_then(|request| request["id"].as_str())
        .filter(|id| !id.is_empty() && id.len() <= 128)
    {
        send_approval_preview(client, sender, sequence, id, endpoint).await?;
    }
    Ok(())
}

fn complete_approval_preview(preview: &Value, id: &str) -> Option<Prompt> {
    if id.is_empty()
        || id.len() > 128
        || preview["id"].as_str() != Some(id)
        || preview["previewComplete"] != true
    {
        return None;
    }
    let fingerprint = claw_security::authorization::approval_preview_fingerprint(
        preview["bindingToken"].as_str()?,
    )?;
    if preview["previewFingerprint"].as_str() != Some(fingerprint.as_str()) {
        return None;
    }
    let prompt = claw_protocol::native_approval::checked_bound_approval_prompt(
        preview,
        MAX_EVENT_TEXT_BYTES,
    )?;
    Some(Prompt::Approval {
        id: id.to_owned(),
        text: prompt.to_owned(),
        preview_fingerprint: Some(fingerprint),
    })
}

async fn request_json(
    client: &GatewaySession<'_>,
    sequence: &mut u64,
    method: &'static str,
    params: &Value,
    endpoint: &str,
) -> Result<Value, WorkerError> {
    let core = resolve_core_method(method)
        .ok_or_else(|| WorkerError(format!("frozen Gateway method missing: {method}")))?;
    let correlation = format!("gta-claw-tui-{}", *sequence);
    let request_id = RequestId::new(correlation.clone(), AUTHENTICATED_MAX_FRAME_BYTES)
        .map_err(|error| WorkerError(error.to_string()))?;
    *sequence = sequence
        .checked_add(1)
        .ok_or_else(|| WorkerError("Gateway request identity exhausted".to_owned()))?;
    tracing::trace!(
        action = "rpc.request",
        outcome = "success",
        endpoint = sanitize(endpoint),
        rpc.method = method,
        rpc.request_id = correlation.as_str(),
    );
    let response = match client
        .client
        .request_for_epoch(
            client.epoch,
            request_id,
            GatewayMethodName::Core(core),
            params,
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            let error = WorkerError(error.to_string());
            tracing::debug!(
                action = "rpc.response",
                outcome = "failure",
                endpoint = sanitize(endpoint),
                rpc.method = method,
                failure.reason = sanitize(&error.to_string()),
            );
            return Err(error);
        }
    };
    if !response.ok() {
        let failure = response
            .error()
            .map_or("unknown", |error| error.code.as_str());
        tracing::debug!(
            action = "rpc.response",
            outcome = "failure",
            endpoint = sanitize(endpoint),
            rpc.method = method,
            rpc.error_code = sanitize(failure),
        );
        return Err(WorkerError(format!("{method} failed ({failure})")));
    }
    tracing::debug!(
        action = "rpc.response",
        outcome = "success",
        endpoint = sanitize(endpoint),
        rpc.method = method,
        rpc.ok = bool_field(true),
    );
    let Some(payload) = response.payload().value() else {
        return Ok(Value::Null);
    };
    Codec::authenticated()
        .decode_opaque::<Value>(payload)
        .map_err(|error| WorkerError(error.to_string()))
}

fn parse_sessions(value: &Value) -> Vec<SessionSummary> {
    let items = value
        .get("sessions")
        .or_else(|| value.get("items"))
        .and_then(Value::as_array)
        .or_else(|| value.as_array());
    items
        .into_iter()
        .flatten()
        .take(MAX_SESSIONS)
        .filter_map(|item| {
            let id = bounded_string_field(item, &["id", "sessionId", "key"], MAX_LABEL_BYTES)?;
            let title = bounded_string_field(item, &["title", "name", "label"], MAX_LABEL_BYTES)
                .unwrap_or_else(|| id.clone());
            let workspace =
                bounded_string_field(item, &["workspace", "cwd", "path"], MAX_LABEL_BYTES)
                    .unwrap_or_default();
            let state = bounded_string_field(item, &["state", "status"], 64)
                .map_or(RunState::Draft, |state| RunState::parse(&state));
            let progress = item
                .get("progress")
                .and_then(Value::as_u64)
                .and_then(|value| u8::try_from(value.min(100)).ok());
            Some(SessionSummary {
                id,
                title,
                workspace,
                state,
                progress,
            })
        })
        .collect()
}

fn map_gateway_event(frame: &claw_protocol::gateway::EventFrame) -> Option<WorkerEvent> {
    let event_name = frame.event().as_str().to_owned();
    if event_name == "sessions.changed" {
        return Some(WorkerEvent::Notice(
            "Sessions changed; press r to refresh".to_owned(),
        ));
    }
    let payload = frame
        .payload()
        .value()
        .and_then(|payload| Codec::authenticated().decode_opaque::<Value>(payload).ok())?;
    let session_id = event_session(&payload)?;
    match event_name.as_str() {
        "session.message" | "chat" => {
            if payload.get("question").is_some() || payload.get("questionId").is_some() {
                Some(WorkerEvent::SessionPrompt {
                    session_id,
                    prompt: Prompt::Question {
                        id: bounded_string_field(&payload, &["questionId", "id"], MAX_LABEL_BYTES)
                            .unwrap_or_default(),
                        text: bounded_string_field(
                            &payload,
                            &["question", "text", "message"],
                            MAX_EVENT_TEXT_BYTES,
                        )
                        .unwrap_or_else(|| "Agent is waiting for an answer".to_owned()),
                    },
                })
            } else {
                Some(WorkerEvent::Message {
                    session_id,
                    message: TranscriptEntry {
                        role: bounded_string_field(&payload, &["role", "source"], 128)
                            .unwrap_or_else(|| "agent".to_owned()),
                        text: bounded_string_field(
                            &payload,
                            &["text", "message", "content"],
                            MAX_EVENT_TEXT_BYTES,
                        )
                        .unwrap_or_default(),
                    },
                })
            }
        }
        "session.tool" | "session.operation" => Some(WorkerEvent::Tool {
            session_id,
            tool: ToolActivity {
                name: bounded_string_field(&payload, &["tool", "name", "operation"], 128)
                    .unwrap_or_else(|| "operation".to_owned()),
                status: bounded_string_field(&payload, &["status", "state"], 128)
                    .unwrap_or_else(|| "running".to_owned()),
                summary: bounded_string_field(
                    &payload,
                    &["summary", "message", "description"],
                    MAX_EVENT_TEXT_BYTES,
                )
                .unwrap_or_default(),
            },
        }),
        "session.approval" | "exec.approval.requested" | "plugin.approval.requested" => {
            Some(WorkerEvent::SessionPrompt {
                session_id,
                prompt: Prompt::Approval {
                    preview_fingerprint: None,
                    id: bounded_string_field(&payload, &["approvalId", "id"], MAX_LABEL_BYTES)
                        .unwrap_or_default(),
                    text: bounded_string_field(
                        &payload,
                        &["prompt", "command", "message"],
                        MAX_EVENT_TEXT_BYTES,
                    )
                    .unwrap_or_else(|| "Agent requests approval".to_owned()),
                },
            })
        }
        _ => None,
    }
}

fn event_session(payload: &Value) -> Option<String> {
    let mut selected: Option<&str> = None;
    for field in ["sessionId", "sessionKey"] {
        if let Some(value) = payload.get(field) {
            let value = value.as_str().filter(|value| {
                !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
            })?;
            if selected.is_some_and(|selected| selected != value) {
                return None;
            }
            selected = Some(value);
        }
    }
    selected.map(str::to_owned)
}

fn string_field(value: &Value, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

fn bounded_string_field(value: &Value, names: &[&str], max_bytes: usize) -> Option<String> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
        .map(|value| bounded_text(value, max_bytes))
}

fn bounded_text(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let suffix = if max_bytes >= '…'.len_utf8() {
        "…"
    } else {
        ""
    };
    let mut end = max_bytes.saturating_sub(suffix.len()).min(value.len());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let mut bounded = value[..end].to_owned();
    bounded.push_str(suffix);
    bounded
}

fn artifact_preview(value: &Value) -> Vec<String> {
    let text = string_field(value, &["content", "text", "data"]).unwrap_or_else(|| {
        serde_json::to_string_pretty(value)
            .unwrap_or_else(|_| "Artifact preview unavailable".to_owned())
    });
    text.lines()
        .take(MAX_PREVIEW_LINES)
        .map(|line| bounded_text(line, MAX_EVENT_TEXT_BYTES))
        .collect()
}

fn generate_identity() -> Result<DeviceIdentity, WorkerError> {
    let random = SystemRandom::new();
    let mut rng = IdentityRandom(&random);
    DeviceIdentity::try_generate(&mut rng)
        .map_err(|_| WorkerError("secure randomness is unavailable".to_owned()))
}

struct IdentityRandom<'a>(&'a SystemRandom);

impl TryRng for IdentityRandom<'_> {
    type Error = RandomError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill(destination).map_err(|_| RandomError)
    }
}

impl TryCryptoRng for IdentityRandom<'_> {}

#[derive(Clone, Copy, Debug)]
struct RandomError;

impl Display for RandomError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("system random fill failed")
    }
}

impl Error for RandomError {}

#[derive(Debug)]
struct WorkerError(String);

impl Display for WorkerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for WorkerError {}

/// Names a connection state for a user-facing notice.
const fn connection_label(state: &ConnectionState) -> &'static str {
    match state {
        ConnectionState::Starting => "starting",
        ConnectionState::Connecting => "connecting",
        ConnectionState::Authenticating => "authenticating",
        ConnectionState::Ready(_) => "ready",
        ConnectionState::Reconnecting { .. } => "reconnecting",
        ConnectionState::ResyncRequired(_) => "resync required",
        ConnectionState::AuthenticationFailed(_) => "authentication failed",
        ConnectionState::ProtocolFailed { .. } => "protocol failed",
        ConnectionState::ReconnectExhausted => "reconnect exhausted",
        ConnectionState::Stopped => "stopped",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn partial_page_identity_bounds_and_content_are_checked_before_display() {
        use super::{PartialPageRequest, RunState, parse_partial_page, partial_sha256};
        use serde_json::json;

        let request = PartialPageRequest {
            session_id: "owned".to_owned(),
            run_id: "a".repeat(64),
            revision: 3,
            turn: 0,
            state: RunState::OutcomeUnknown,
            offset: 0,
            total_bytes: None,
            sha256: None,
        };
        let value = json!({"runId":request.run_id,"sessionId":"owned","revision":3,"turn":0,"status":"outcome_unknown","durable":true,"acknowledged":false,"automaticReplay":false,
            "partial":{"available":true,"text":"abc","offset":0,"nextOffset":null,"totalBytes":3,"sha256":partial_sha256(b"abc"),"messageComplete":false,"untrusted":true,"reasoningIncluded":false,"toolArgumentsIncluded":false}});
        let page =
            parse_partial_page(value.clone(), request.clone()).expect("single complete page");
        assert_eq!(page.text, "abc");
        assert_eq!(page.end_offset, 3);
        assert!(page.next_offset.is_none());
        for (pointer, changed) in [
            ("/runId", json!("b".repeat(64))),
            ("/sessionId", json!("other")),
            ("/revision", json!(4)),
            ("/turn", json!(1)),
            ("/status", json!("executing")),
            ("/status", json!("failed")),
            ("/acknowledged", json!(true)),
            ("/automaticReplay", json!(true)),
            ("/partial/offset", json!(1)),
            ("/partial/nextOffset", json!(1)),
            ("/partial/text", json!("bad")),
            ("/partial/totalBytes", json!(4_194_305)),
            ("/partial/sha256", json!("0".repeat(64))),
            ("/partial/reasoningIncluded", json!(true)),
            ("/partial/toolArgumentsIncluded", json!(true)),
            ("/partial/messageComplete", json!(true)),
            ("/partial/untrusted", json!(false)),
        ] {
            let mut corrupt = value.clone();
            *corrupt.pointer_mut(pointer).expect("fixture field") = changed;
            assert!(
                parse_partial_page(corrupt, request.clone()).is_err(),
                "{pointer}"
            );
        }
        let mut continuation = value.clone();
        continuation["partial"]["offset"] = json!(2048);
        continuation["partial"]["totalBytes"] = json!(2051);
        let next = PartialPageRequest {
            offset: 2048,
            total_bytes: Some(2051),
            sha256: Some(partial_sha256(b"abc")),
            ..request.clone()
        };
        assert!(parse_partial_page(continuation.clone(), next.clone()).is_ok());
        assert!(
            parse_partial_page(
                continuation.clone(),
                PartialPageRequest {
                    total_bytes: Some(2052),
                    ..next.clone()
                }
            )
            .is_err()
        );
        assert!(
            parse_partial_page(
                continuation,
                PartialPageRequest {
                    sha256: None,
                    ..next
                }
            )
            .is_err()
        );
        let mut empty = value;
        empty["partial"]["text"] = json!("");
        empty["partial"]["totalBytes"] = json!(0);
        empty["partial"]["sha256"] = json!(partial_sha256(b""));
        assert!(parse_partial_page(empty, request).is_ok());
    }

    use super::{ConnectionExit, WorkerError, connection_exit_after_teardown};

    #[test]
    fn native_recovery_cursor_is_bounded_canonical_and_strictly_advancing() {
        use super::recovery_cursor;
        use serde_json::json;

        let previous = "1".repeat(64);
        assert_eq!(
            recovery_cursor(&json!("2".repeat(64)), Some(&previous)).expect("advancing cursor"),
            Some("2".repeat(64))
        );
        assert_eq!(
            recovery_cursor(&serde_json::Value::Null, Some(&previous)).expect("completed page"),
            None
        );
        for value in [
            json!(previous),
            json!("0".repeat(64)),
            json!("A".repeat(64)),
            json!(""),
            json!(5),
        ] {
            assert!(recovery_cursor(&value, Some(&previous)).is_err());
        }
    }

    #[test]
    fn native_event_session_requires_exact_nonconflicting_identity() {
        use super::event_session;
        use serde_json::json;

        assert_eq!(
            event_session(&json!({"sessionId":"current"})).as_deref(),
            Some("current")
        );
        assert_eq!(
            event_session(&json!({"sessionKey":"current","sessionId":"current"})).as_deref(),
            Some("current")
        );
        for payload in [
            json!({}),
            json!({"sessionId":""}),
            json!({"sessionId":null}),
            json!({"sessionId":"current","sessionKey":"other"}),
            json!({"sessionId":"current\n"}),
            json!({"sessionId":"x".repeat(129)}),
        ] {
            assert!(
                event_session(&payload).is_none(),
                "invalid event identity was accepted"
            );
        }
    }

    #[test]
    fn shutdown_decision_wins_over_a_teardown_error() {
        let outcome = connection_exit_after_teardown(
            ConnectionExit::Shutdown,
            Err(WorkerError("simulated shutdown timeout".to_owned())),
        );

        assert!(matches!(outcome, Ok(ConnectionExit::Shutdown)));
    }
}

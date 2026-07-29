//! Narrow runtime ports consumed by the HTTP adapter.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use claw_protocol::gateway::ConnectParams;
use claw_security::audit::AuditEvent;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// A boxed asynchronous port operation.
pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Dependency readiness at one instant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadinessSnapshot {
    /// Whether all required dependencies can accept work.
    pub ready: bool,
    /// Stable dependency names that currently fail readiness.
    pub failing: Vec<String>,
    /// Process uptime in milliseconds.
    pub uptime_ms: u64,
}

/// Supplies real dependency health rather than a constant probe response.
pub trait ReadinessPort: Send + Sync {
    /// Returns the current readiness snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] when the adapter cannot determine dependency
    /// health at all — for example its own state is poisoned or unreachable.
    /// An implementation must not report an error merely because a dependency
    /// is down; that is a `ready: false` snapshot instead. `GET /ready` renders
    /// an error as `503` with `{"ready":false}`, and for an authenticated
    /// caller lists `internal` in `failing`.
    fn snapshot(&self) -> Result<ReadinessSnapshot, PortError>;
}

/// One OpenAI-compatible model.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Model {
    /// Public model identifier.
    pub id: String,
}

/// Usage values shared by chat and Responses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Usage {
    /// Input token count.
    pub input_tokens: u64,
    /// Output token count.
    pub output_tokens: u64,
    /// Total token count.
    pub total_tokens: u64,
}

/// One client-provided function tool.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClientTool {
    /// Function name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// JSON Schema parameters.
    pub parameters: Option<Value>,
}

/// Kind of multimodal input attached to a generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputMediaKind {
    /// Image input.
    Image,
    /// File input.
    File,
}

/// Validated source for one multimodal input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputMediaSource {
    /// Untrusted remote HTTP(S) source to be resolved by the application adapter.
    ///
    /// Parsing only proves URL syntax. Adapters that fetch this source must
    /// enforce SSRF policy on the resolved address, connect to that validated
    /// address, and repeat validation for every redirect.
    Url(String),
    /// Base64-encoded inline source.
    Base64 {
        /// Declared MIME type.
        media_type: String,
        /// Base64 payload without a data-URI prefix.
        data: String,
        /// Optional client filename.
        filename: Option<String>,
    },
}

/// One validated image or file input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputMedia {
    /// Input kind.
    pub kind: InputMediaKind,
    /// Validated source.
    pub source: InputMediaSource,
}

/// Requested tool-choice policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolChoice {
    /// Provider may choose a tool.
    Auto,
    /// Provider must not call tools.
    None,
    /// Provider must call at least one supplied tool.
    Required,
    /// Provider must call this function.
    Function(String),
}

/// Provider-neutral generation request.
#[derive(Clone, Debug, PartialEq)]
pub struct GenerationRequest {
    /// `OpenClaw` routing model identifier.
    pub model: String,
    /// Flattened conversation prompt.
    pub prompt: String,
    /// Optional system instructions.
    pub instructions: Option<String>,
    /// Validated multimodal inputs from the active turn.
    pub media: Vec<InputMedia>,
    /// Client-provided tools.
    pub tools: Vec<ClientTool>,
    /// Tool-choice constraint.
    pub tool_choice: ToolChoice,
    /// Optional output token limit.
    pub max_tokens: Option<u64>,
    /// Optional upper bound on emitted tool calls.
    pub max_tool_calls: Option<u64>,
    /// Optional sampling temperature.
    pub temperature: Option<f64>,
    /// Optional top-p value.
    pub top_p: Option<f64>,
    /// Optional frequency penalty.
    pub frequency_penalty: Option<f64>,
    /// Optional presence penalty.
    pub presence_penalty: Option<f64>,
    /// Optional deterministic sampling seed.
    pub seed: Option<i64>,
    /// Optional stop sequences.
    pub stop: Option<Vec<String>>,
    /// Optional `OpenAI` response-format object.
    pub response_format: Option<Value>,
    /// Stable request identifier.
    pub request_id: String,
    /// Provider session used for scoped response continuity.
    pub session_id: String,
}

/// One pending client tool call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ToolCall {
    /// Provider call identifier.
    pub id: String,
    /// Function name.
    pub name: String,
    /// Serialized JSON arguments.
    pub arguments: String,
}

/// Completed provider generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationOutput {
    /// Assistant text.
    pub text: String,
    /// Pending client tool calls.
    pub tool_calls: Vec<ToolCall>,
    /// Usage accounting.
    pub usage: Usage,
}

/// One backpressured streaming provider event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenerationEvent {
    /// Assistant text delta.
    Text(String),
    /// Completed client tool call.
    ToolCall(ToolCall),
}

/// Embedding provider request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddingRequest {
    /// `OpenClaw` routing model identifier.
    pub model: String,
    /// Input texts.
    pub input: Vec<String>,
    /// Optional output dimensions.
    pub dimensions: Option<usize>,
}

/// Calls the provider SDK without depending on a concrete provider crate.
pub trait ProviderPort: Send + Sync {
    /// Lists configured `OpenClaw` model aliases.
    fn models(&self) -> PortFuture<'_, Result<Vec<Model>, PortError>>;

    /// Runs a non-streaming generation.
    fn generate(
        &self,
        request: GenerationRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<GenerationOutput, PortError>>;

    /// Streams deltas through a bounded sender and returns final usage.
    fn stream(
        &self,
        request: GenerationRequest,
        events: mpsc::Sender<GenerationEvent>,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<Usage, PortError>>;

    /// Embeds one bounded batch.
    fn embed(
        &self,
        request: EmbeddingRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<Vec<Vec<f32>>, PortError>>;
}

/// Result of an HTTP tool invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolOutcome {
    /// HTTP status selected by tool policy.
    pub status: u16,
    /// Success flag.
    pub ok: bool,
    /// Success result.
    pub result: Option<Value>,
    /// Stable error type.
    pub error_type: Option<String>,
    /// Safe error message.
    pub error_message: Option<String>,
    /// Whether approval is required.
    pub requires_approval: Option<bool>,
}

/// Complete routing and policy context for one tool invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolInvocationContext {
    /// Optional explicit session key.
    pub session_key: Option<String>,
    /// Optional explicit agent ID.
    pub agent_id: Option<String>,
    /// Optional idempotency key.
    pub idempotency_key: Option<String>,
    /// Optional message channel used for policy inheritance.
    pub message_channel: Option<String>,
    /// Optional channel account.
    pub account_id: Option<String>,
    /// Optional message target.
    pub agent_to: Option<String>,
    /// Optional thread ID.
    pub agent_thread_id: Option<String>,
    /// Whether the authenticated caller is the owner.
    pub sender_is_owner: bool,
    /// Whether the caller requested a non-executing policy preview.
    pub dry_run: bool,
}

/// One fully contextualized tool invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolInvocation {
    /// Tool name.
    pub name: String,
    /// Tool arguments.
    pub arguments: Value,
    /// Optional top-level action merged only when the target schema supports it.
    pub action: Option<String>,
    /// Routing and policy context.
    pub context: ToolInvocationContext,
}

/// Tool schema exposed to MCP.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ToolDefinition {
    /// Tool name.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Input JSON Schema.
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// Invokes gateway-scoped tools and supplies MCP schemas.
pub trait ToolPort: Send + Sync {
    /// Lists currently available tools.
    fn list(&self) -> PortFuture<'_, Result<Vec<ToolDefinition>, PortError>>;

    /// Invokes one tool.
    fn invoke(
        &self,
        invocation: ToolInvocation,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<ToolOutcome, PortError>>;
}

/// Successful admin Gateway dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminSuccess {
    /// Gateway response payload.
    pub payload: Value,
    /// Optional response metadata.
    pub meta: Option<Value>,
}

/// Gateway-shaped admin dispatch error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminFailure {
    /// Stable Gateway error code.
    pub code: String,
    /// Safe message.
    pub message: String,
    /// Optional details.
    pub details: Option<Value>,
    /// Optional retryability.
    pub retryable: Option<bool>,
    /// Optional retry delay.
    pub retry_after_ms: Option<u64>,
}

/// Dispatches the allowlisted admin Gateway methods.
pub trait AdminPort: Send + Sync {
    /// Dispatches one already-authorized method.
    fn dispatch(
        &self,
        method: String,
        params: Option<Value>,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<AdminSuccess, AdminFailure>>;
}

/// Authenticated watch-node identity returned by the pairing adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchIdentity {
    /// Stable node/device identifier.
    pub node_id: String,
    /// Rotated or newly issued device token.
    pub device_token: Option<String>,
}

/// Verifies watch pairing credentials and signed device proof.
pub trait WatchAuthPort: Send + Sync {
    /// Authenticates one canonical watch connect request.
    fn authenticate(
        &self,
        connect: ConnectParams,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WatchIdentity, PortError>>;
}

/// Accepts invoke results returned by a watch node.
pub trait WatchResultPort: Send + Sync {
    /// Handles one result and reports whether it matched pending work.
    fn handle(
        &self,
        node_id: String,
        result: Value,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<bool, PortError>>;
}

/// Result selected by the task-flow webhook runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookOutcome {
    /// HTTP status.
    pub status: u16,
    /// Optional stable outcome code.
    pub code: Option<String>,
    /// Optional safe error.
    pub error: Option<String>,
    /// Runtime result.
    pub result: Value,
}

/// Executes an authenticated configured webhook route.
pub trait WebhookPort: Send + Sync {
    /// Executes one route action.
    fn invoke(
        &self,
        route_id: String,
        action: Value,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WebhookOutcome, PortError>>;
}

/// Persists security decisions before protected dispatch.
pub trait AuditPort: Send + Sync {
    /// Durably persists one redacted event.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] when the event could not be made durable. The
    /// authorization decision that produced the event is then *not* taken: an
    /// OpenAI-style route answers `503` with
    /// `{"error":{"message":"internal error","type":"api_error"}}`, and
    /// `POST /api/v1/admin/rpc` answers `503` with
    /// `{"ok":false,"error":{"type":"unavailable",...}}`.
    fn persist(&self, event: &AuditEvent) -> Result<(), PortError>;
}

/// Runtime adapters required by the HTTP crate.
#[derive(Clone)]
pub struct ApiServices {
    /// Provider adapter.
    pub provider: Arc<dyn ProviderPort>,
    /// Readiness adapter.
    pub readiness: Arc<dyn ReadinessPort>,
    /// Gateway tool adapter.
    pub tools: Arc<dyn ToolPort>,
    /// Admin Gateway adapter.
    pub admin: Arc<dyn AdminPort>,
    /// Watch authentication adapter.
    pub watch_auth: Arc<dyn WatchAuthPort>,
    /// Watch result adapter.
    pub watch_results: Arc<dyn WatchResultPort>,
    /// Webhook adapter.
    pub webhooks: Arc<dyn WebhookPort>,
    /// Durable security audit adapter.
    pub audit: Arc<dyn AuditPort>,
}

/// Stable adapter failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortErrorKind {
    /// Invalid caller input.
    InvalidRequest,
    /// Requested resource does not exist.
    NotFound,
    /// Provider or dependency is unavailable.
    Unavailable,
    /// Operation exceeded its deadline.
    Timeout,
    /// The mutation committed, but its durability could not be confirmed.
    CommittedButNotDurable,
    /// Internal adapter failure.
    Internal,
}

/// Error returned by an application port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortError {
    /// Stable classification.
    pub kind: PortErrorKind,
    /// Safe client-facing message.
    pub message: String,
}

impl PortError {
    /// Creates a safe port error.
    #[must_use]
    pub fn new(kind: PortErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl Display for PortError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for PortError {}

/// Shape accepted by `/v1/embeddings`.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct EmbeddingsBody {
    pub(crate) model: Option<Value>,
    pub(crate) input: Option<Value>,
    pub(crate) encoding_format: Option<Value>,
    pub(crate) dimensions: Option<Value>,
}

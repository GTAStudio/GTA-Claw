//! Shared golden-fixture harness for the OpenAI-compatible HTTP surface.
//!
//! Five test binaries (`openai_chat`, `openai_responses`, `openai_models`,
//! `openai_embeddings`, `openai_tools_invoke`) include this module, so any single
//! binary uses only a subset of it.
#![expect(
    dead_code,
    reason = "shared fixture harness compiled into five test binaries; each one exercises only the subset of the helpers its own feature needs"
)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use claw_http_api::{
    AdminFailure, AdminPort, AdminSuccess, ApiConfig, ApiServices, AuditPort, BearerAuthenticator,
    BearerCredential, EmbeddingRequest, GenerationEvent, GenerationOutput, GenerationRequest,
    HttpApi, Model, PortError, PortErrorKind, PortFuture, ProviderPort, ReadinessPort,
    ReadinessSnapshot, ToolCall, ToolDefinition, ToolInvocation, ToolOutcome, ToolPort, Usage,
    WatchAuthPort, WatchIdentity, WatchResultPort, WebhookOutcome, WebhookPort,
};
use claw_protocol::gateway::ConnectParams;
use claw_security::audit::AuditEvent;
use claw_security::authorization::{Role, Scope, ScopeSet};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Feature ledger rows this fixture suite is allowed to carry evidence for.
pub(crate) const COVERED_FEATURES: [&str; 5] = [
    "interop.openai.chat-completions",
    "interop.openai.openresponses",
    "interop.openai.models",
    "interop.openai.embeddings",
    "interop.openai.tools-invoke",
];

/// Environment variable that rewrites the `response` block of every fixture it runs.
///
/// Unset — which is how CI runs — the golden is a pure assertion.
const UPDATE_VARIABLE: &str = "UPDATE_OPENAI_GOLDENS";

/// Content type the crate emits for buffered JSON responses.
pub(crate) const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

/// Content type the crate emits for server-sent event streams.
pub(crate) const SSE_CONTENT_TYPE: &str = "text/event-stream; charset=utf-8";

/// Response headers a golden pins. Every other header is deliberately ignored so
/// that unrelated middleware cannot churn every fixture in the suite.
const PINNED_HEADERS: [&str; 3] = ["allow", "cache-control", "content-type"];

/// Identifier prefixes minted by `ApiState::id`.
const IDENTIFIER_PREFIXES: [&str; 5] = ["call", "chatcmpl", "msg", "resp", "session"];

/// Lower bound below which a `created` field is a literal rather than a clock read.
const EARLIEST_PLAUSIBLE_UNIX_SECOND: u64 = 1_600_000_000;

// ---------------------------------------------------------------------------
// Fixture schema
// ---------------------------------------------------------------------------

/// One pinned request/response exchange.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fixture {
    /// Ledger row this exchange is evidence for.
    pub(crate) feature_id: String,
    /// Human-readable statement of what the exchange pins.
    pub(crate) description: String,
    /// Scripted runtime behaviour behind the HTTP surface.
    #[serde(default)]
    pub(crate) runtime: RuntimeScript,
    /// Request the harness sends verbatim.
    pub(crate) request: RequestSpec,
    /// Pinned response. Absent only while regenerating goldens.
    #[serde(default)]
    pub(crate) response: Option<Value>,
}

/// Scripted behaviour of every runtime port behind the HTTP adapter.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RuntimeScript {
    /// Agent identifiers the gateway is configured with.
    pub(crate) agents: Option<Vec<String>>,
    /// Result of `ProviderPort::models`.
    pub(crate) models: Option<ModelsScript>,
    /// Result of `ProviderPort::generate`.
    pub(crate) generate: Option<GenerateScript>,
    /// Result of `ProviderPort::stream`.
    pub(crate) stream: Option<StreamScript>,
    /// Result of `ProviderPort::embed`.
    pub(crate) embed: Option<EmbedScript>,
    /// Result of `ToolPort::invoke`.
    pub(crate) tool: Option<ToolScript>,
}

/// Scripted `ProviderPort::models` outcome.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ModelsScript {
    /// Provider reports these identifiers.
    Ids {
        /// Identifiers the provider knows about.
        ids: Vec<String>,
    },
    /// Provider fails.
    Error {
        /// Failure classification and message.
        error: ErrorSpec,
    },
}

/// Scripted `ProviderPort::generate` outcome.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum GenerateScript {
    /// Provider completes.
    Output {
        /// Assistant text.
        #[serde(default)]
        text: String,
        /// Pending client tool calls.
        #[serde(default)]
        tool_calls: Vec<ToolCallSpec>,
        /// Usage accounting.
        #[serde(default)]
        usage: UsageSpec,
    },
    /// Provider fails.
    Error {
        /// Failure classification and message.
        error: ErrorSpec,
    },
}

/// Scripted `ProviderPort::stream` outcome.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum StreamScript {
    /// Provider emits every event and then reports usage.
    Events {
        /// Ordered provider events.
        #[serde(default)]
        events: Vec<StreamEventSpec>,
        /// Final usage accounting.
        #[serde(default)]
        usage: UsageSpec,
    },
    /// Provider emits a prefix of events and then fails.
    Error {
        /// Events emitted before the failure.
        #[serde(default)]
        events: Vec<StreamEventSpec>,
        /// Failure classification and message.
        error: ErrorSpec,
    },
}

/// One scripted streaming provider event.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum StreamEventSpec {
    /// Assistant text delta.
    Text(String),
    /// Completed client tool call.
    ToolCall(ToolCallSpec),
}

/// Scripted `ProviderPort::embed` outcome.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum EmbedScript {
    /// Provider returns these exact vectors.
    Vectors {
        /// One vector per input.
        vectors: Vec<Vec<f32>>,
    },
    /// Provider returns one vector per input honouring the requested dimensions.
    Dimensioned {
        /// Dimensions used when the request omits them.
        #[serde(default = "default_dimensions")]
        fallback: usize,
    },
    /// Provider fails.
    Error {
        /// Failure classification and message.
        error: ErrorSpec,
    },
}

/// Dimensions the scripted embedding provider uses when the request omits them.
const fn default_dimensions() -> usize {
    3
}

/// Scripted `ToolPort::invoke` outcome.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ToolScript {
    /// Tool succeeds and echoes the arguments it received.
    Echo,
    /// Tool policy selects this exact outcome.
    Outcome {
        /// HTTP status selected by tool policy.
        status: u16,
        /// Success flag.
        ok: bool,
        /// Success result.
        #[serde(default)]
        result: Option<Value>,
        /// Stable error type.
        #[serde(default)]
        error_type: Option<String>,
        /// Safe error message.
        #[serde(default)]
        error_message: Option<String>,
        /// Whether approval is required.
        #[serde(default)]
        requires_approval: Option<bool>,
    },
    /// The tool port itself fails.
    Error {
        /// Failure classification and message.
        error: ErrorSpec,
    },
}

/// One scripted port failure.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ErrorSpec {
    /// Stable adapter failure classification.
    kind: ErrorKindSpec,
    /// Safe client-facing message.
    message: String,
}

impl ErrorSpec {
    /// Converts the pinned specification into a runtime port error.
    fn port_error(&self) -> PortError {
        PortError::new(self.kind.into_kind(), self.message.clone())
    }
}

/// Serializable mirror of `PortErrorKind`.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ErrorKindSpec {
    /// Invalid caller input.
    InvalidRequest,
    /// Requested resource does not exist.
    NotFound,
    /// Provider or dependency is unavailable.
    Unavailable,
    /// Operation exceeded its deadline.
    Timeout,
    /// Internal adapter failure.
    Internal,
}

impl ErrorKindSpec {
    /// Maps the pinned classification onto the runtime enum.
    const fn into_kind(self) -> PortErrorKind {
        match self {
            Self::InvalidRequest => PortErrorKind::InvalidRequest,
            Self::NotFound => PortErrorKind::NotFound,
            Self::Unavailable => PortErrorKind::Unavailable,
            Self::Timeout => PortErrorKind::Timeout,
            Self::Internal => PortErrorKind::Internal,
        }
    }
}

/// One scripted pending tool call.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolCallSpec {
    /// Provider call identifier.
    id: String,
    /// Function name.
    name: String,
    /// Serialized JSON arguments.
    arguments: String,
}

impl ToolCallSpec {
    /// Converts the pinned specification into a runtime tool call.
    fn tool_call(&self) -> ToolCall {
        ToolCall {
            id: self.id.clone(),
            name: self.name.clone(),
            arguments: self.arguments.clone(),
        }
    }
}

/// Usage accounting a scripted provider reports.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "the field names are the fixture JSON keys, and `deny_unknown_fields` makes renaming them a breaking change to every golden fixture"
)]
pub(crate) struct UsageSpec {
    /// Input token count.
    input_tokens: u64,
    /// Output token count.
    output_tokens: u64,
    /// Total token count.
    total_tokens: u64,
}

impl Default for UsageSpec {
    fn default() -> Self {
        Self {
            input_tokens: 3,
            output_tokens: 2,
            total_tokens: 5,
        }
    }
}

impl UsageSpec {
    /// Converts the pinned specification into runtime usage.
    const fn usage(self) -> Usage {
        Usage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            total_tokens: self.total_tokens,
        }
    }
}

/// One pinned HTTP request.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestSpec {
    /// HTTP method.
    pub(crate) method: String,
    /// Request target.
    pub(crate) path: String,
    /// Bearer token, if the request is authenticated.
    #[serde(default)]
    pub(crate) token: Option<String>,
    /// Extra request headers.
    #[serde(default)]
    pub(crate) headers: Vec<(String, String)>,
    /// JSON request body.
    #[serde(default)]
    pub(crate) body: Option<Value>,
    /// Verbatim request body, for malformed-payload contracts.
    #[serde(default)]
    pub(crate) raw_body: Option<String>,
}

impl RequestSpec {
    /// Builds a JSON `POST` request specification.
    pub(crate) fn post(path: &str, token: &str, body: Value) -> Self {
        Self {
            method: "POST".to_owned(),
            path: path.to_owned(),
            token: Some(token.to_owned()),
            headers: Vec::new(),
            body: Some(body),
            raw_body: None,
        }
    }

    /// Builds a `GET` request specification.
    pub(crate) fn get(path: &str, token: &str) -> Self {
        Self {
            method: "GET".to_owned(),
            path: path.to_owned(),
            token: Some(token.to_owned()),
            headers: Vec::new(),
            body: None,
            raw_body: None,
        }
    }

    /// Serializes the request body.
    fn body_bytes(&self) -> Vec<u8> {
        assert!(
            !(self.body.is_some() && self.raw_body.is_some()),
            "a fixture request declares both body and raw_body"
        );
        match (&self.body, &self.raw_body) {
            (Some(body), _) => serde_json::to_vec(body).expect("fixture body serializes"),
            (None, Some(raw)) => raw.as_bytes().to_vec(),
            (None, None) => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Scripted runtime
// ---------------------------------------------------------------------------

/// Deterministic scripted implementation of every runtime port.
///
/// Nothing here reaches the network: every provider, tool, admin, watch and
/// webhook result is decided by the fixture.
pub(crate) struct ScriptedRuntime {
    script: RuntimeScript,
    generation_requests: Mutex<Vec<GenerationRequest>>,
    embedding_requests: Mutex<Vec<EmbeddingRequest>>,
    tool_invocations: Mutex<Vec<ToolInvocation>>,
    audits: Mutex<Vec<AuditEvent>>,
    stream_cancelled: AtomicBool,
}

impl ScriptedRuntime {
    /// Creates a runtime driven by one fixture script.
    pub(crate) fn new(script: RuntimeScript) -> Arc<Self> {
        Arc::new(Self {
            script,
            generation_requests: Mutex::new(Vec::new()),
            embedding_requests: Mutex::new(Vec::new()),
            tool_invocations: Mutex::new(Vec::new()),
            audits: Mutex::new(Vec::new()),
            stream_cancelled: AtomicBool::new(false),
        })
    }

    /// Builds the complete service bundle backed by this runtime.
    pub(crate) fn services(self: &Arc<Self>) -> ApiServices {
        ApiServices {
            provider: self.clone(),
            readiness: self.clone(),
            tools: self.clone(),
            admin: self.clone(),
            watch_auth: self.clone(),
            watch_results: self.clone(),
            webhooks: self.clone(),
            audit: self.clone(),
        }
    }

    /// Returns every generation request the provider port observed.
    pub(crate) fn generation_requests(&self) -> Vec<GenerationRequest> {
        self.generation_requests
            .lock()
            .expect("generation request lock")
            .clone()
    }

    /// Returns the single generation request the provider port observed.
    pub(crate) fn generation_request(&self) -> GenerationRequest {
        let mut requests = self.generation_requests();
        assert_eq!(
            requests.len(),
            1,
            "expected exactly one generation request, observed {}",
            requests.len()
        );
        requests.remove(0)
    }

    /// Returns every embedding request the provider port observed.
    pub(crate) fn embedding_requests(&self) -> Vec<EmbeddingRequest> {
        self.embedding_requests
            .lock()
            .expect("embedding request lock")
            .clone()
    }

    /// Returns the single embedding request the provider port observed.
    pub(crate) fn embedding_request(&self) -> EmbeddingRequest {
        let mut requests = self.embedding_requests();
        assert_eq!(
            requests.len(),
            1,
            "expected exactly one embedding request, observed {}",
            requests.len()
        );
        requests.remove(0)
    }

    /// Returns every tool invocation the tool port observed.
    pub(crate) fn tool_invocations(&self) -> Vec<ToolInvocation> {
        self.tool_invocations
            .lock()
            .expect("tool invocation lock")
            .clone()
    }

    /// Returns the single tool invocation the tool port observed.
    pub(crate) fn tool_invocation(&self) -> ToolInvocation {
        let mut invocations = self.tool_invocations();
        assert_eq!(
            invocations.len(),
            1,
            "expected exactly one tool invocation, observed {}",
            invocations.len()
        );
        invocations.remove(0)
    }

    /// Returns persisted authorization audit events.
    pub(crate) fn audit_events(&self) -> Vec<AuditEvent> {
        self.audits.lock().expect("audit lock").clone()
    }

    /// Reports whether a streaming generation observed cancellation.
    pub(crate) fn stream_was_cancelled(&self) -> bool {
        self.stream_cancelled.load(Ordering::Acquire)
    }
}

impl ReadinessPort for ScriptedRuntime {
    fn snapshot(&self) -> Result<ReadinessSnapshot, PortError> {
        Ok(ReadinessSnapshot {
            ready: true,
            failing: Vec::new(),
            uptime_ms: 0,
        })
    }
}

impl ProviderPort for ScriptedRuntime {
    fn models(&self) -> PortFuture<'_, Result<Vec<Model>, PortError>> {
        Box::pin(async move {
            match self.script.models.as_ref() {
                None => Ok(vec![Model {
                    id: "openclaw".to_owned(),
                }]),
                Some(ModelsScript::Ids { ids }) => {
                    Ok(ids.iter().map(|id| Model { id: id.clone() }).collect())
                }
                Some(ModelsScript::Error { error }) => Err(error.port_error()),
            }
        })
    }

    fn generate(
        &self,
        request: GenerationRequest,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<GenerationOutput, PortError>> {
        Box::pin(async move {
            self.generation_requests
                .lock()
                .expect("generation request lock")
                .push(request);
            match self.script.generate.as_ref() {
                None => Ok(GenerationOutput {
                    text: "deterministic response".to_owned(),
                    tool_calls: Vec::new(),
                    usage: UsageSpec::default().usage(),
                }),
                Some(GenerateScript::Output {
                    text,
                    tool_calls,
                    usage,
                }) => Ok(GenerationOutput {
                    text: text.clone(),
                    tool_calls: tool_calls.iter().map(ToolCallSpec::tool_call).collect(),
                    usage: usage.usage(),
                }),
                Some(GenerateScript::Error { error }) => Err(error.port_error()),
            }
        })
    }

    fn stream(
        &self,
        request: GenerationRequest,
        events: mpsc::Sender<GenerationEvent>,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<Usage, PortError>> {
        Box::pin(async move {
            self.generation_requests
                .lock()
                .expect("generation request lock")
                .push(request);
            let default = vec![
                StreamEventSpec::Text("deterministic ".to_owned()),
                StreamEventSpec::Text("response".to_owned()),
            ];
            let (scripted, outcome) = match self.script.stream.as_ref() {
                None => (&default, Ok(UsageSpec::default().usage())),
                Some(StreamScript::Events {
                    events: scripted,
                    usage,
                }) => (scripted, Ok(usage.usage())),
                Some(StreamScript::Error {
                    events: scripted,
                    error,
                }) => (scripted, Err(error.port_error())),
            };
            for event in scripted {
                let event = match event {
                    StreamEventSpec::Text(text) => GenerationEvent::Text(text.clone()),
                    StreamEventSpec::ToolCall(call) => GenerationEvent::ToolCall(call.tool_call()),
                };
                if events.send(event).await.is_err() {
                    self.stream_cancelled.store(true, Ordering::Release);
                    return Err(PortError::new(
                        PortErrorKind::Unavailable,
                        "stream receiver disconnected",
                    ));
                }
            }
            outcome
        })
    }

    fn embed(
        &self,
        request: EmbeddingRequest,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<Vec<Vec<f32>>, PortError>> {
        Box::pin(async move {
            self.embedding_requests
                .lock()
                .expect("embedding request lock")
                .push(request.clone());
            match self.script.embed.as_ref() {
                None => Ok(dimensioned_vectors(&request, default_dimensions())),
                Some(EmbedScript::Vectors { vectors }) => Ok(vectors.clone()),
                Some(EmbedScript::Dimensioned { fallback }) => {
                    Ok(dimensioned_vectors(&request, *fallback))
                }
                Some(EmbedScript::Error { error }) => Err(error.port_error()),
            }
        })
    }
}

/// Produces one vector per input, each of exactly the requested width.
///
/// Every component is a multiple of a quarter so that the JSON encoding is exact
/// on both `f32` and `f64` and a golden can pin it character for character.
fn dimensioned_vectors(request: &EmbeddingRequest, fallback: usize) -> Vec<Vec<f32>> {
    let width = request.dimensions.unwrap_or(fallback);
    request
        .input
        .iter()
        .enumerate()
        .map(|(index, _)| {
            (0..width)
                .map(|dimension| {
                    let component = u16::try_from(index * 8 + dimension)
                        .expect("fixture embedding widths stay inside `u16`");
                    f32::from(component) / 4.0
                })
                .collect()
        })
        .collect()
}

impl ToolPort for ScriptedRuntime {
    fn list(&self) -> PortFuture<'_, Result<Vec<ToolDefinition>, PortError>> {
        Box::pin(async {
            Ok(vec![ToolDefinition {
                name: "echo".to_owned(),
                description: Some("Returns its arguments".to_owned()),
                input_schema: json!({"type":"object"}),
            }])
        })
    }

    fn invoke(
        &self,
        invocation: ToolInvocation,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<ToolOutcome, PortError>> {
        Box::pin(async move {
            self.tool_invocations
                .lock()
                .expect("tool invocation lock")
                .push(invocation.clone());
            match self.script.tool.as_ref() {
                None | Some(ToolScript::Echo) => Ok(ToolOutcome {
                    status: 200,
                    ok: true,
                    result: Some(invocation.arguments),
                    error_type: None,
                    error_message: None,
                    requires_approval: None,
                }),
                Some(ToolScript::Outcome {
                    status,
                    ok,
                    result,
                    error_type,
                    error_message,
                    requires_approval,
                }) => Ok(ToolOutcome {
                    status: *status,
                    ok: *ok,
                    result: result.clone(),
                    error_type: error_type.clone(),
                    error_message: error_message.clone(),
                    requires_approval: *requires_approval,
                }),
                Some(ToolScript::Error { error }) => Err(error.port_error()),
            }
        })
    }
}

impl AdminPort for ScriptedRuntime {
    fn dispatch(
        &self,
        _method: String,
        _params: Option<Value>,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<AdminSuccess, AdminFailure>> {
        Box::pin(async {
            Err(AdminFailure {
                code: "NOT_SUPPORTED".to_owned(),
                message: "the OpenAI fixture runtime dispatches no admin methods".to_owned(),
                details: None,
                retryable: Some(false),
                retry_after_ms: None,
            })
        })
    }
}

impl WatchAuthPort for ScriptedRuntime {
    fn authenticate(
        &self,
        _connect: ConnectParams,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WatchIdentity, PortError>> {
        Box::pin(async {
            Err(PortError::new(
                PortErrorKind::InvalidRequest,
                "the OpenAI fixture runtime pairs no watch nodes",
            ))
        })
    }
}

impl WatchResultPort for ScriptedRuntime {
    fn handle(
        &self,
        _node_id: String,
        _result: Value,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<bool, PortError>> {
        Box::pin(async { Ok(false) })
    }
}

impl WebhookPort for ScriptedRuntime {
    fn invoke(
        &self,
        _route_id: String,
        _action: Value,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WebhookOutcome, PortError>> {
        Box::pin(async {
            Err(PortError::new(
                PortErrorKind::NotFound,
                "the OpenAI fixture runtime configures no webhook routes",
            ))
        })
    }
}

impl AuditPort for ScriptedRuntime {
    fn persist(&self, event: &AuditEvent) -> Result<(), PortError> {
        self.audits.lock().expect("audit lock").push(event.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Server harness
// ---------------------------------------------------------------------------

/// A running API server bound to an ephemeral loopback port.
pub(crate) struct TestServer {
    address: SocketAddr,
    task: JoinHandle<()>,
    /// Scripted runtime the server is wired to.
    pub(crate) runtime: Arc<ScriptedRuntime>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Builds a bearer credential for an operator principal.
fn operator(token: &str, scopes: impl IntoIterator<Item = Scope>) -> BearerCredential {
    BearerCredential::new(token, Role::Operator, ScopeSet::from_scopes(scopes))
}

/// Builds the pinned authentication and limit configuration.
///
/// The token set is fixed so a fixture can name a principal by token alone:
///
/// | token | role | scopes |
/// | --- | --- | --- |
/// | `operator-token` | operator | `operator.admin` |
/// | `write-token` | operator | `operator.write` |
/// | `read-token` | operator | `operator.read` |
/// | `scopeless-token` | operator | none |
/// | `node-token` | node | `operator.admin` |
fn config(agents: Vec<String>) -> ApiConfig {
    let mut config = ApiConfig::new(BearerAuthenticator::new(vec![
        operator("operator-token", [Scope::OperatorAdmin]),
        operator("write-token", [Scope::OperatorWrite]),
        operator("read-token", [Scope::OperatorRead]),
        operator("scopeless-token", []),
        BearerCredential::new(
            "node-token",
            Role::Node,
            ScopeSet::from_scopes([Scope::OperatorAdmin]),
        ),
    ]));
    config.agents = agents;
    // Long enough that no keep-alive comment can land inside a pinned stream.
    config.limits.heartbeat_interval = Duration::from_mins(10);
    config
}

/// Starts a server driven by the supplied script.
pub(crate) async fn spawn(script: RuntimeScript) -> TestServer {
    let agents = script
        .agents
        .clone()
        .unwrap_or_else(|| vec!["main".to_owned()]);
    let runtime = ScriptedRuntime::new(script);
    let api = HttpApi::new(config(agents), runtime.services());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let address = listener.local_addr().expect("listener address");
    let task = tokio::spawn(async move {
        api.serve(listener).await.expect("serve test API");
    });
    TestServer {
        address,
        task,
        runtime,
    }
}

/// Parses a runtime script from an inline JSON literal.
pub(crate) fn script(value: Value) -> RuntimeScript {
    serde_json::from_value(value).expect("inline runtime script parses")
}

/// One complete HTTP response read off the socket.
pub(crate) struct HttpResponse {
    /// Status code.
    pub(crate) status: u16,
    /// Lowercased response headers.
    pub(crate) headers: BTreeMap<String, String>,
    /// Decoded response body.
    pub(crate) body: Vec<u8>,
}

impl HttpResponse {
    /// Parses the body as JSON.
    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("response body is JSON")
    }

    /// Returns the body as text.
    pub(crate) fn text(&self) -> &str {
        std::str::from_utf8(&self.body).expect("response body is UTF-8")
    }

    /// Returns one header value.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

impl TestServer {
    /// Sends one pinned request and reads the complete response.
    pub(crate) async fn send(&self, request: &RequestSpec) -> HttpResponse {
        let body = request.body_bytes();
        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            request.method,
            request.path,
            self.address,
            body.len()
        );
        if let Some(token) = &request.token {
            head.push_str("Authorization: Bearer ");
            head.push_str(token);
            head.push_str("\r\n");
        }
        let declares_content_type = request
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"));
        if !declares_content_type && !body.is_empty() {
            head.push_str("Content-Type: application/json\r\n");
        }
        for (name, value) in &request.headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");

        let mut stream = TcpStream::connect(self.address)
            .await
            .expect("connect test server");
        stream
            .write_all(head.as_bytes())
            .await
            .expect("write request head");
        stream.write_all(&body).await.expect("write request body");
        let raw = timeout(Duration::from_secs(10), read_complete_response(&mut stream))
            .await
            .expect("response arrived before the harness deadline")
            .expect("read complete response");
        parse_response(&raw)
    }
}

/// Reads until the response is framed completely or the peer closes.
async fn read_complete_response(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        if let Some(length) = complete_response_length(&raw) {
            raw.truncate(length);
            return Ok(raw);
        }
        match stream.read(&mut buffer).await {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before the complete HTTP response",
                ));
            }
            Ok(read) => raw.extend_from_slice(&buffer[..read]),
            Err(error) => return Err(error),
        }
    }
}

/// Returns the total byte length of a completely framed response.
fn complete_response_length(raw: &[u8]) -> Option<usize> {
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let body_start = split + 4;
    let head = std::str::from_utf8(&raw[..split]).ok()?;
    let mut content_length = None;
    let mut chunked = false;
    for (name, value) in head
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim(), value.trim()))
    {
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
        }
    }
    if chunked {
        return complete_chunked_length(&raw[body_start..])
            .and_then(|length| body_start.checked_add(length));
    }
    content_length.and_then(|length| {
        let total = body_start.checked_add(length)?;
        (raw.len() >= total).then_some(total)
    })
}

/// Returns the byte length of a complete chunked body, terminator included.
fn complete_chunked_length(bytes: &[u8]) -> Option<usize> {
    let mut offset = 0_usize;
    loop {
        let size_end = bytes
            .get(offset..)?
            .windows(2)
            .position(|window| window == b"\r\n")?;
        let size_text = std::str::from_utf8(bytes.get(offset..offset + size_end)?).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        offset = offset.checked_add(size_end + 2)?;
        if size == 0 {
            loop {
                let trailer_end = bytes
                    .get(offset..)?
                    .windows(2)
                    .position(|window| window == b"\r\n")?;
                offset = offset.checked_add(trailer_end + 2)?;
                if trailer_end == 0 {
                    return Some(offset);
                }
            }
        }
        let chunk_end = offset.checked_add(size)?;
        if bytes.get(chunk_end..chunk_end + 2)? != b"\r\n" {
            return None;
        }
        offset = chunk_end + 2;
    }
}

/// Splits a raw response into status, headers and a decoded body.
fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP header terminator");
    let head = std::str::from_utf8(&raw[..split]).expect("HTTP head is UTF-8");
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    let headers = lines
        .map(|line| {
            let (name, value) = line.split_once(':').expect("header delimiter");
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect::<BTreeMap<_, _>>();
    let raw_body = &raw[split + 4..];
    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        decode_chunked(raw_body)
    } else {
        raw_body.to_vec()
    };
    HttpResponse {
        status,
        headers,
        body,
    }
}

/// Decodes a chunked transfer body.
fn decode_chunked(mut bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    loop {
        let end = bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size terminator");
        let size_text = std::str::from_utf8(&bytes[..end]).expect("chunk size is UTF-8");
        let size = usize::from_str_radix(
            size_text.split(';').next().expect("chunk size component"),
            16,
        )
        .expect("hexadecimal chunk size");
        bytes = &bytes[end + 2..];
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&bytes[..size]);
        bytes = &bytes[size + 2..];
    }
    decoded
}

// ---------------------------------------------------------------------------
// Observation and normalisation
// ---------------------------------------------------------------------------

/// One decoded server-sent event.
#[derive(Debug)]
pub(crate) struct SseEvent {
    /// `event:` name, absent for unnamed data frames.
    pub(crate) name: Option<String>,
    /// `data:` payload, parsed as JSON where possible.
    pub(crate) data: Value,
}

/// Splits an SSE body into its complete ordered event sequence.
///
/// The frozen terminator `data: [DONE]` is returned as an ordinary event so a
/// golden pins it rather than a test forgetting to assert it.
pub(crate) fn parse_sse(body: &str) -> Vec<SseEvent> {
    body.split("\n\n")
        .filter(|block| !block.is_empty())
        .map(|block| {
            let (name, data) = match block.split_once('\n') {
                Some((first, rest)) if first.starts_with("event: ") => (
                    Some(
                        first
                            .strip_prefix("event: ")
                            .expect("checked event prefix")
                            .to_owned(),
                    ),
                    rest,
                ),
                _ => (None, block),
            };
            let payload = data.strip_prefix("data: ").unwrap_or_else(|| {
                panic!("server-sent event block without a data line: {block:?}")
            });
            let data = serde_json::from_str::<Value>(payload)
                .unwrap_or_else(|_| Value::String(payload.to_owned()));
            SseEvent { name, data }
        })
        .collect()
}

/// Renders a response as the comparable value a golden pins.
pub(crate) fn observe(response: &HttpResponse) -> Value {
    let mut headers = Map::new();
    for name in PINNED_HEADERS {
        if let Some(value) = response.header(name) {
            headers.insert(name.to_owned(), Value::String(value.to_owned()));
        }
    }
    let content_type = response.header("content-type").unwrap_or_default();
    let mut observed = Map::new();
    observed.insert("status".to_owned(), json!(response.status));
    observed.insert("headers".to_owned(), Value::Object(headers));
    if content_type.starts_with("text/event-stream") {
        let events = parse_sse(response.text())
            .into_iter()
            .map(|event| {
                let mut object = Map::new();
                if let Some(name) = event.name {
                    object.insert("event".to_owned(), Value::String(name));
                }
                object.insert("data".to_owned(), event.data);
                Value::Object(object)
            })
            .collect::<Vec<_>>();
        observed.insert("events".to_owned(), Value::Array(events));
    } else if content_type.starts_with("application/json") {
        observed.insert("body".to_owned(), response.json());
    } else if response.body.is_empty() {
        observed.insert("body".to_owned(), Value::Null);
    } else {
        observed.insert("text".to_owned(), Value::String(response.text().to_owned()));
    }
    let mut observed = Value::Object(observed);
    normalize(&mut observed);
    observed
}

/// Rewrites minted identifiers and clock reads into stable, validated tokens.
///
/// This is deliberately *validating* rather than erasing. An identifier is only
/// replaced once it parses as `<prefix>_<48 lowercase hex digits>` with a prefix
/// the adapter actually mints, and equal identifiers map to equal tokens, so a
/// golden still pins that, for example, every chunk of one stream carries one
/// identifier and that two tool call items carry two different ones.
pub(crate) fn normalize(value: &mut Value) {
    let mut table = Substitutions::default();
    substitute(value, &mut table);
}

/// First-seen ordered substitution table.
#[derive(Default)]
struct Substitutions {
    identifiers: BTreeMap<String, String>,
    counts: BTreeMap<String, usize>,
    timestamps: BTreeMap<u64, String>,
}

impl Substitutions {
    /// Returns the stable token for one minted identifier.
    fn identifier(&mut self, raw: &str, prefix: &str) -> String {
        if let Some(token) = self.identifiers.get(raw) {
            return token.clone();
        }
        let count = self.counts.entry(prefix.to_owned()).or_insert(0);
        *count += 1;
        let token = format!("<id:{prefix}#{count}>");
        self.identifiers.insert(raw.to_owned(), token.clone());
        token
    }

    /// Returns the stable token for one clock read.
    fn timestamp(&mut self, raw: u64) -> String {
        if let Some(token) = self.timestamps.get(&raw) {
            return token.clone();
        }
        let token = format!("<created#{}>", self.timestamps.len() + 1);
        self.timestamps.insert(raw, token.clone());
        token
    }
}

/// Recursively applies the substitution table.
fn substitute(value: &mut Value, table: &mut Substitutions) {
    match value {
        Value::String(text) => {
            if let Some(prefix) = minted_identifier_prefix(text) {
                *text = table.identifier(text, prefix);
            }
        }
        Value::Array(items) => {
            for item in items {
                substitute(item, table);
            }
        }
        Value::Object(entries) => {
            for (key, entry) in entries.iter_mut() {
                if matches!(key.as_str(), "created" | "created_at")
                    && let Some(seconds) = entry.as_u64()
                    && seconds >= EARLIEST_PLAUSIBLE_UNIX_SECOND
                {
                    *entry = Value::String(table.timestamp(seconds));
                    continue;
                }
                substitute(entry, table);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Returns the minting prefix when a string is an adapter-minted identifier.
fn minted_identifier_prefix(text: &str) -> Option<&'static str> {
    let (prefix, suffix) = text.split_once('_')?;
    let known = IDENTIFIER_PREFIXES
        .into_iter()
        .find(|candidate| *candidate == prefix)?;
    (suffix.len() == 48
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(known)
}

// ---------------------------------------------------------------------------
// Fixture execution
// ---------------------------------------------------------------------------

/// One executed fixture.
pub(crate) struct FixtureRun {
    /// Server the exchange ran against, still holding its recorded port traffic.
    pub(crate) server: TestServer,
    /// Raw response as read off the socket.
    pub(crate) response: HttpResponse,
    /// Normalised response, already compared against the golden.
    pub(crate) observed: Value,
}

impl FixtureRun {
    /// Returns the decoded SSE event sequence.
    pub(crate) fn events(&self) -> Vec<SseEvent> {
        parse_sse(self.response.text())
    }
}

/// Resolves one fixture path inside the crate.
fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("openai")
        .join(relative)
}

/// Runs one golden fixture end to end and asserts the pinned response.
pub(crate) async fn run_fixture(feature_id: &str, relative: &str) -> FixtureRun {
    assert!(
        COVERED_FEATURES.contains(&feature_id),
        "{feature_id} is not one of the ledger rows this suite covers"
    );
    let path = fixture_path(relative);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()));
    let fixture: Fixture = serde_json::from_str(&source)
        .unwrap_or_else(|error| panic!("parse fixture {}: {error}", path.display()));
    assert_eq!(
        fixture.feature_id,
        feature_id,
        "fixture {} is filed under {} but was run as evidence for {feature_id}",
        path.display(),
        fixture.feature_id
    );
    assert!(
        !fixture.description.trim().is_empty(),
        "fixture {} states no contract",
        path.display()
    );

    let server = spawn(fixture.runtime.clone()).await;
    let response = server.send(&fixture.request).await;
    let observed = observe(&response);

    let updating = env::var(UPDATE_VARIABLE).is_ok_and(|value| value == "1");
    if updating {
        let mut document: Value = serde_json::from_str(&source).expect("fixture reparses");
        document
            .as_object_mut()
            .expect("fixture is an object")
            .insert("response".to_owned(), observed.clone());
        let mut rendered = serde_json::to_string_pretty(&document).expect("fixture serializes");
        rendered.push('\n');
        fs::write(&path, rendered).expect("rewrite fixture");
    }

    let expected = match fixture.response {
        Some(expected) => expected,
        None if updating => observed.clone(),
        None => panic!(
            "fixture {} pins no response; regenerate it with {UPDATE_VARIABLE}=1 and review the diff",
            path.display()
        ),
    };
    assert_eq!(
        observed,
        expected,
        "fixture {} diverged\n--- observed ---\n{}\n--- pinned ---\n{}",
        path.display(),
        serde_json::to_string_pretty(&observed).expect("observed renders"),
        serde_json::to_string_pretty(&expected).expect("pinned renders")
    );

    FixtureRun {
        server,
        response,
        observed,
    }
}

/// Asserts that a set of error fixtures maps onto distinct, non-collapsed contracts.
///
/// Every acceptance row in this domain requires errors to stay classified, so a
/// suite that let two different failures render identically, or let everything
/// render as an unclassified `500`, would be worthless as evidence.
pub(crate) fn assert_error_contracts_are_distinct(observed: &[(String, Value)]) {
    assert!(
        observed.len() >= 4,
        "an error contract table needs several classes, got {}",
        observed.len()
    );
    let mut seen: BTreeMap<(u64, String, String), String> = BTreeMap::new();
    for (name, value) in observed {
        let status = value["status"].as_u64().expect("observed status");
        let error = &value["body"]["error"];
        let kind = error
            .get("type")
            .and_then(Value::as_str)
            .or_else(|| error.get("code").and_then(Value::as_str))
            .or_else(|| error.as_str())
            .unwrap_or_else(|| panic!("{name} returned no classified error: {value}"))
            .to_owned();
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        assert!(
            !(status == 500 && kind == "api_error"),
            "{name} collapsed into an unclassified 500"
        );
        let previous = seen.insert((status, kind.clone(), message.clone()), name.clone());
        assert!(
            previous.is_none(),
            "{name} is indistinguishable from {}: status {status}, type {kind}, message {message:?}",
            previous.unwrap_or_default()
        );
    }
    let statuses = observed
        .iter()
        .filter_map(|(_, value)| value["status"].as_u64())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        statuses.len() >= 4,
        "an error contract table that produces {} distinct statuses is collapsed",
        statuses.len()
    );
}

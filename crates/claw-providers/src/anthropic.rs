//! Anthropic `POST /v1/messages`.
//!
//! Anthropic's dialect differs from `OpenAI`'s in four ways this module handles
//! explicitly: the system prompt is a top-level field rather than a message,
//! `max_tokens` is mandatory, tool results are carried as blocks inside a user
//! turn, and streaming is a typed event protocol rather than a single chunk
//! shape.

use std::collections::BTreeMap;
use std::collections::VecDeque;

use claw_provider_sdk::error::{ErrorKind, Operation, ProviderError};
use claw_provider_sdk::http::{Body, HttpRequest, Method, TlsPolicy};
use claw_provider_sdk::model::{
    AssistantMessage, CapabilitySet, ChatMessage, CompletionRequest, CompletionResponse,
    ContentPart, FinishReason, ImageSource, ModelDescriptor, ModelId, ProviderId, ResponseFormat,
    ToolArguments, ToolCall, ToolChoice, Usage,
};
use claw_provider_sdk::origin::{BoundApiKey, Origin, OriginApproval};
use claw_provider_sdk::provider::{BoxFuture, Provider, RequestContext};
use claw_provider_sdk::secret::ApiKey;
use claw_provider_sdk::sse::{SseDecoder, SseEvent};
use claw_provider_sdk::stream::{CompletionStream, StreamEvent, ToolCallAssembler};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::openai_compatible::{ChunkStream, EventStream};
use crate::runtime::{ProviderRuntime, ReliabilityConfig};

/// Wire version pinned by this client.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Default endpoint for the public Anthropic API.
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// `max_tokens` sent when the caller does not specify one.
///
/// Anthropic rejects a request without `max_tokens`, and the portable
/// [`CompletionRequest`] treats the field as optional, so a default is
/// unavoidable. It is configurable rather than hard-coded.
pub const DEFAULT_MAX_TOKENS: u32 = 4_096;

/// Capabilities the Anthropic client can drive.
const CAPABILITIES: CapabilitySet = crate::descriptor::ANTHROPIC_CAPABILITIES;

/// Configuration of the Anthropic client.
#[derive(Debug)]
pub struct AnthropicConfig {
    /// Base URL that `/v1/messages` is appended to.
    pub base_url: Url,
    /// Anthropic API key.
    ///
    /// The credential carries the origin it was authorised for.
    /// [`Anthropic::new`] rejects a configuration whose `base_url` is on a
    /// different origin, so pointing this client elsewhere cannot silently
    /// reuse a stored Anthropic key.
    pub api_key: BoundApiKey,
    /// Value of the `anthropic-version` header.
    pub version: String,
    /// `max_tokens` used when the request does not set one.
    pub default_max_tokens: u32,
    /// Extra non-secret headers, used for beta opt-ins.
    pub extra_headers: Vec<(String, String)>,
    /// Reliability policies.
    pub reliability: ReliabilityConfig,
}

impl AnthropicConfig {
    /// Builds the default public-API configuration for `api_key`.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidRequest`] if [`DEFAULT_BASE_URL`] ever stops
    /// parsing, which the accompanying test rules out.
    pub fn new(api_key: ApiKey) -> Result<Self, ProviderError> {
        let base_url: Url = DEFAULT_BASE_URL.parse().map_err(|_| {
            ProviderError::new(
                ErrorKind::InvalidRequest,
                "anthropic",
                Operation::Authorize,
                "the default base URL is not a valid URL",
            )
        })?;
        let api_key = BoundApiKey::for_endpoint(&base_url, api_key).map_err(|error| {
            ProviderError::new(
                ErrorKind::InvalidRequest,
                "anthropic",
                Operation::Authorize,
                format!("the default base URL names no usable origin: {error}"),
            )
        })?;
        Ok(Self {
            base_url,
            api_key,
            version: ANTHROPIC_VERSION.to_owned(),
            default_max_tokens: DEFAULT_MAX_TOKENS,
            extra_headers: Vec::new(),
            reliability: ReliabilityConfig::default(),
        })
    }

    /// Builds a configuration for an operator-enrolled Anthropic-compatible
    /// endpoint.
    ///
    /// This is the deliberate path for a gateway or proxy. The
    /// [`OriginApproval`] must come from a human decision, never from the same
    /// configuration field that supplies `base_url`.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Authentication`] when `base_url` is not on the
    /// enrolled origin.
    pub fn for_enrolled_origin(
        api_key: ApiKey,
        base_url: Url,
        approval: &OriginApproval,
    ) -> Result<Self, ProviderError> {
        let origin = Origin::of(&base_url).map_err(|error| {
            ProviderError::new(
                ErrorKind::Authentication,
                "anthropic",
                Operation::Authorize,
                format!("the endpoint names no usable origin: {error}"),
            )
        })?;
        if approval.origin() != &origin {
            return Err(ProviderError::new(
                ErrorKind::Authentication,
                "anthropic",
                Operation::Authorize,
                format!(
                    "the endpoint {origin} was not the origin enrolled ({})",
                    approval.origin()
                ),
            ));
        }
        Ok(Self {
            base_url,
            api_key: BoundApiKey::new(origin, api_key),
            version: ANTHROPIC_VERSION.to_owned(),
            default_max_tokens: DEFAULT_MAX_TOKENS,
            extra_headers: Vec::new(),
            reliability: ReliabilityConfig::default(),
        })
    }
}

/// A client for the Anthropic messages API.
#[derive(Debug)]
pub struct Anthropic {
    id: ProviderId,
    base_url: Url,
    api_key: BoundApiKey,
    version: String,
    default_max_tokens: u32,
    extra_headers: Vec<(String, String)>,
    runtime: ProviderRuntime,
}

impl Anthropic {
    /// Builds a client.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Authentication`] when the key is empty or is bound
    /// to an origin other than `base_url`'s, and [`ErrorKind::Transport`] when
    /// the TLS stack cannot be initialized.
    pub fn new(config: AnthropicConfig) -> Result<Self, ProviderError> {
        // Credential and destination must agree before the client exists, so a
        // redirected endpoint can never reach the send path with this key.
        let key = config.api_key.for_url(&config.base_url).map_err(|error| {
            ProviderError::new(
                ErrorKind::Authentication,
                "anthropic",
                Operation::Authorize,
                format!(
                    "the configured endpoint is not the one this credential authorises: {error}"
                ),
            )
        })?;
        if key.is_empty() {
            return Err(ProviderError::new(
                ErrorKind::Authentication,
                "anthropic",
                Operation::Authorize,
                "this provider requires an API key",
            ));
        }
        let tls_policy = if config.base_url.scheme() == "http" {
            TlsPolicy::AllowLoopbackPlaintext
        } else {
            TlsPolicy::RequireHttps
        };
        let runtime = ProviderRuntime::new("anthropic", tls_policy, config.reliability)?;
        Ok(Self {
            id: ProviderId::new("anthropic").map_err(|_| {
                ProviderError::new(
                    ErrorKind::InvalidRequest,
                    "anthropic",
                    Operation::Authorize,
                    "the provider identifier is invalid",
                )
            })?,
            base_url: config.base_url,
            api_key: config.api_key,
            version: config.version,
            default_max_tokens: config.default_max_tokens.max(1),
            extra_headers: config.extra_headers,
            runtime,
        })
    }

    /// Builds a client against the public API.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Authentication`] when `api_key` is empty or is
    /// bound to an origin other than [`DEFAULT_BASE_URL`]'s, and
    /// [`ErrorKind::Transport`] when the TLS stack cannot be built.
    pub fn with_api_key(api_key: ApiKey) -> Result<Self, ProviderError> {
        Self::new(AnthropicConfig::new(api_key)?)
    }

    /// Returns the endpoint this client talks to.
    #[must_use]
    pub const fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Returns the `max_tokens` used when a request omits one.
    #[must_use]
    pub const fn default_max_tokens(&self) -> u32 {
        self.default_max_tokens
    }

    /// Replaces the reliability runtime.
    ///
    /// This is the seam tests use to drive retry and circuit policies with a
    /// [`claw_provider_sdk::clock::ManualClock`] instead of real time.
    #[must_use]
    pub fn with_runtime(mut self, runtime: ProviderRuntime) -> Self {
        self.runtime = runtime;
        self
    }

    fn endpoint(&self, path: &str) -> Result<Url, ProviderError> {
        let base = self.base_url.as_str().trim_end_matches('/');
        format!("{base}/{path}").parse().map_err(|_| {
            ProviderError::new(
                ErrorKind::InvalidRequest,
                self.id.as_str(),
                Operation::Transport,
                "the configured base URL cannot be joined with the request path",
            )
        })
    }

    fn request(&self, method: Method, url: Url) -> Result<HttpRequest, ProviderError> {
        let mut request = HttpRequest::new(method, url)
            .header("accept", "application/json")
            .header("anthropic-version", self.version.clone())
            .credential_header("x-api-key", &self.api_key)
            .map_err(|error| {
                ProviderError::new(
                    ErrorKind::Authentication,
                    self.id.as_str(),
                    Operation::Authorize,
                    format!("the credential is not authorised for this endpoint: {error}"),
                )
            })?;
        for (name, value) in &self.extra_headers {
            request = request.header(name.clone(), value.clone());
        }
        Ok(request)
    }
}

impl Provider for Anthropic {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> CapabilitySet {
        CAPABILITIES
    }

    fn complete<'a>(
        &'a self,
        request: &'a CompletionRequest,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<CompletionResponse, ProviderError>> {
        Box::pin(async move {
            let url = self.endpoint("v1/messages")?;
            let body = encode_messages(request, self.default_max_tokens, false)?;
            let response = self
                .runtime
                .execute(Operation::Complete, context.cancel(), || {
                    Ok(self
                        .request(Method::Post, url.clone())?
                        .body(Body::Json(body.clone())))
                })
                .await?;
            decode_message(self.id.as_str(), response.body())
        })
    }

    fn stream<'a>(
        &'a self,
        request: &'a CompletionRequest,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<CompletionStream, ProviderError>> {
        Box::pin(async move {
            let url = self.endpoint("v1/messages")?;
            let body = encode_messages(request, self.default_max_tokens, true)?;
            let cancel = context.cancel().clone();
            let stream = self
                .runtime
                .execute_streaming(Operation::StreamCompletion, &cancel, || {
                    Ok(self
                        .request(Method::Post, url.clone())?
                        .replace_header("accept", "text/event-stream")
                        .body(Body::Json(body.clone())))
                })
                .await?;
            Ok(CompletionStream::new(
                self.id.as_str(),
                cancel,
                event_stream(self.id.as_str().to_owned(), stream.into_chunks()),
            ))
        })
    }

    fn list_models<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<Vec<ModelDescriptor>, ProviderError>> {
        Box::pin(async move {
            let url = self.endpoint("v1/models")?;
            let response = self
                .runtime
                .execute(Operation::ListModels, context.cancel(), || {
                    self.request(Method::Get, url.clone())
                })
                .await?;
            decode_models(self.id.as_str(), response.body())
        })
    }
}

// ---------------------------------------------------------------------------
// Request encoding
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct WireRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<WireMessage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    stop_sequences: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<WireTool<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<WireToolChoice<'a>>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
}

#[derive(Debug, Serialize)]
struct WireTool<'a> {
    name: &'a str,
    description: &'a str,
    input_schema: &'a serde_json::Map<String, Value>,
}

#[derive(Debug, Serialize)]
struct WireToolChoice<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disable_parallel_tool_use: Option<bool>,
}

#[derive(Debug, Serialize)]
struct WireMessage<'a> {
    role: &'static str,
    content: Vec<WireBlock<'a>>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum WireBlock<'a> {
    #[serde(rename = "text")]
    Text {
        /// Visible text.
        text: &'a str,
    },
    #[serde(rename = "image")]
    Image {
        /// Where the bytes live.
        source: WireImageSource<'a>,
    },
    #[serde(rename = "tool_use")]
    ToolUse {
        /// Provider-assigned call identifier.
        id: &'a str,
        /// Tool name.
        name: &'a str,
        /// Parsed argument object.
        input: Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        /// Identifier of the call being answered.
        tool_use_id: &'a str,
        /// Tool output.
        content: &'a str,
        /// Whether the tool failed.
        is_error: bool,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum WireImageSource<'a> {
    #[serde(rename = "base64")]
    Base64 {
        /// IANA media type of the bytes.
        media_type: &'static str,
        /// Standard base64 payload.
        data: &'a str,
    },
    #[serde(rename = "url")]
    Url {
        /// Absolute URL Anthropic will fetch.
        url: String,
    },
}

fn encode_blocks<'a>(parts: &'a [ContentPart], blocks: &mut Vec<WireBlock<'a>>) {
    for part in parts {
        match part {
            ContentPart::Text(text) => blocks.push(WireBlock::Text { text }),
            ContentPart::Image(image) => blocks.push(WireBlock::Image {
                source: match &image.source {
                    ImageSource::Base64(data) => WireImageSource::Base64 {
                        media_type: image.media_type.as_str(),
                        data,
                    },
                    ImageSource::Url(url) => WireImageSource::Url {
                        url: url.to_string(),
                    },
                },
            }),
        }
    }
}

/// Encodes a completion request as an Anthropic `messages` document.
///
/// System turns are hoisted into the top-level `system` field and consecutive
/// tool results are merged into a single user turn, as the API requires.
///
/// # Errors
///
/// Returns [`ErrorKind::InvalidRequest`] when the request is invalid, when it
/// asks for a JSON response format (Anthropic has no equivalent switch), or when
/// serialization fails.
pub fn encode_messages(
    request: &CompletionRequest,
    default_max_tokens: u32,
    stream: bool,
) -> Result<String, ProviderError> {
    request.validate().map_err(|error| {
        ProviderError::new(
            ErrorKind::InvalidRequest,
            "anthropic",
            Operation::Complete,
            error.to_string(),
        )
    })?;
    if request.response_format != ResponseFormat::Text {
        return Err(ProviderError::new(
            ErrorKind::Unsupported,
            "anthropic",
            Operation::Complete,
            "Anthropic has no response-format switch; use a tool to constrain output",
        ));
    }

    let mut system = String::new();
    let mut messages: Vec<WireMessage<'_>> = Vec::new();
    for message in &request.messages {
        match message {
            ChatMessage::System(text) => {
                if !system.is_empty() {
                    system.push_str("\n\n");
                }
                system.push_str(text);
            }
            ChatMessage::User(parts) => {
                let mut blocks = Vec::new();
                encode_blocks(parts, &mut blocks);
                messages.push(WireMessage {
                    role: "user",
                    content: blocks,
                });
            }
            ChatMessage::Assistant(assistant) => {
                let mut blocks = Vec::new();
                encode_blocks(&assistant.content, &mut blocks);
                for call in &assistant.tool_calls {
                    let input: Value =
                        serde_json::from_str(call.arguments.as_str()).map_err(|error| {
                            ProviderError::new(
                                ErrorKind::InvalidRequest,
                                "anthropic",
                                Operation::Complete,
                                format!("a replayed tool call carried invalid arguments: {error}"),
                            )
                        })?;
                    blocks.push(WireBlock::ToolUse {
                        id: &call.id,
                        name: &call.name,
                        input,
                    });
                }
                messages.push(WireMessage {
                    role: "assistant",
                    content: blocks,
                });
            }
            ChatMessage::ToolResult(result) => {
                let block = WireBlock::ToolResult {
                    tool_use_id: &result.tool_call_id,
                    content: &result.content,
                    is_error: result.is_error,
                };
                match messages.last_mut() {
                    Some(last)
                        if last.role == "user"
                            && last
                                .content
                                .iter()
                                .all(|block| matches!(block, WireBlock::ToolResult { .. })) =>
                    {
                        last.content.push(block);
                    }
                    _ => messages.push(WireMessage {
                        role: "user",
                        content: vec![block],
                    }),
                }
            }
        }
    }

    let tools: Vec<WireTool<'_>> = request
        .tools
        .iter()
        .map(|tool| WireTool {
            name: &tool.name,
            description: &tool.description,
            input_schema: tool.parameters.as_map(),
        })
        .collect();
    let disable_parallel = request.parallel_tool_calls.map(|allowed| !allowed);
    let tool_choice = if tools.is_empty() {
        None
    } else {
        Some(match &request.tool_choice {
            ToolChoice::Auto => WireToolChoice {
                kind: "auto",
                name: None,
                disable_parallel_tool_use: disable_parallel,
            },
            ToolChoice::None => WireToolChoice {
                kind: "none",
                name: None,
                disable_parallel_tool_use: None,
            },
            ToolChoice::Required => WireToolChoice {
                kind: "any",
                name: None,
                disable_parallel_tool_use: disable_parallel,
            },
            ToolChoice::Function(name) => WireToolChoice {
                kind: "tool",
                name: Some(name),
                disable_parallel_tool_use: disable_parallel,
            },
        })
    };

    let wire = WireRequest {
        model: request.model.as_str(),
        max_tokens: request
            .max_output_tokens
            .unwrap_or(default_max_tokens)
            .max(1),
        messages,
        system: if system.is_empty() {
            None
        } else {
            Some(system)
        },
        temperature: request.temperature(),
        top_p: request.top_p(),
        stop_sequences: request.stop_sequences.iter().map(String::as_str).collect(),
        tools,
        tool_choice,
        stream,
    };
    serde_json::to_string(&wire).map_err(|error| {
        ProviderError::new(
            ErrorKind::InvalidRequest,
            "anthropic",
            Operation::Complete,
            error.to_string(),
        )
    })
}

// ---------------------------------------------------------------------------
// Response decoding
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[expect(
    clippy::struct_field_names,
    reason = "these are Anthropic's wire field names; renaming them to drop the \
              shared `_tokens` suffix would need `#[serde(rename)]` on every \
              field and put the real name one indirection away from the type"
)]
struct WireUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
}

impl From<WireUsage> for Usage {
    fn from(usage: WireUsage) -> Self {
        Self {
            input_tokens: usage
                .input_tokens
                .saturating_add(usage.cache_creation_input_tokens),
            output_tokens: usage.output_tokens,
            cached_input_tokens: usage.cache_read_input_tokens,
            reasoning_tokens: 0,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WireResponseBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "thinking")]
    Thinking { thinking: String },
    #[serde(rename = "redacted_thinking")]
    RedactedThinking {},
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
}

#[derive(Debug, Deserialize)]
struct WireMessageResponse {
    #[serde(default)]
    id: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    content: Vec<WireResponseBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    usage: WireUsage,
}

fn protocol_error(provider: &str, operation: Operation, detail: &str) -> ProviderError {
    ProviderError::new(ErrorKind::Protocol, provider, operation, detail)
}

/// Maps an Anthropic `stop_reason` onto the portable enumeration.
#[must_use]
pub fn stop_reason(raw: &str) -> FinishReason {
    match raw {
        "end_turn" | "stop_sequence" => FinishReason::Stop,
        "max_tokens" => FinishReason::Length,
        "tool_use" => FinishReason::ToolCalls,
        "refusal" => FinishReason::ContentFilter,
        other => FinishReason::Other(other.to_owned()),
    }
}

/// Decodes a buffered `messages` response.
///
/// # Errors
///
/// Returns [`ErrorKind::Protocol`] when the document does not match the dialect.
pub fn decode_message(provider: &str, body: &[u8]) -> Result<CompletionResponse, ProviderError> {
    let wire: WireMessageResponse = serde_json::from_slice(body).map_err(|error| {
        protocol_error(
            provider,
            Operation::Complete,
            &format!("the message response could not be parsed: {error}"),
        )
    })?;
    let mut content = Vec::new();
    let mut reasoning = String::new();
    let mut tool_calls = Vec::new();
    for block in wire.content {
        match block {
            WireResponseBlock::Text { text } => content.push(ContentPart::Text(text)),
            WireResponseBlock::Thinking { thinking } => reasoning.push_str(&thinking),
            WireResponseBlock::RedactedThinking {} => {}
            WireResponseBlock::ToolUse { id, name, input } => {
                let arguments = serde_json::to_string(&input).map_err(|error| {
                    protocol_error(
                        provider,
                        Operation::Complete,
                        &format!("a tool call carried an unrepresentable input: {error}"),
                    )
                })?;
                tool_calls.push(ToolCall {
                    id,
                    name,
                    arguments: ToolArguments::new(arguments).map_err(|error| {
                        protocol_error(
                            provider,
                            Operation::Complete,
                            &format!("a tool call carried invalid arguments: {error}"),
                        )
                    })?,
                });
            }
        }
    }
    let model = ModelId::new(if wire.model.is_empty() {
        "unknown".to_owned()
    } else {
        wire.model
    })
    .map_err(|error| {
        protocol_error(
            provider,
            Operation::Complete,
            &format!("the response named an invalid model: {error}"),
        )
    })?;
    Ok(CompletionResponse {
        id: wire.id,
        model,
        message: AssistantMessage {
            content,
            reasoning: if reasoning.is_empty() {
                None
            } else {
                Some(reasoning)
            },
            tool_calls,
        },
        finish_reason: wire
            .stop_reason
            .as_deref()
            .map_or(FinishReason::Stop, stop_reason),
        usage: Usage::from(wire.usage),
    })
}

#[derive(Debug, Deserialize)]
struct WireModel {
    id: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WireModelList {
    data: Vec<WireModel>,
}

/// Decodes a `v1/models` response.
///
/// Anthropic publishes a display name but no context window or per-model
/// capability metadata, so those fields stay empty rather than being guessed.
///
/// # Errors
///
/// Returns [`ErrorKind::Protocol`] when the document does not match the dialect.
pub fn decode_models(provider: &str, body: &[u8]) -> Result<Vec<ModelDescriptor>, ProviderError> {
    let wire: WireModelList = serde_json::from_slice(body).map_err(|error| {
        protocol_error(
            provider,
            Operation::ListModels,
            &format!("the model list could not be parsed: {error}"),
        )
    })?;
    wire.data
        .into_iter()
        .map(|model| {
            Ok(ModelDescriptor {
                id: ModelId::new(model.id).map_err(|error| {
                    protocol_error(
                        provider,
                        Operation::ListModels,
                        &format!("the catalogue contained an invalid model id: {error}"),
                    )
                })?,
                display_name: model.display_name,
                context_window: None,
                max_output_tokens: None,
                capabilities: CapabilitySet::EMPTY,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct WireStreamMessage {
    #[serde(default)]
    id: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    usage: WireUsage,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WireStartBlock {
    #[serde(rename = "text")]
    Text {},
    #[serde(rename = "thinking")]
    Thinking {},
    #[serde(rename = "redacted_thinking")]
    RedactedThinking {},
    #[serde(rename = "tool_use")]
    ToolUse { id: String, name: String },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WireBlockDelta {
    #[serde(rename = "text_delta")]
    Text { text: String },
    #[serde(rename = "thinking_delta")]
    Thinking { thinking: String },
    #[serde(rename = "signature_delta")]
    Signature {},
    #[serde(rename = "input_json_delta")]
    InputJson { partial_json: String },
}

#[derive(Debug, Deserialize)]
struct WireMessageDelta {
    #[serde(default)]
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WireStreamEvent {
    #[serde(rename = "message_start")]
    MessageStart { message: WireStreamMessage },
    #[serde(rename = "content_block_start")]
    ContentBlockStart {
        index: usize,
        content_block: WireStartBlock,
    },
    #[serde(rename = "content_block_delta")]
    ContentBlockDelta { index: usize, delta: WireBlockDelta },
    #[serde(rename = "content_block_stop")]
    ContentBlockStop { index: usize },
    #[serde(rename = "message_delta")]
    MessageDelta {
        delta: WireMessageDelta,
        #[serde(default)]
        usage: WireUsage,
    },
    #[serde(rename = "message_stop")]
    MessageStop {},
    #[serde(rename = "ping")]
    Ping {},
    #[serde(rename = "error")]
    Error { error: WireStreamError },
}

#[derive(Debug, Deserialize)]
struct WireStreamError {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    message: String,
}

/// Turns Anthropic stream events into portable [`StreamEvent`] values.
#[derive(Debug)]
pub struct AnthropicStreamDecoder {
    provider: String,
    assembler: ToolCallAssembler,
    /// Maps an Anthropic content-block index onto a tool-call ordinal.
    tool_indices: BTreeMap<usize, usize>,
    usage: Usage,
    finish_reason: Option<FinishReason>,
    completed: bool,
}

impl AnthropicStreamDecoder {
    /// Creates a decoder that reports errors as coming from `provider`.
    #[must_use]
    pub fn new(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            assembler: ToolCallAssembler::new(),
            tool_indices: BTreeMap::new(),
            usage: Usage::default(),
            finish_reason: None,
            completed: false,
        }
    }

    /// Applies one server-sent event.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Protocol`] when an event cannot be parsed, or the
    /// typed error the server reported in an `error` event.
    pub fn accept(&mut self, event: &SseEvent) -> Result<Vec<StreamEvent>, ProviderError> {
        if self.completed {
            return Ok(Vec::new());
        }
        let data = event.data.trim();
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let parsed: WireStreamEvent = serde_json::from_str(data).map_err(|error| {
            protocol_error(
                &self.provider,
                Operation::StreamCompletion,
                &format!("a stream event could not be parsed: {error}"),
            )
        })?;
        let mut events = Vec::new();
        match parsed {
            WireStreamEvent::MessageStart { message } => {
                self.usage = Usage::from(message.usage);
                events.push(StreamEvent::Started {
                    id: message.id,
                    model: message.model,
                });
                if self.usage != Usage::default() {
                    events.push(StreamEvent::UsageUpdate(self.usage));
                }
            }
            WireStreamEvent::ContentBlockStart {
                index,
                content_block,
            } => {
                if let WireStartBlock::ToolUse { id, name } = content_block {
                    let ordinal = self.assembler.len();
                    self.tool_indices.insert(index, ordinal);
                    events.extend(self.assembler.accept(ordinal, Some(&id), Some(&name), None));
                }
            }
            WireStreamEvent::ContentBlockDelta { index, delta } => match delta {
                WireBlockDelta::Text { text } => {
                    if !text.is_empty() {
                        events.push(StreamEvent::TextDelta(text));
                    }
                }
                WireBlockDelta::Thinking { thinking } => {
                    if !thinking.is_empty() {
                        events.push(StreamEvent::ReasoningDelta(thinking));
                    }
                }
                WireBlockDelta::Signature {} => {}
                WireBlockDelta::InputJson { partial_json } => {
                    if let Some(&ordinal) = self.tool_indices.get(&index) {
                        events.extend(self.assembler.accept(
                            ordinal,
                            None,
                            None,
                            Some(&partial_json),
                        ));
                    } else {
                        return Err(protocol_error(
                            &self.provider,
                            Operation::StreamCompletion,
                            "an input_json_delta arrived for a block that never started",
                        ));
                    }
                }
            },
            WireStreamEvent::ContentBlockStop { index } => {
                if let Some(&ordinal) = self.tool_indices.get(&index) {
                    let completed = self.assembler.complete(ordinal).map_err(|error| {
                        protocol_error(
                            &self.provider,
                            Operation::StreamCompletion,
                            &format!("a streamed tool call could not be assembled: {error}"),
                        )
                    })?;
                    events.push(completed);
                }
            }
            WireStreamEvent::MessageDelta { delta, usage } => {
                if let Some(raw) = delta.stop_reason {
                    self.finish_reason = Some(stop_reason(&raw));
                }
                let reported = Usage::from(usage);
                if reported != Usage::default() {
                    self.usage = Usage {
                        input_tokens: self.usage.input_tokens.max(reported.input_tokens),
                        output_tokens: reported.output_tokens,
                        cached_input_tokens: self
                            .usage
                            .cached_input_tokens
                            .max(reported.cached_input_tokens),
                        reasoning_tokens: 0,
                    };
                    events.push(StreamEvent::UsageUpdate(self.usage));
                }
            }
            WireStreamEvent::MessageStop {} => events.extend(self.finish()),
            WireStreamEvent::Ping {} => {}
            WireStreamEvent::Error { error } => {
                self.completed = true;
                return Err(ProviderError::new(
                    error_kind_for(&error.kind),
                    &self.provider,
                    Operation::StreamCompletion,
                    if error.message.is_empty() {
                        error.kind.clone()
                    } else {
                        error.message.clone()
                    },
                )
                .with_upstream_code(&error.kind));
            }
        }
        Ok(events)
    }

    /// Emits the terminal event for a stream that ended.
    #[must_use]
    pub fn finish(&mut self) -> Vec<StreamEvent> {
        if self.completed {
            return Vec::new();
        }
        self.completed = true;
        vec![StreamEvent::Completed {
            finish_reason: self.finish_reason.clone().unwrap_or(FinishReason::Stop),
            usage: self.usage,
        }]
    }

    /// Returns the usage seen so far.
    #[must_use]
    pub const fn usage(&self) -> Usage {
        self.usage
    }
}

/// Maps an Anthropic error `type` onto the portable taxonomy.
#[must_use]
pub fn error_kind_for(kind: &str) -> ErrorKind {
    match kind {
        "authentication_error" | "permission_error" => ErrorKind::Authentication,
        "rate_limit_error" => ErrorKind::RateLimit,
        "billing_error" => ErrorKind::Quota,
        "invalid_request_error" | "not_found_error" | "request_too_large" => {
            ErrorKind::InvalidRequest
        }
        "overloaded_error" | "api_error" => ErrorKind::Server,
        "timeout_error" => ErrorKind::Timeout,
        _ => ErrorKind::Protocol,
    }
}

/// Decodes a complete recorded Anthropic SSE body into portable events.
///
/// # Errors
///
/// Returns [`ErrorKind::Protocol`] when the body is not well-formed, or the
/// typed error the server reported.
pub fn decode_event_stream(provider: &str, body: &[u8]) -> Result<Vec<StreamEvent>, ProviderError> {
    let mut sse = SseDecoder::new();
    let mut decoder = AnthropicStreamDecoder::new(provider);
    let mut events = Vec::new();
    let framed = sse.push(body).map_err(|error| {
        protocol_error(
            provider,
            Operation::StreamCompletion,
            &format!("the event stream is malformed: {error}"),
        )
    })?;
    for event in framed {
        events.extend(decoder.accept(&event)?);
    }
    for event in sse.finish().map_err(|error| {
        protocol_error(
            provider,
            Operation::StreamCompletion,
            &format!("the event stream is malformed: {error}"),
        )
    })? {
        events.extend(decoder.accept(&event)?);
    }
    events.extend(decoder.finish());
    Ok(events)
}

struct StreamState {
    chunks: ChunkStream,
    sse: SseDecoder,
    decoder: AnthropicStreamDecoder,
    pending: VecDeque<StreamEvent>,
    exhausted: bool,
}

fn event_stream(provider: String, chunks: ChunkStream) -> EventStream {
    let state = StreamState {
        chunks,
        sse: SseDecoder::new(),
        decoder: AnthropicStreamDecoder::new(provider.clone()),
        pending: VecDeque::new(),
        exhausted: false,
    };
    Box::pin(futures_util::stream::unfold(
        (state, provider),
        |(mut state, provider)| async move {
            loop {
                if let Some(event) = state.pending.pop_front() {
                    return Some((Ok(event), (state, provider)));
                }
                if state.exhausted {
                    return None;
                }
                match state.chunks.next().await {
                    Some(Ok(bytes)) => match state.sse.push(&bytes) {
                        Ok(framed) => {
                            for event in framed {
                                match state.decoder.accept(&event) {
                                    Ok(events) => state.pending.extend(events),
                                    Err(error) => {
                                        state.exhausted = true;
                                        return Some((Err(error), (state, provider)));
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            state.exhausted = true;
                            let error = protocol_error(
                                &provider,
                                Operation::StreamCompletion,
                                &format!("the event stream is malformed: {error}"),
                            );
                            return Some((Err(error), (state, provider)));
                        }
                    },
                    Some(Err(error)) => {
                        state.exhausted = true;
                        return Some((Err(error), (state, provider)));
                    }
                    None => {
                        state.exhausted = true;
                        match state.sse.finish() {
                            Ok(framed) => {
                                for event in framed {
                                    match state.decoder.accept(&event) {
                                        Ok(events) => state.pending.extend(events),
                                        Err(error) => {
                                            return Some((Err(error), (state, provider)));
                                        }
                                    }
                                }
                            }
                            Err(error) => {
                                let error = protocol_error(
                                    &provider,
                                    Operation::StreamCompletion,
                                    &format!("the event stream is malformed: {error}"),
                                );
                                return Some((Err(error), (state, provider)));
                            }
                        }
                        let tail = state.decoder.finish();
                        state.pending.extend(tail);
                    }
                }
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use claw_provider_sdk::model::{
        Capability, ImageMediaType, ImagePart, ToolDefinition, ToolParameters, ToolResultMessage,
    };
    use serde_json::json;

    use super::*;

    fn model(id: &str) -> ModelId {
        ModelId::new(id).expect("valid model id")
    }

    fn parse(document: &str) -> Value {
        serde_json::from_str(document).expect("encoded document must be valid JSON")
    }

    #[test]
    fn the_system_turn_is_hoisted_and_max_tokens_is_always_present() {
        let request = CompletionRequest::new(
            model("claude-sonnet-4-5"),
            vec![
                ChatMessage::System("be terse".to_owned()),
                ChatMessage::user_text("hei"),
                ChatMessage::System("and polite".to_owned()),
            ],
        );
        let encoded = parse(&encode_messages(&request, 512, false).expect("encode"));
        assert_eq!(
            encoded,
            json!({
                "model": "claude-sonnet-4-5",
                "max_tokens": 512,
                "system": "be terse\n\nand polite",
                "messages": [
                    {"role": "user", "content": [{"type": "text", "text": "hei"}]}
                ]
            })
        );
    }

    #[test]
    fn an_explicit_output_budget_overrides_the_default() {
        let mut request =
            CompletionRequest::new(model("claude-opus-4-1"), vec![ChatMessage::user_text("x")]);
        request.max_output_tokens = Some(64);
        let encoded = parse(&encode_messages(&request, 4096, false).expect("encode"));
        assert_eq!(encoded["max_tokens"], json!(64));
    }

    #[test]
    fn tool_calls_and_results_round_trip_through_content_blocks() {
        let mut request = CompletionRequest::new(
            model("claude-sonnet-4-5"),
            vec![
                ChatMessage::user_text("weather?"),
                ChatMessage::Assistant(AssistantMessage {
                    content: vec![ContentPart::text("checking")],
                    reasoning: None,
                    tool_calls: vec![ToolCall {
                        id: "toolu_1".to_owned(),
                        name: "get_weather".to_owned(),
                        arguments: ToolArguments::new(r#"{"city":"Oslo"}"#).expect("arguments"),
                    }],
                }),
                ChatMessage::ToolResult(ToolResultMessage {
                    tool_call_id: "toolu_1".to_owned(),
                    content: "12C".to_owned(),
                    is_error: false,
                }),
                ChatMessage::ToolResult(ToolResultMessage {
                    tool_call_id: "toolu_2".to_owned(),
                    content: "boom".to_owned(),
                    is_error: true,
                }),
            ],
        );
        request.tools = vec![ToolDefinition {
            name: "get_weather".to_owned(),
            description: "look it up".to_owned(),
            parameters: ToolParameters::new(json!({"type": "object"})).expect("schema"),
        }];
        request.tool_choice = ToolChoice::Function("get_weather".to_owned());
        request.parallel_tool_calls = Some(false);

        let encoded = parse(&encode_messages(&request, 1024, false).expect("encode"));
        assert_eq!(
            encoded["messages"],
            json!([
                {"role": "user", "content": [{"type": "text", "text": "weather?"}]},
                {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "checking"},
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "get_weather",
                            "input": {"city": "Oslo"}
                        }
                    ]
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_1",
                            "content": "12C",
                            "is_error": false
                        },
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_2",
                            "content": "boom",
                            "is_error": true
                        }
                    ]
                }
            ])
        );
        assert_eq!(
            encoded["tools"],
            json!([{
                "name": "get_weather",
                "description": "look it up",
                "input_schema": {"type": "object"}
            }])
        );
        assert_eq!(
            encoded["tool_choice"],
            json!({
                "type": "tool",
                "name": "get_weather",
                "disable_parallel_tool_use": true
            })
        );
    }

    #[test]
    fn tool_choice_variants_map_onto_the_anthropic_names() {
        let tool = ToolDefinition {
            name: "f".to_owned(),
            description: String::new(),
            parameters: ToolParameters::empty(),
        };
        for (choice, expected) in [
            (ToolChoice::Auto, json!({"type": "auto"})),
            (ToolChoice::None, json!({"type": "none"})),
            (ToolChoice::Required, json!({"type": "any"})),
            (
                ToolChoice::Function("f".to_owned()),
                json!({"type": "tool", "name": "f"}),
            ),
        ] {
            let mut request = CompletionRequest::new(
                model("claude-sonnet-4-5"),
                vec![ChatMessage::user_text("x")],
            );
            request.tools = vec![tool.clone()];
            request.tool_choice = choice.clone();
            let encoded = parse(&encode_messages(&request, 16, false).expect("encode"));
            assert_eq!(encoded["tool_choice"], expected, "{choice:?}");
        }
    }

    #[test]
    fn images_are_encoded_as_typed_sources() {
        let request = CompletionRequest::new(
            model("claude-sonnet-4-5"),
            vec![ChatMessage::User(vec![
                ContentPart::Image(ImagePart {
                    media_type: ImageMediaType::Webp,
                    source: ImageSource::Base64("AAAA".to_owned()),
                }),
                ContentPart::Image(ImagePart {
                    media_type: ImageMediaType::Gif,
                    source: ImageSource::Url("https://example.invalid/a.gif".parse().expect("url")),
                }),
            ])],
        );
        let encoded = parse(&encode_messages(&request, 16, false).expect("encode"));
        assert_eq!(
            encoded["messages"][0]["content"],
            json!([
                {
                    "type": "image",
                    "source": {"type": "base64", "media_type": "image/webp", "data": "AAAA"}
                },
                {
                    "type": "image",
                    "source": {"type": "url", "url": "https://example.invalid/a.gif"}
                }
            ])
        );
    }

    #[test]
    fn a_json_response_format_is_rejected_rather_than_silently_dropped() {
        let mut request = CompletionRequest::new(
            model("claude-sonnet-4-5"),
            vec![ChatMessage::user_text("x")],
        );
        request.response_format = ResponseFormat::JsonObject;
        let error = encode_messages(&request, 16, false).expect_err("unsupported");
        assert_eq!(error.kind(), ErrorKind::Unsupported);
        assert_eq!(
            error.detail(),
            "Anthropic has no response-format switch; use a tool to constrain output"
        );
    }

    #[test]
    fn a_message_response_decodes_text_thinking_and_tool_use() {
        let body = br#"{
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-5-20250929",
            "content": [
                {"type": "thinking", "thinking": "let me check", "signature": "sig"},
                {"type": "redacted_thinking", "data": "opaque"},
                {"type": "text", "text": "It is 12C."},
                {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "Oslo"}}
            ],
            "stop_reason": "tool_use",
            "usage": {
                "input_tokens": 20,
                "output_tokens": 9,
                "cache_read_input_tokens": 5,
                "cache_creation_input_tokens": 2
            }
        }"#;
        let response = decode_message("anthropic", body).expect("decode");
        assert_eq!(response.id, "msg_01");
        assert_eq!(response.model.as_str(), "claude-sonnet-4-5-20250929");
        assert_eq!(
            response.message.content,
            vec![ContentPart::text("It is 12C.")]
        );
        assert_eq!(response.message.reasoning.as_deref(), Some("let me check"));
        assert_eq!(response.message.tool_calls.len(), 1);
        assert_eq!(response.message.tool_calls[0].id, "toolu_1");
        assert_eq!(response.message.tool_calls[0].name, "get_weather");
        assert_eq!(
            response.message.tool_calls[0].arguments.as_str(),
            r#"{"city":"Oslo"}"#
        );
        assert_eq!(response.finish_reason, FinishReason::ToolCalls);
        assert_eq!(
            response.usage,
            Usage {
                input_tokens: 22,
                output_tokens: 9,
                cached_input_tokens: 5,
                reasoning_tokens: 0,
            }
        );
    }

    #[test]
    fn stop_reasons_map_onto_the_portable_enumeration() {
        assert_eq!(stop_reason("end_turn"), FinishReason::Stop);
        assert_eq!(stop_reason("stop_sequence"), FinishReason::Stop);
        assert_eq!(stop_reason("max_tokens"), FinishReason::Length);
        assert_eq!(stop_reason("tool_use"), FinishReason::ToolCalls);
        assert_eq!(stop_reason("refusal"), FinishReason::ContentFilter);
        assert_eq!(
            stop_reason("pause_turn"),
            FinishReason::Other("pause_turn".to_owned())
        );
    }

    #[test]
    fn the_model_catalogue_keeps_the_published_display_name() {
        let models = decode_models(
            "anthropic",
            br#"{
                "data": [
                    {"type": "model", "id": "claude-opus-4-1-20250805", "display_name": "Claude Opus 4.1"},
                    {"type": "model", "id": "claude-3-5-haiku-20241022"}
                ],
                "has_more": false
            }"#,
        )
        .expect("decode");
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id.as_str(), "claude-opus-4-1-20250805");
        assert_eq!(models[0].display_name.as_deref(), Some("Claude Opus 4.1"));
        assert_eq!(models[0].context_window, None);
        assert_eq!(models[1].id.as_str(), "claude-3-5-haiku-20241022");
        assert_eq!(models[1].display_name, None);
    }

    #[test]
    fn a_recorded_text_stream_decodes_to_the_exact_event_sequence() {
        let body = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4-5\",\"usage\":{\"input_tokens\":12,\"output_tokens\":1}}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: ping\ndata: {\"type\":\"ping\"}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hei\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" der\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        );
        let events = decode_event_stream("anthropic", body.as_bytes()).expect("decode");
        assert_eq!(
            events,
            vec![
                StreamEvent::Started {
                    id: "msg_1".to_owned(),
                    model: "claude-sonnet-4-5".to_owned(),
                },
                StreamEvent::UsageUpdate(Usage {
                    input_tokens: 12,
                    output_tokens: 1,
                    cached_input_tokens: 0,
                    reasoning_tokens: 0,
                }),
                StreamEvent::TextDelta("Hei".to_owned()),
                StreamEvent::TextDelta(" der".to_owned()),
                StreamEvent::UsageUpdate(Usage {
                    input_tokens: 12,
                    output_tokens: 7,
                    cached_input_tokens: 0,
                    reasoning_tokens: 0,
                }),
                StreamEvent::Completed {
                    finish_reason: FinishReason::Stop,
                    usage: Usage {
                        input_tokens: 12,
                        output_tokens: 7,
                        cached_input_tokens: 0,
                        reasoning_tokens: 0,
                    },
                },
            ]
        );
    }

    #[test]
    fn a_recorded_tool_use_stream_assembles_input_json_deltas() {
        let body = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_2\",\"model\":\"m\",\"usage\":{}}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"hmm\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"abc\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_9\",\"name\":\"get_weather\",\"input\":{}}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"ci\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"ty\\\":\\\"Oslo\\\"}\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":31}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        );
        let events = decode_event_stream("anthropic", body.as_bytes()).expect("decode");
        assert_eq!(
            events,
            vec![
                StreamEvent::Started {
                    id: "msg_2".to_owned(),
                    model: "m".to_owned(),
                },
                StreamEvent::ReasoningDelta("hmm".to_owned()),
                StreamEvent::ToolCallStarted {
                    index: 0,
                    id: "toolu_9".to_owned(),
                    name: "get_weather".to_owned(),
                },
                StreamEvent::ToolCallArgumentsDelta {
                    index: 0,
                    delta: "{\"ci".to_owned(),
                },
                StreamEvent::ToolCallArgumentsDelta {
                    index: 0,
                    delta: "ty\":\"Oslo\"}".to_owned(),
                },
                StreamEvent::ToolCallCompleted {
                    index: 0,
                    call: ToolCall {
                        id: "toolu_9".to_owned(),
                        name: "get_weather".to_owned(),
                        arguments: ToolArguments::new(r#"{"city":"Oslo"}"#).expect("arguments"),
                    },
                },
                StreamEvent::UsageUpdate(Usage {
                    input_tokens: 0,
                    output_tokens: 31,
                    cached_input_tokens: 0,
                    reasoning_tokens: 0,
                }),
                StreamEvent::Completed {
                    finish_reason: FinishReason::ToolCalls,
                    usage: Usage {
                        input_tokens: 0,
                        output_tokens: 31,
                        cached_input_tokens: 0,
                        reasoning_tokens: 0,
                    },
                },
            ]
        );
    }

    #[test]
    fn two_tool_blocks_get_independent_ordinals() {
        let body = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"x\",\"usage\":{}}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"a\",\"name\":\"f\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"x\\\":1}\"}}\n\n",
            "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"b\",\"name\":\"g\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"y\\\":2}\"}}\n\n",
            "data: {\"type\":\"content_block_stop\",\"index\":2}\n\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        let events = decode_event_stream("anthropic", body.as_bytes()).expect("decode");
        let completed: Vec<&StreamEvent> = events
            .iter()
            .filter(|event| matches!(event, StreamEvent::ToolCallCompleted { .. }))
            .collect();
        assert_eq!(
            completed,
            vec![
                &StreamEvent::ToolCallCompleted {
                    index: 0,
                    call: ToolCall {
                        id: "a".to_owned(),
                        name: "f".to_owned(),
                        arguments: ToolArguments::new(r#"{"x":1}"#).expect("arguments"),
                    },
                },
                &StreamEvent::ToolCallCompleted {
                    index: 1,
                    call: ToolCall {
                        id: "b".to_owned(),
                        name: "g".to_owned(),
                        arguments: ToolArguments::new(r#"{"y":2}"#).expect("arguments"),
                    },
                },
            ]
        );
    }

    #[test]
    fn an_error_event_becomes_a_typed_provider_error() {
        let body = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"x\",\"usage\":{}}}\n\n",
            "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n",
        );
        let error = decode_event_stream("anthropic", body.as_bytes()).expect_err("server error");
        assert_eq!(error.kind(), ErrorKind::Server);
        assert_eq!(error.operation(), Operation::StreamCompletion);
        assert_eq!(error.detail(), "Overloaded");
        assert_eq!(error.upstream_code(), Some("overloaded_error"));
    }

    #[test]
    fn error_types_map_onto_the_portable_taxonomy() {
        assert_eq!(
            error_kind_for("authentication_error"),
            ErrorKind::Authentication
        );
        assert_eq!(
            error_kind_for("permission_error"),
            ErrorKind::Authentication
        );
        assert_eq!(error_kind_for("rate_limit_error"), ErrorKind::RateLimit);
        assert_eq!(error_kind_for("billing_error"), ErrorKind::Quota);
        assert_eq!(
            error_kind_for("invalid_request_error"),
            ErrorKind::InvalidRequest
        );
        assert_eq!(error_kind_for("overloaded_error"), ErrorKind::Server);
        assert_eq!(error_kind_for("timeout_error"), ErrorKind::Timeout);
        assert_eq!(error_kind_for("brand_new_error"), ErrorKind::Protocol);
    }

    #[test]
    fn an_input_json_delta_without_a_start_is_a_protocol_error() {
        let body = "data: {\"type\":\"content_block_delta\",\"index\":3,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n";
        let error = decode_event_stream("anthropic", body.as_bytes()).expect_err("orphan delta");
        assert_eq!(error.kind(), ErrorKind::Protocol);
        assert_eq!(
            error.detail(),
            "an input_json_delta arrived for a block that never started"
        );
    }

    #[test]
    fn every_chunk_split_of_a_recorded_stream_yields_identical_events() {
        let body = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"x\",\"usage\":{\"input_tokens\":3}}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"alpha\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        )
        .as_bytes();
        let expected = decode_event_stream("anthropic", body).expect("decode");
        for split in 1..body.len() {
            let mut sse = SseDecoder::new();
            let mut decoder = AnthropicStreamDecoder::new("anthropic");
            let mut events = Vec::new();
            for part in [&body[..split], &body[split..]] {
                for event in sse.push(part).expect("frame") {
                    events.extend(decoder.accept(&event).expect("accept"));
                }
            }
            for event in sse.finish().expect("frame") {
                events.extend(decoder.accept(&event).expect("accept"));
            }
            events.extend(decoder.finish());
            assert_eq!(events, expected, "split at {split}");
        }
    }

    #[test]
    fn a_client_needs_a_key_and_sends_the_pinned_version_header() {
        let error = Anthropic::with_api_key(ApiKey::new("")).expect_err("empty key");
        assert_eq!(error.kind(), ErrorKind::Authentication);

        let client = Anthropic::with_api_key(ApiKey::new("sk-ant-secret-value")).expect("build");
        assert_eq!(client.base_url().as_str(), "https://api.anthropic.com/");
        assert_eq!(client.default_max_tokens(), DEFAULT_MAX_TOKENS);
        assert_eq!(client.id().as_str(), "anthropic");
        // Stated independently of `CAPABILITIES` on purpose: comparing the client's
        // answer to the very constant it returns cannot fail. Upstream publishes no
        // capability data, so the strongest available check is an exhaustive,
        // hand-written restatement of what Anthropic's API actually offers.
        let supported = [
            Capability::Completion,
            Capability::Streaming,
            Capability::ToolCalling,
            Capability::ModelListing,
            Capability::Vision,
            Capability::Reasoning,
            Capability::PromptCaching,
        ];
        for capability in Capability::ALL {
            assert_eq!(
                client.capabilities().contains(capability),
                supported.contains(&capability),
                "anthropic capability {capability:?}"
            );
        }
        assert_eq!(
            client.capabilities().len(),
            u32::try_from(supported.len()).expect("capability count fits in u32")
        );
        assert!(!client.capabilities().contains(Capability::Embeddings));

        let request = client
            .request(
                Method::Post,
                client.endpoint("v1/messages").expect("endpoint"),
            )
            .expect("request");
        assert_eq!(
            request.url().as_str(),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            request.header_names(),
            vec!["accept", "anthropic-version", "x-api-key"]
        );
        let rendered = format!("{request:?}");
        assert!(
            !rendered.contains("sk-ant-secret-value"),
            "debug output leaked the key: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            !format!("{client:?}").contains("sk-ant-secret-value"),
            "client debug output leaked the key"
        );
    }
}

//! The OpenAI `chat/completions` dialect.
//!
//! This module implements the wire protocol shared by OpenAI and the many
//! services that reproduce it: chat completions (buffered and streamed),
//! function calling, embeddings and model listing.
//!
//! Encoding and decoding are pure functions over `&str`/`&[u8]`, so every wire
//! behaviour in this module is tested against recorded byte fixtures without a
//! network.

use std::collections::VecDeque;
use std::pin::Pin;

use bytes::Bytes;
use claw_provider_sdk::cancel::CancelToken;
use claw_provider_sdk::error::{ErrorKind, Operation, ProviderError};
use claw_provider_sdk::http::{Body, HttpRequest, Method, TlsPolicy};
use claw_provider_sdk::model::{
    AssistantMessage, Capability, CapabilitySet, ChatMessage, CompletionRequest,
    CompletionResponse, ContentPart, Embedding, EmbeddingsRequest, EmbeddingsResponse,
    FinishReason, ImageSource, ModelDescriptor, ModelId, ProviderId, ResponseFormat, ToolArguments,
    ToolCall, ToolChoice, Usage,
};
use claw_provider_sdk::provider::{BoxFuture, Provider, RequestContext};
use claw_provider_sdk::secret::{ApiKey, SecretString};
use claw_provider_sdk::sse::{SseDecoder, SseEvent};
use claw_provider_sdk::stream::{CompletionStream, StreamEvent, ToolCallAssembler};
use futures_core::Stream;
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::descriptor::{ImplementationStatus, ProviderFamily};
use crate::registry::ProviderRegistry;
use crate::runtime::{ProviderRuntime, ReliabilityConfig};

/// Sentinel that terminates an OpenAI-style event stream.
pub const DONE_SENTINEL: &str = "[DONE]";

/// Providers known to require `stream_options.include_usage` for stream usage.
const STREAM_USAGE_OPT_IN: [&str; 1] = ["openai"];

/// How the API key is presented to the service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthStyle {
    /// `Authorization: Bearer <key>`.
    Bearer,
    /// A provider-specific header carrying the raw key.
    Header(String),
    /// The service takes no credential.
    None,
}

/// Configuration of one OpenAI-compatible endpoint.
#[derive(Debug)]
pub struct OpenAiConfig {
    /// Frozen provider identifier used in errors and metrics.
    pub provider: ProviderId,
    /// Base URL that `chat/completions` is appended to.
    pub base_url: Url,
    /// Credential, when the service requires one.
    pub api_key: Option<ApiKey>,
    /// How the credential is presented.
    pub auth: AuthStyle,
    /// Extra non-secret headers sent with every request.
    pub extra_headers: Vec<(String, String)>,
    /// Capabilities the caller may exercise.
    pub capabilities: CapabilitySet,
    /// Whether to ask for usage accounting in streamed responses.
    ///
    /// OpenAI only reports token usage in a stream when
    /// `stream_options.include_usage` is set. Many compatible services reject
    /// the unknown field, so this defaults to `false` everywhere except
    /// `openai` itself.
    pub stream_usage: bool,
    /// Reliability policies.
    pub reliability: ReliabilityConfig,
}

/// A client for one OpenAI-compatible endpoint.
#[derive(Debug)]
pub struct OpenAiCompatible {
    id: ProviderId,
    base_url: Url,
    api_key: Option<ApiKey>,
    auth: AuthStyle,
    extra_headers: Vec<(String, String)>,
    capabilities: CapabilitySet,
    stream_usage: bool,
    runtime: ProviderRuntime,
}

impl OpenAiCompatible {
    /// Builds a client from an explicit configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Authentication`] when the credential is missing for
    /// the chosen [`AuthStyle`], and [`ErrorKind::Transport`] when the TLS stack
    /// cannot be initialized.
    pub fn new(config: OpenAiConfig) -> Result<Self, ProviderError> {
        if matches!(config.auth, AuthStyle::Bearer | AuthStyle::Header(_))
            && config.api_key.as_ref().is_none_or(ApiKey::is_empty)
        {
            return Err(ProviderError::new(
                ErrorKind::Authentication,
                config.provider.as_str(),
                Operation::Authorize,
                "this provider requires an API key",
            ));
        }
        let tls_policy = if config.base_url.scheme() == "http" {
            TlsPolicy::AllowLoopbackPlaintext
        } else {
            TlsPolicy::RequireHttps
        };
        let runtime = ProviderRuntime::new(
            config.provider.as_str().to_owned(),
            tls_policy,
            config.reliability,
        )?;
        Ok(Self {
            id: config.provider,
            base_url: config.base_url,
            api_key: config.api_key,
            auth: config.auth,
            extra_headers: config.extra_headers,
            capabilities: config.capabilities,
            stream_usage: config.stream_usage,
            runtime,
        })
    }

    /// Builds a client for a registered provider using its default endpoint.
    ///
    /// `base_url` overrides the registry default and is required for providers
    /// whose status is
    /// [`EndpointRequired`](crate::descriptor::ImplementationStatus::EndpointRequired).
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Unsupported`] for an unknown provider or one that
    /// does not speak this dialect, and [`ErrorKind::InvalidRequest`] when no
    /// endpoint is available.
    pub fn from_registry(
        id: &str,
        api_key: Option<ApiKey>,
        base_url: Option<Url>,
    ) -> Result<Self, ProviderError> {
        let descriptor = ProviderRegistry::global().get(id).ok_or_else(|| {
            ProviderError::new(
                ErrorKind::Unsupported,
                id,
                Operation::Authorize,
                "no such provider is registered",
            )
        })?;
        if descriptor.family != ProviderFamily::OpenAiChatCompletions {
            return Err(ProviderError::new(
                ErrorKind::Unsupported,
                id,
                Operation::Authorize,
                "this provider does not speak the OpenAI chat-completions dialect",
            ));
        }
        let base_url = match (base_url, descriptor.base_url) {
            (Some(url), _) => url,
            (None, Some(default)) => default.parse::<Url>().map_err(|_| {
                ProviderError::new(
                    ErrorKind::InvalidRequest,
                    id,
                    Operation::Authorize,
                    "the registered base URL is not a valid URL",
                )
            })?,
            (None, None) => {
                return Err(ProviderError::new(
                    ErrorKind::InvalidRequest,
                    id,
                    Operation::Authorize,
                    "this provider ships no default endpoint, so a base URL is required",
                ));
            }
        };
        let auth = if descriptor.is_credential_free() && api_key.is_none() {
            AuthStyle::None
        } else {
            AuthStyle::Bearer
        };
        let provider = ProviderId::new(descriptor.id).map_err(|_| {
            ProviderError::new(
                ErrorKind::InvalidRequest,
                id,
                Operation::Authorize,
                "the registered identifier is not a valid provider id",
            )
        })?;
        Self::new(OpenAiConfig {
            provider,
            base_url,
            api_key,
            auth,
            extra_headers: Vec::new(),
            capabilities: descriptor.capabilities,
            stream_usage: STREAM_USAGE_OPT_IN.contains(&descriptor.id),
            reliability: ReliabilityConfig::default(),
        })
    }

    /// Returns the endpoint this client talks to.
    #[must_use]
    pub const fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Returns whether stream usage accounting is requested explicitly.
    #[must_use]
    pub const fn stream_usage(&self) -> bool {
        self.stream_usage
    }

    /// Returns how the credential is presented to the service.
    #[must_use]
    pub const fn auth_style(&self) -> &AuthStyle {
        &self.auth
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

    fn request(&self, method: Method, url: Url) -> HttpRequest {
        let mut request = HttpRequest::new(method, url).header("accept", "application/json");
        match (&self.auth, self.api_key.as_ref()) {
            (AuthStyle::Bearer, Some(key)) => {
                request = request.secret_header("authorization", key.bearer_header());
            }
            (AuthStyle::Header(name), Some(key)) => {
                request = request.secret_header(name.clone(), SecretString::new(key.expose()));
            }
            _ => {}
        }
        for (name, value) in &self.extra_headers {
            request = request.header(name.clone(), value.clone());
        }
        request
    }

    fn check_capability(
        &self,
        capability: Capability,
        operation: Operation,
    ) -> Result<(), ProviderError> {
        if self.capabilities.contains(capability) {
            return Ok(());
        }
        Err(ProviderError::new(
            ErrorKind::Unsupported,
            self.id.as_str(),
            operation,
            "this provider does not advertise the requested capability",
        ))
    }
}

impl Provider for OpenAiCompatible {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> CapabilitySet {
        self.capabilities
    }

    fn complete<'a>(
        &'a self,
        request: &'a CompletionRequest,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<CompletionResponse, ProviderError>> {
        Box::pin(async move {
            self.check_capability(Capability::Completion, Operation::Complete)?;
            validate(self.id.as_str(), request, Operation::Complete)?;
            let url = self.endpoint("chat/completions")?;
            let body = encode_completion(request, false, false)?;
            let response = self
                .runtime
                .execute(Operation::Complete, context.cancel(), || {
                    Ok(self
                        .request(Method::Post, url.clone())
                        .body(Body::Json(body.clone())))
                })
                .await?;
            decode_completion(self.id.as_str(), response.body())
        })
    }

    fn stream<'a>(
        &'a self,
        request: &'a CompletionRequest,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<CompletionStream, ProviderError>> {
        Box::pin(async move {
            self.check_capability(Capability::Streaming, Operation::StreamCompletion)?;
            validate(self.id.as_str(), request, Operation::StreamCompletion)?;
            let url = self.endpoint("chat/completions")?;
            let body = encode_completion(request, true, self.stream_usage)?;
            let cancel = context.cancel().clone();
            let stream = self
                .runtime
                .execute_streaming(Operation::StreamCompletion, &cancel, || {
                    Ok(self
                        .request(Method::Post, url.clone())
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

    fn embed<'a>(
        &'a self,
        request: &'a EmbeddingsRequest,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<EmbeddingsResponse, ProviderError>> {
        Box::pin(async move {
            self.check_capability(Capability::Embeddings, Operation::Embed)?;
            request.validate().map_err(|error| {
                ProviderError::new(
                    ErrorKind::InvalidRequest,
                    self.id.as_str(),
                    Operation::Embed,
                    error.to_string(),
                )
            })?;
            let url = self.endpoint("embeddings")?;
            let body = encode_embeddings(request)?;
            let response = self
                .runtime
                .execute(Operation::Embed, context.cancel(), || {
                    Ok(self
                        .request(Method::Post, url.clone())
                        .body(Body::Json(body.clone())))
                })
                .await?;
            decode_embeddings(self.id.as_str(), response.body())
        })
    }

    fn list_models<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<Vec<ModelDescriptor>, ProviderError>> {
        Box::pin(async move {
            self.check_capability(Capability::ModelListing, Operation::ListModels)?;
            let url = self.endpoint("models")?;
            let response = self
                .runtime
                .execute(Operation::ListModels, context.cancel(), || {
                    Ok(self.request(Method::Get, url.clone()))
                })
                .await?;
            decode_models(self.id.as_str(), response.body())
        })
    }
}

fn validate(
    provider: &str,
    request: &CompletionRequest,
    operation: Operation,
) -> Result<(), ProviderError> {
    request.validate().map_err(|error| {
        ProviderError::new(
            ErrorKind::InvalidRequest,
            provider,
            operation,
            error.to_string(),
        )
    })
}

// ---------------------------------------------------------------------------
// Request encoding
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct WireCompletionRequest<'a> {
    model: &'a str,
    messages: Vec<WireMessage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    stop: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<WireTool<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<WireToolChoice<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallel_tool_calls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<WireResponseFormat>,
    #[serde(skip_serializing_if = "is_false")]
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_options: Option<WireStreamOptions>,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if requires a predicate taking a reference"
)]
fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Serialize)]
struct WireStreamOptions {
    include_usage: bool,
}

#[derive(Debug, Serialize)]
struct WireResponseFormat {
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum WireToolChoice<'a> {
    Named(&'static str),
    Function {
        #[serde(rename = "type")]
        kind: &'static str,
        function: WireToolChoiceFunction<'a>,
    },
}

#[derive(Debug, Serialize)]
struct WireToolChoiceFunction<'a> {
    name: &'a str,
}

#[derive(Debug, Serialize)]
struct WireTool<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    function: WireFunction<'a>,
}

#[derive(Debug, Serialize)]
struct WireFunction<'a> {
    name: &'a str,
    description: &'a str,
    parameters: &'a serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum WireContent<'a> {
    Text(&'a str),
    Parts(Vec<WireContentPart<'a>>),
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum WireContentPart<'a> {
    #[serde(rename = "text")]
    Text {
        /// Text fragment.
        text: &'a str,
    },
    #[serde(rename = "image_url")]
    ImageUrl {
        /// Image reference.
        image_url: WireImageUrl,
    },
}

#[derive(Debug, Serialize)]
struct WireImageUrl {
    url: String,
}

#[derive(Debug, Serialize)]
struct WireMessage<'a> {
    role: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<WireContent<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tool_calls: Vec<WireToolCall<'a>>,
}

#[derive(Debug, Serialize)]
struct WireToolCall<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    function: WireToolCallFunction<'a>,
}

#[derive(Debug, Serialize)]
struct WireToolCallFunction<'a> {
    name: &'a str,
    arguments: &'a str,
}

fn encode_message(message: &ChatMessage) -> WireMessage<'_> {
    match message {
        ChatMessage::System(text) => WireMessage {
            role: "system",
            content: Some(WireContent::Text(text)),
            tool_call_id: None,
            tool_calls: Vec::new(),
        },
        ChatMessage::User(parts) => WireMessage {
            role: "user",
            content: Some(encode_content(parts)),
            tool_call_id: None,
            tool_calls: Vec::new(),
        },
        ChatMessage::Assistant(assistant) => WireMessage {
            role: "assistant",
            content: encode_assistant_content(assistant),
            tool_call_id: None,
            tool_calls: assistant
                .tool_calls
                .iter()
                .map(|call| WireToolCall {
                    id: &call.id,
                    kind: "function",
                    function: WireToolCallFunction {
                        name: &call.name,
                        arguments: call.arguments.as_str(),
                    },
                })
                .collect(),
        },
        ChatMessage::ToolResult(result) => WireMessage {
            role: "tool",
            content: Some(WireContent::Text(&result.content)),
            tool_call_id: Some(&result.tool_call_id),
            tool_calls: Vec::new(),
        },
    }
}

fn encode_assistant_content(message: &AssistantMessage) -> Option<WireContent<'_>> {
    if message.content.is_empty() {
        return None;
    }
    Some(encode_content(&message.content))
}

fn encode_content(parts: &[ContentPart]) -> WireContent<'_> {
    if let [ContentPart::Text(text)] = parts {
        return WireContent::Text(text);
    }
    WireContent::Parts(
        parts
            .iter()
            .map(|part| match part {
                ContentPart::Text(text) => WireContentPart::Text { text },
                ContentPart::Image(image) => WireContentPart::ImageUrl {
                    image_url: WireImageUrl {
                        url: match &image.source {
                            ImageSource::Url(url) => url.to_string(),
                            ImageSource::Base64(data) => {
                                format!("data:{};base64,{data}", image.media_type.as_str())
                            }
                        },
                    },
                },
            })
            .collect(),
    )
}

/// Encodes a completion request as an OpenAI `chat/completions` document.
///
/// # Errors
///
/// Returns [`ErrorKind::InvalidRequest`] when the request cannot be serialized.
pub fn encode_completion(
    request: &CompletionRequest,
    stream: bool,
    stream_usage: bool,
) -> Result<String, ProviderError> {
    let tools: Vec<WireTool<'_>> = request
        .tools
        .iter()
        .map(|tool| WireTool {
            kind: "function",
            function: WireFunction {
                name: &tool.name,
                description: &tool.description,
                parameters: tool.parameters.as_map(),
            },
        })
        .collect();
    let tool_choice = if tools.is_empty() {
        None
    } else {
        Some(match &request.tool_choice {
            ToolChoice::Auto => WireToolChoice::Named("auto"),
            ToolChoice::None => WireToolChoice::Named("none"),
            ToolChoice::Required => WireToolChoice::Named("required"),
            ToolChoice::Function(name) => WireToolChoice::Function {
                kind: "function",
                function: WireToolChoiceFunction { name },
            },
        })
    };
    let wire = WireCompletionRequest {
        model: request.model.as_str(),
        messages: request.messages.iter().map(encode_message).collect(),
        max_tokens: request.max_output_tokens,
        temperature: request.temperature(),
        top_p: request.top_p(),
        stop: request.stop_sequences.iter().map(String::as_str).collect(),
        seed: request.seed,
        tools,
        tool_choice,
        parallel_tool_calls: request.parallel_tool_calls,
        response_format: match request.response_format {
            ResponseFormat::Text => None,
            ResponseFormat::JsonObject => Some(WireResponseFormat {
                kind: "json_object",
            }),
        },
        stream,
        stream_options: if stream && stream_usage {
            Some(WireStreamOptions {
                include_usage: true,
            })
        } else {
            None
        },
    };
    serde_json::to_string(&wire).map_err(|error| {
        ProviderError::new(
            ErrorKind::InvalidRequest,
            request.model.as_str(),
            Operation::Complete,
            error.to_string(),
        )
    })
}

#[derive(Debug, Serialize)]
struct WireEmbeddingsRequest<'a> {
    model: &'a str,
    input: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<u32>,
}

/// Encodes an embeddings request.
///
/// # Errors
///
/// Returns [`ErrorKind::InvalidRequest`] when the request cannot be serialized.
pub fn encode_embeddings(request: &EmbeddingsRequest) -> Result<String, ProviderError> {
    serde_json::to_string(&WireEmbeddingsRequest {
        model: request.model.as_str(),
        input: &request.inputs,
        dimensions: request.dimensions,
    })
    .map_err(|error| {
        ProviderError::new(
            ErrorKind::InvalidRequest,
            request.model.as_str(),
            Operation::Embed,
            error.to_string(),
        )
    })
}

// ---------------------------------------------------------------------------
// Response decoding
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct WireUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    prompt_tokens_details: Option<WirePromptDetails>,
    #[serde(default)]
    completion_tokens_details: Option<WireCompletionDetails>,
}

#[derive(Debug, Deserialize)]
struct WirePromptDetails {
    #[serde(default)]
    cached_tokens: u64,
}

#[derive(Debug, Deserialize)]
struct WireCompletionDetails {
    #[serde(default)]
    reasoning_tokens: u64,
}

impl From<WireUsage> for Usage {
    fn from(usage: WireUsage) -> Self {
        Self {
            input_tokens: usage.prompt_tokens,
            output_tokens: usage.completion_tokens,
            cached_input_tokens: usage
                .prompt_tokens_details
                .map_or(0, |details| details.cached_tokens),
            reasoning_tokens: usage
                .completion_tokens_details
                .map_or(0, |details| details.reasoning_tokens),
        }
    }
}

#[derive(Debug, Deserialize)]
struct WireResponseToolCall {
    #[serde(default)]
    id: String,
    #[serde(default)]
    function: WireResponseFunction,
}

#[derive(Debug, Default, Deserialize)]
struct WireResponseFunction {
    #[serde(default)]
    name: String,
    #[serde(default)]
    arguments: String,
}

#[derive(Debug, Default, Deserialize)]
struct WireResponseMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
    #[serde(default)]
    reasoning: Option<String>,
    #[serde(default)]
    tool_calls: Vec<WireResponseToolCall>,
}

#[derive(Debug, Deserialize)]
struct WireChoice {
    #[serde(default)]
    message: WireResponseMessage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WireCompletionResponse {
    #[serde(default)]
    id: String,
    #[serde(default)]
    model: String,
    choices: Vec<WireChoice>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

fn protocol_error(provider: &str, operation: Operation, detail: &str) -> ProviderError {
    ProviderError::new(ErrorKind::Protocol, provider, operation, detail)
}

/// Maps an OpenAI `finish_reason` onto the portable enumeration.
#[must_use]
pub fn finish_reason(raw: &str) -> FinishReason {
    match raw {
        "stop" | "end_turn" => FinishReason::Stop,
        "length" | "max_tokens" => FinishReason::Length,
        "tool_calls" | "function_call" => FinishReason::ToolCalls,
        "content_filter" => FinishReason::ContentFilter,
        other => FinishReason::Other(other.to_owned()),
    }
}

/// Decodes a buffered `chat/completions` response.
///
/// # Errors
///
/// Returns [`ErrorKind::Protocol`] when the document does not match the dialect
/// or a tool call carries arguments that are not a JSON object.
pub fn decode_completion(provider: &str, body: &[u8]) -> Result<CompletionResponse, ProviderError> {
    let wire: WireCompletionResponse = serde_json::from_slice(body).map_err(|error| {
        protocol_error(
            provider,
            Operation::Complete,
            &format!("the completion response could not be parsed: {error}"),
        )
    })?;
    let choice = wire.choices.into_iter().next().ok_or_else(|| {
        protocol_error(
            provider,
            Operation::Complete,
            "the completion response carried no choices",
        )
    })?;
    let mut content = Vec::new();
    if let Some(text) = choice.message.content.filter(|text| !text.is_empty()) {
        content.push(ContentPart::Text(text));
    }
    let mut tool_calls = Vec::with_capacity(choice.message.tool_calls.len());
    for call in choice.message.tool_calls {
        tool_calls.push(ToolCall {
            id: call.id,
            name: call.function.name,
            arguments: ToolArguments::new(call.function.arguments).map_err(|error| {
                protocol_error(
                    provider,
                    Operation::Complete,
                    &format!("a tool call carried invalid arguments: {error}"),
                )
            })?,
        });
    }
    let model = decode_model_id(provider, Operation::Complete, wire.model)?;
    let finish = choice
        .finish_reason
        .as_deref()
        .map_or(FinishReason::Stop, finish_reason);
    Ok(CompletionResponse {
        id: wire.id,
        model,
        message: AssistantMessage {
            content,
            reasoning: choice
                .message
                .reasoning_content
                .or(choice.message.reasoning)
                .filter(|text| !text.is_empty()),
            tool_calls,
        },
        finish_reason: finish,
        usage: wire.usage.map(Usage::from).unwrap_or_default(),
    })
}

fn decode_model_id(
    provider: &str,
    operation: Operation,
    raw: String,
) -> Result<ModelId, ProviderError> {
    let raw = if raw.is_empty() {
        "unknown".to_owned()
    } else {
        raw
    };
    ModelId::new(raw).map_err(|error| {
        protocol_error(
            provider,
            operation,
            &format!("the response named an invalid model: {error}"),
        )
    })
}

#[derive(Debug, Deserialize)]
struct WireEmbedding {
    #[serde(default)]
    index: usize,
    embedding: Vec<f32>,
}

#[derive(Debug, Deserialize)]
struct WireEmbeddingsResponse {
    #[serde(default)]
    model: String,
    data: Vec<WireEmbedding>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

/// Decodes an `embeddings` response.
///
/// # Errors
///
/// Returns [`ErrorKind::Protocol`] when the document does not match the dialect.
pub fn decode_embeddings(provider: &str, body: &[u8]) -> Result<EmbeddingsResponse, ProviderError> {
    let wire: WireEmbeddingsResponse = serde_json::from_slice(body).map_err(|error| {
        protocol_error(
            provider,
            Operation::Embed,
            &format!("the embeddings response could not be parsed: {error}"),
        )
    })?;
    let model = decode_model_id(provider, Operation::Embed, wire.model)?;
    Ok(EmbeddingsResponse {
        model,
        embeddings: wire
            .data
            .into_iter()
            .map(|entry| Embedding {
                index: entry.index,
                vector: entry.embedding,
            })
            .collect(),
        usage: wire.usage.map(Usage::from).unwrap_or_default(),
    })
}

#[derive(Debug, Deserialize)]
struct WireModel {
    id: String,
}

#[derive(Debug, Deserialize)]
struct WireModelList {
    data: Vec<WireModel>,
}

/// Decodes a `models` response.
///
/// The OpenAI model catalogue publishes no capability, context-window or
/// display-name metadata, so every returned [`ModelDescriptor`] carries only an
/// identifier and an empty capability set. Nothing is inferred.
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
                display_name: None,
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
struct WireDeltaToolCall {
    #[serde(default)]
    index: usize,
    id: Option<String>,
    #[serde(default)]
    function: Option<WireDeltaFunction>,
}

#[derive(Debug, Deserialize)]
struct WireDeltaFunction {
    name: Option<String>,
    arguments: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct WireDelta {
    content: Option<String>,
    reasoning_content: Option<String>,
    reasoning: Option<String>,
    #[serde(default)]
    tool_calls: Vec<WireDeltaToolCall>,
}

#[derive(Debug, Deserialize)]
struct WireStreamChoice {
    #[serde(default)]
    delta: WireDelta,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WireStreamChunk {
    #[serde(default)]
    id: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    choices: Vec<WireStreamChoice>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

/// Turns OpenAI stream chunks into portable [`StreamEvent`] values.
///
/// The decoder is a pure state machine over already-framed SSE events, so it can
/// be driven directly from a recorded byte fixture.
#[derive(Debug)]
pub struct OpenAiStreamDecoder {
    provider: String,
    assembler: ToolCallAssembler,
    started: bool,
    usage: Usage,
    finish_reason: Option<FinishReason>,
    completed: bool,
}

impl OpenAiStreamDecoder {
    /// Creates a decoder that reports errors as coming from `provider`.
    #[must_use]
    pub fn new(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            assembler: ToolCallAssembler::new(),
            started: false,
            usage: Usage::default(),
            finish_reason: None,
            completed: false,
        }
    }

    /// Applies one server-sent event.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Protocol`] when a chunk cannot be parsed.
    pub fn accept(&mut self, event: &SseEvent) -> Result<Vec<StreamEvent>, ProviderError> {
        if self.completed {
            return Ok(Vec::new());
        }
        let data = event.data.trim();
        if data.is_empty() {
            return Ok(Vec::new());
        }
        if data == DONE_SENTINEL {
            return Ok(self.finish());
        }
        let chunk: WireStreamChunk = serde_json::from_str(data).map_err(|error| {
            protocol_error(
                &self.provider,
                Operation::StreamCompletion,
                &format!("a stream chunk could not be parsed: {error}"),
            )
        })?;
        let mut events = Vec::new();
        if !self.started && !chunk.id.is_empty() {
            self.started = true;
            events.push(StreamEvent::Started {
                id: chunk.id,
                model: chunk.model,
            });
        }
        if let Some(usage) = chunk.usage {
            self.usage = Usage::from(usage);
            events.push(StreamEvent::UsageUpdate(self.usage));
        }
        for choice in chunk.choices {
            if let Some(text) = choice.delta.content.filter(|text| !text.is_empty()) {
                events.push(StreamEvent::TextDelta(text));
            }
            if let Some(text) = choice
                .delta
                .reasoning_content
                .or(choice.delta.reasoning)
                .filter(|text| !text.is_empty())
            {
                events.push(StreamEvent::ReasoningDelta(text));
            }
            for call in choice.delta.tool_calls {
                let (name, arguments) = call
                    .function
                    .map_or((None, None), |function| (function.name, function.arguments));
                events.extend(self.assembler.accept(
                    call.index,
                    call.id.as_deref(),
                    name.as_deref(),
                    arguments.as_deref(),
                ));
            }
            if let Some(raw) = choice.finish_reason {
                self.finish_reason = Some(finish_reason(&raw));
            }
        }
        Ok(events)
    }

    /// Emits the terminal events for a stream that ended.
    ///
    /// Pending tool calls are finalized here, because a provider signals the
    /// last argument fragment only by ending the stream.
    #[must_use]
    pub fn finish(&mut self) -> Vec<StreamEvent> {
        if self.completed {
            return Vec::new();
        }
        self.completed = true;
        let mut events = Vec::new();
        let pending = self.assembler.len();
        for index in 0..pending {
            match self.assembler.complete(index) {
                Ok(event) => events.push(event),
                Err(_) => {
                    events.push(StreamEvent::Completed {
                        finish_reason: FinishReason::Other("incomplete_tool_call".to_owned()),
                        usage: self.usage,
                    });
                    return events;
                }
            }
        }
        let finish = self.finish_reason.clone().unwrap_or(if pending > 0 {
            FinishReason::ToolCalls
        } else {
            FinishReason::Stop
        });
        events.push(StreamEvent::Completed {
            finish_reason: finish,
            usage: self.usage,
        });
        events
    }

    /// Returns the usage seen so far.
    #[must_use]
    pub const fn usage(&self) -> Usage {
        self.usage
    }
}

/// Decodes a complete recorded SSE body into portable events.
///
/// This is the same state machine the live stream uses, driven from bytes.
///
/// # Errors
///
/// Returns [`ErrorKind::Protocol`] when the body is not well-formed.
pub fn decode_event_stream(provider: &str, body: &[u8]) -> Result<Vec<StreamEvent>, ProviderError> {
    let mut sse = SseDecoder::new();
    let mut decoder = OpenAiStreamDecoder::new(provider);
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
    let tail = sse.finish().map_err(|error| {
        protocol_error(
            provider,
            Operation::StreamCompletion,
            &format!("the event stream is malformed: {error}"),
        )
    })?;
    for event in tail {
        events.extend(decoder.accept(&event)?);
    }
    events.extend(decoder.finish());
    Ok(events)
}

/// A stream of raw response-body chunks.
pub type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, ProviderError>> + Send>>;

/// A stream of decoded completion events.
pub type EventStream = Pin<Box<dyn Stream<Item = Result<StreamEvent, ProviderError>> + Send>>;

struct StreamState {
    chunks: ChunkStream,
    sse: SseDecoder,
    decoder: OpenAiStreamDecoder,
    pending: VecDeque<StreamEvent>,
    exhausted: bool,
}

fn event_stream(provider: String, chunks: ChunkStream) -> EventStream {
    let state = StreamState {
        chunks,
        sse: SseDecoder::new(),
        decoder: OpenAiStreamDecoder::new(provider.clone()),
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

/// Builds the cancellable event stream used by [`Provider::stream`].
///
/// Exposed so integration tests can drive the same decoding path from a
/// synthetic chunk stream.
#[must_use]
pub fn events_from_chunks(
    provider: &str,
    cancel: CancelToken,
    chunks: ChunkStream,
) -> CompletionStream {
    CompletionStream::new(provider, cancel, event_stream(provider.to_owned(), chunks))
}

/// Returns `true` when `id` names a registered provider that ships a verified
/// default endpoint.
#[must_use]
pub fn has_default_endpoint(id: &str) -> bool {
    ProviderRegistry::global()
        .get(id)
        .is_some_and(|descriptor| descriptor.status == ImplementationStatus::Implemented)
}

#[cfg(test)]
mod tests {
    use claw_provider_sdk::model::{
        ImageMediaType, ImagePart, ToolDefinition, ToolParameters, ToolResultMessage,
    };
    use serde_json::{Value, json};

    use super::*;

    fn model(id: &str) -> ModelId {
        ModelId::new(id).expect("valid model id")
    }

    fn parse(document: &str) -> Value {
        serde_json::from_str(document).expect("encoded document must be valid JSON")
    }

    #[test]
    fn a_minimal_request_encodes_only_the_required_fields() {
        let request =
            CompletionRequest::new(model("gpt-4o-mini"), vec![ChatMessage::user_text("hello")]);
        let encoded = parse(&encode_completion(&request, false, false).expect("encode"));
        assert_eq!(
            encoded,
            json!({
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}]
            })
        );
    }

    #[test]
    fn sampling_tools_and_response_format_are_encoded_in_the_openai_shape() {
        let mut request = CompletionRequest::new(
            model("gpt-4o"),
            vec![
                ChatMessage::System("be terse".to_owned()),
                ChatMessage::user_text("weather?"),
                ChatMessage::Assistant(AssistantMessage {
                    content: Vec::new(),
                    reasoning: None,
                    tool_calls: vec![ToolCall {
                        id: "call_1".to_owned(),
                        name: "get_weather".to_owned(),
                        arguments: ToolArguments::new(r#"{"city":"Oslo"}"#).expect("arguments"),
                    }],
                }),
                ChatMessage::ToolResult(ToolResultMessage {
                    tool_call_id: "call_1".to_owned(),
                    content: "12C".to_owned(),
                    is_error: false,
                }),
            ],
        );
        request.tools = vec![ToolDefinition {
            name: "get_weather".to_owned(),
            description: "look up the weather".to_owned(),
            parameters: ToolParameters::new(json!({
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"]
            }))
            .expect("schema"),
        }];
        request.tool_choice = ToolChoice::Function("get_weather".to_owned());
        request.max_output_tokens = Some(256);
        request.temperature_milli = Some(250);
        request.top_p_milli = Some(900);
        request.stop_sequences = vec!["\n\n".to_owned()];
        request.parallel_tool_calls = Some(false);
        request.seed = Some(7);
        request.response_format = ResponseFormat::JsonObject;

        let encoded = parse(&encode_completion(&request, true, true).expect("encode"));
        assert_eq!(
            encoded,
            json!({
                "model": "gpt-4o",
                "messages": [
                    {"role": "system", "content": "be terse"},
                    {"role": "user", "content": "weather?"},
                    {
                        "role": "assistant",
                        "tool_calls": [{
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "get_weather", "arguments": "{\"city\":\"Oslo\"}"}
                        }]
                    },
                    {"role": "tool", "content": "12C", "tool_call_id": "call_1"}
                ],
                "max_tokens": 256,
                "temperature": 0.25,
                "top_p": 0.9,
                "stop": ["\n\n"],
                "seed": 7,
                "tools": [{
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "description": "look up the weather",
                        "parameters": {
                            "type": "object",
                            "properties": {"city": {"type": "string"}},
                            "required": ["city"]
                        }
                    }
                }],
                "tool_choice": {"type": "function", "function": {"name": "get_weather"}},
                "parallel_tool_calls": false,
                "response_format": {"type": "json_object"},
                "stream": true,
                "stream_options": {"include_usage": true}
            })
        );
    }

    #[test]
    fn images_are_encoded_as_data_urls_and_absolute_urls() {
        let request = CompletionRequest::new(
            model("gpt-4o"),
            vec![ChatMessage::User(vec![
                ContentPart::text("what is this?"),
                ContentPart::Image(ImagePart {
                    media_type: ImageMediaType::Png,
                    source: ImageSource::Base64("iVBORw0KGgo=".to_owned()),
                }),
                ContentPart::Image(ImagePart {
                    media_type: ImageMediaType::Jpeg,
                    source: ImageSource::Url(
                        "https://example.invalid/cat.jpg".parse().expect("url"),
                    ),
                }),
            ])],
        );
        let encoded = parse(&encode_completion(&request, false, false).expect("encode"));
        assert_eq!(
            encoded["messages"][0]["content"],
            json!([
                {"type": "text", "text": "what is this?"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}},
                {"type": "image_url", "image_url": {"url": "https://example.invalid/cat.jpg"}}
            ])
        );
    }

    #[test]
    fn tool_choice_is_omitted_when_no_tool_is_offered() {
        let mut request =
            CompletionRequest::new(model("gpt-4o"), vec![ChatMessage::user_text("hi")]);
        request.tool_choice = ToolChoice::Required;
        let encoded = parse(&encode_completion(&request, false, false).expect("encode"));
        assert_eq!(encoded.get("tool_choice"), None);
        assert_eq!(encoded.get("tools"), None);
    }

    #[test]
    fn stream_options_are_only_sent_when_both_flags_are_set() {
        let request = CompletionRequest::new(model("gpt-4o"), vec![ChatMessage::user_text("hi")]);
        let streaming_without_usage =
            parse(&encode_completion(&request, true, false).expect("encode"));
        assert_eq!(streaming_without_usage["stream"], json!(true));
        assert_eq!(streaming_without_usage.get("stream_options"), None);

        let buffered_with_usage = parse(&encode_completion(&request, false, true).expect("encode"));
        assert_eq!(buffered_with_usage.get("stream"), None);
        assert_eq!(buffered_with_usage.get("stream_options"), None);
    }

    #[test]
    fn embeddings_requests_encode_the_input_array() {
        let request = EmbeddingsRequest {
            model: model("text-embedding-3-small"),
            inputs: vec!["alpha".to_owned(), "beta".to_owned()],
            dimensions: Some(256),
        };
        assert_eq!(
            parse(&encode_embeddings(&request).expect("encode")),
            json!({
                "model": "text-embedding-3-small",
                "input": ["alpha", "beta"],
                "dimensions": 256
            })
        );
    }

    #[test]
    fn a_text_completion_decodes_into_the_portable_response() {
        let body = br#"{
            "id": "chatcmpl-9",
            "object": "chat.completion",
            "model": "gpt-4o-2024-08-06",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hei!"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 3,
                "total_tokens": 14,
                "prompt_tokens_details": {"cached_tokens": 8},
                "completion_tokens_details": {"reasoning_tokens": 2}
            }
        }"#;
        let response = decode_completion("openai", body).expect("decode");
        assert_eq!(response.id, "chatcmpl-9");
        assert_eq!(response.model.as_str(), "gpt-4o-2024-08-06");
        assert_eq!(response.message.content, vec![ContentPart::text("Hei!")]);
        assert_eq!(response.message.reasoning, None);
        assert_eq!(response.message.tool_calls, Vec::new());
        assert_eq!(response.finish_reason, FinishReason::Stop);
        assert_eq!(
            response.usage,
            Usage {
                input_tokens: 11,
                output_tokens: 3,
                cached_input_tokens: 8,
                reasoning_tokens: 2,
            }
        );
    }

    #[test]
    fn a_tool_call_completion_decodes_arguments_and_reasoning() {
        let body = br#"{
            "id": "chatcmpl-10",
            "model": "deepseek-reasoner",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "reasoning_content": "the user wants weather",
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"Oslo\"}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        }"#;
        let response = decode_completion("deepseek", body).expect("decode");
        assert_eq!(response.message.content, Vec::new());
        assert_eq!(
            response.message.reasoning.as_deref(),
            Some("the user wants weather")
        );
        assert_eq!(response.message.tool_calls.len(), 1);
        let call = &response.message.tool_calls[0];
        assert_eq!(call.id, "call_abc");
        assert_eq!(call.name, "get_weather");
        assert_eq!(call.arguments.as_str(), r#"{"city":"Oslo"}"#);
        assert_eq!(response.finish_reason, FinishReason::ToolCalls);
        assert_eq!(response.usage, Usage::default());
    }

    #[test]
    fn a_response_without_choices_is_a_protocol_error() {
        let error =
            decode_completion("openai", br#"{"id":"x","choices":[]}"#).expect_err("no choices");
        assert_eq!(error.kind(), ErrorKind::Protocol);
        assert_eq!(error.operation(), Operation::Complete);
        assert_eq!(error.provider(), "openai");
        assert_eq!(error.detail(), "the completion response carried no choices");
    }

    #[test]
    fn tool_arguments_that_are_not_a_json_object_are_rejected() {
        let body = br#"{
            "id": "x",
            "model": "m",
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "id": "1",
                        "function": {"name": "f", "arguments": "[1,2]"}
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        }"#;
        let error = decode_completion("openai", body).expect_err("bad arguments");
        assert_eq!(error.kind(), ErrorKind::Protocol);
    }

    #[test]
    fn embeddings_and_model_lists_decode_exactly() {
        let embeddings = decode_embeddings(
            "openai",
            br#"{
                "object": "list",
                "model": "text-embedding-3-small",
                "data": [
                    {"object": "embedding", "index": 0, "embedding": [0.5, -0.25]},
                    {"object": "embedding", "index": 1, "embedding": [1.0]}
                ],
                "usage": {"prompt_tokens": 4, "total_tokens": 4}
            }"#,
        )
        .expect("decode");
        assert_eq!(embeddings.model.as_str(), "text-embedding-3-small");
        assert_eq!(embeddings.embeddings.len(), 2);
        assert_eq!(embeddings.embeddings[0].index, 0);
        assert_eq!(embeddings.embeddings[0].vector, vec![0.5, -0.25]);
        assert_eq!(embeddings.embeddings[1].index, 1);
        assert_eq!(embeddings.embeddings[1].vector, vec![1.0]);
        assert_eq!(embeddings.usage.input_tokens, 4);
        assert_eq!(embeddings.usage.output_tokens, 0);

        let models = decode_models(
            "openai",
            br#"{"object":"list","data":[{"id":"gpt-4o","object":"model"},{"id":"o3-mini","object":"model"}]}"#,
        )
        .expect("decode");
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id.as_str(), "gpt-4o");
        assert_eq!(models[0].capabilities, CapabilitySet::EMPTY);
        assert_eq!(models[0].display_name, None);
        assert_eq!(models[1].id.as_str(), "o3-mini");
    }

    #[test]
    fn finish_reasons_map_onto_the_portable_enumeration() {
        assert_eq!(finish_reason("stop"), FinishReason::Stop);
        assert_eq!(finish_reason("length"), FinishReason::Length);
        assert_eq!(finish_reason("tool_calls"), FinishReason::ToolCalls);
        assert_eq!(finish_reason("function_call"), FinishReason::ToolCalls);
        assert_eq!(finish_reason("content_filter"), FinishReason::ContentFilter);
        assert_eq!(
            finish_reason("insufficient_system_resource"),
            FinishReason::Other("insufficient_system_resource".to_owned())
        );
    }

    #[test]
    fn a_recorded_text_stream_decodes_to_the_exact_event_sequence() {
        let body = concat!(
            "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hei\"}}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" der\"}}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2}}\n\n",
            "data: [DONE]\n\n",
        );
        let events = decode_event_stream("openai", body.as_bytes()).expect("decode");
        assert_eq!(
            events,
            vec![
                StreamEvent::Started {
                    id: "chatcmpl-1".to_owned(),
                    model: "gpt-4o".to_owned(),
                },
                StreamEvent::TextDelta("Hei".to_owned()),
                StreamEvent::TextDelta(" der".to_owned()),
                StreamEvent::UsageUpdate(Usage {
                    input_tokens: 9,
                    output_tokens: 2,
                    cached_input_tokens: 0,
                    reasoning_tokens: 0,
                }),
                StreamEvent::Completed {
                    finish_reason: FinishReason::Stop,
                    usage: Usage {
                        input_tokens: 9,
                        output_tokens: 2,
                        cached_input_tokens: 0,
                        reasoning_tokens: 0,
                    },
                },
            ]
        );
    }

    #[test]
    fn a_recorded_tool_call_stream_assembles_fragmented_arguments() {
        let body = concat!(
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"ci\"}}]}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ty\\\":\\\"Oslo\\\"}\"}}]}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let events = decode_event_stream("openai", body.as_bytes()).expect("decode");
        assert_eq!(
            events,
            vec![
                StreamEvent::Started {
                    id: "c".to_owned(),
                    model: "m".to_owned(),
                },
                StreamEvent::ToolCallStarted {
                    index: 0,
                    id: "call_1".to_owned(),
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
                        id: "call_1".to_owned(),
                        name: "get_weather".to_owned(),
                        arguments: ToolArguments::new(r#"{"city":"Oslo"}"#).expect("arguments"),
                    },
                },
                StreamEvent::Completed {
                    finish_reason: FinishReason::ToolCalls,
                    usage: Usage::default(),
                },
            ]
        );
    }

    #[test]
    fn parallel_tool_calls_are_assembled_independently() {
        let body = concat!(
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"a\",\"function\":{\"name\":\"f\",\"arguments\":\"{\\\"x\\\":1\"}},{\"index\":1,\"id\":\"b\",\"function\":{\"name\":\"g\",\"arguments\":\"{\\\"y\\\":\"}}]}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"function\":{\"arguments\":\"2}\"}},{\"index\":0,\"function\":{\"arguments\":\"}\"}}]}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let events = decode_event_stream("openai", body.as_bytes()).expect("decode");
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
    fn reasoning_deltas_are_reported_separately_from_text() {
        let body = concat!(
            "data: {\"id\":\"c\",\"model\":\"deepseek-reasoner\",\"choices\":[{\"delta\":{\"reasoning_content\":\"think\"}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"deepseek-reasoner\",\"choices\":[{\"delta\":{\"content\":\"answer\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let events = decode_event_stream("deepseek", body.as_bytes()).expect("decode");
        assert_eq!(
            events,
            vec![
                StreamEvent::Started {
                    id: "c".to_owned(),
                    model: "deepseek-reasoner".to_owned(),
                },
                StreamEvent::ReasoningDelta("think".to_owned()),
                StreamEvent::TextDelta("answer".to_owned()),
                StreamEvent::Completed {
                    finish_reason: FinishReason::Stop,
                    usage: Usage::default(),
                },
            ]
        );
    }

    #[test]
    fn a_stream_that_ends_without_the_done_sentinel_still_completes() {
        let body = concat!(
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}]}\n\n",
        );
        let events = decode_event_stream("openai", body.as_bytes()).expect("decode");
        assert_eq!(
            events.last(),
            Some(&StreamEvent::Completed {
                finish_reason: FinishReason::Length,
                usage: Usage::default(),
            })
        );
    }

    #[test]
    fn every_chunk_split_of_a_recorded_stream_yields_identical_events() {
        let body = concat!(
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"alpha\"}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"beta\"}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        )
        .as_bytes();
        let expected = decode_event_stream("openai", body).expect("decode");
        for split in 1..body.len() {
            let mut sse = SseDecoder::new();
            let mut decoder = OpenAiStreamDecoder::new("openai");
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
    fn a_malformed_chunk_is_reported_as_a_protocol_error() {
        let error = decode_event_stream("openai", b"data: {not json}\n\n").expect_err("malformed");
        assert_eq!(error.kind(), ErrorKind::Protocol);
        assert_eq!(error.operation(), Operation::StreamCompletion);
        assert_eq!(error.provider(), "openai");
    }

    #[test]
    fn building_a_client_for_an_unregistered_provider_is_unsupported() {
        let error = OpenAiCompatible::from_registry("not-a-provider", None, None)
            .expect_err("unknown provider");
        assert_eq!(error.kind(), ErrorKind::Unsupported);
        assert_eq!(error.detail(), "no such provider is registered");
    }

    #[test]
    fn building_a_client_for_another_dialect_is_unsupported() {
        let error = OpenAiCompatible::from_registry("anthropic", Some(ApiKey::new("k")), None)
            .expect_err("wrong dialect");
        assert_eq!(error.kind(), ErrorKind::Unsupported);
        assert_eq!(
            error.detail(),
            "this provider does not speak the OpenAI chat-completions dialect"
        );
    }

    #[test]
    fn a_provider_without_a_default_endpoint_requires_an_explicit_base_url() {
        let error = OpenAiCompatible::from_registry("kimi", Some(ApiKey::new("k")), None)
            .expect_err("no endpoint");
        assert_eq!(error.kind(), ErrorKind::InvalidRequest);
        assert_eq!(
            error.detail(),
            "this provider ships no default endpoint, so a base URL is required"
        );

        let client = OpenAiCompatible::from_registry(
            "kimi",
            Some(ApiKey::new("k")),
            Some("https://api.moonshot.cn/v1".parse().expect("url")),
        )
        .expect("explicit endpoint");
        assert_eq!(client.base_url().as_str(), "https://api.moonshot.cn/v1");
        assert!(!client.stream_usage());
    }

    #[test]
    fn a_credentialed_provider_rejects_a_missing_key() {
        let error = OpenAiCompatible::from_registry("openai", None, None).expect_err("no key");
        assert_eq!(error.kind(), ErrorKind::Authentication);
        assert_eq!(error.operation(), Operation::Authorize);
        assert_eq!(error.detail(), "this provider requires an API key");
    }

    #[test]
    fn openai_opts_into_stream_usage_and_local_runtimes_need_no_key() {
        let openai =
            OpenAiCompatible::from_registry("openai", Some(ApiKey::new("k")), None).expect("build");
        assert!(openai.stream_usage());
        assert_eq!(openai.base_url().as_str(), "https://api.openai.com/v1");
        assert_eq!(openai.id().as_str(), "openai");
        assert!(openai.capabilities().contains(Capability::Embeddings));

        let ollama = OpenAiCompatible::from_registry("ollama", None, None).expect("build");
        assert!(!ollama.stream_usage());
        assert_eq!(ollama.base_url().as_str(), "http://127.0.0.1:11434/v1");
        assert_eq!(ollama.auth_style(), &AuthStyle::None);
    }

    #[test]
    fn endpoints_are_joined_without_duplicating_the_separator() {
        let client = OpenAiCompatible::from_registry(
            "groq",
            Some(ApiKey::new("k")),
            Some("https://example.invalid/v1/".parse().expect("url")),
        )
        .expect("build");
        assert_eq!(
            client.endpoint("chat/completions").expect("join").as_str(),
            "https://example.invalid/v1/chat/completions"
        );
        assert_eq!(
            client.endpoint("models").expect("join").as_str(),
            "https://example.invalid/v1/models"
        );
    }

    #[test]
    fn the_authorization_header_is_redacted_in_debug_output() {
        let client =
            OpenAiCompatible::from_registry("openai", Some(ApiKey::new("sk-super-secret")), None)
                .expect("build");
        let request = client.request(
            Method::Post,
            "https://api.openai.com/v1/chat/completions"
                .parse()
                .expect("url"),
        );
        let rendered = format!("{request:?}");
        assert!(
            !rendered.contains("sk-super-secret"),
            "debug output leaked the key: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            !format!("{client:?}").contains("sk-super-secret"),
            "client debug output leaked the key"
        );
        assert_eq!(request.header_names(), vec!["accept", "authorization"]);
    }

    #[test]
    fn the_default_endpoint_predicate_matches_the_registry() {
        assert!(has_default_endpoint("openai"));
        assert!(has_default_endpoint("groq"));
        assert!(!has_default_endpoint("kimi"));
        assert!(!has_default_endpoint("not-a-provider"));
    }
}

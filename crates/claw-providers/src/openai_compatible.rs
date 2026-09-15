//! The `OpenAI` `chat/completions` dialect.
//!
//! This module implements the wire protocol shared by `OpenAI` and the many
//! services that reproduce it: chat completions (buffered and streamed),
//! function calling, embeddings and model listing.
//!
//! Encoding and decoding are pure functions over `&str`/`&[u8]`, so every wire
//! behaviour in this module is tested against recorded byte fixtures without a
//! network.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
use claw_provider_sdk::origin::{BoundApiKey, Origin, OriginApproval, OriginError};
use claw_provider_sdk::provider::{
    BoxFuture, Provider, ProviderPhase, ProviderStatus, RequestContext,
};
use claw_provider_sdk::secret::ApiKey;
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
const MAX_COMPLETION_BODY_BYTES: usize = 8 * 1024 * 1024;

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

/// Explicitly selected completion wire protocol; no endpoint fallback is attempted.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CompletionDialect {
    /// The default `chat/completions` protocol.
    #[default]
    ChatCompletions,
    /// Stateless `responses` requests with server-side storage disabled.
    Responses,
}

impl CompletionDialect {
    const fn path(self) -> &'static str {
        match self {
            Self::ChatCompletions => "chat/completions",
            Self::Responses => "responses",
        }
    }
}

/// Configuration of one OpenAI-compatible endpoint.
#[derive(Debug)]
pub struct OpenAiConfig {
    /// Frozen provider identifier used in errors and metrics.
    pub provider: ProviderId,
    /// Base URL that `chat/completions` is appended to.
    pub base_url: Url,
    /// Credential, when the service requires one.
    ///
    /// The credential carries the origin it was authorised for.
    /// [`OpenAiCompatible::new`] rejects a configuration whose `base_url` is on
    /// a different origin, so changing the endpoint cannot silently redirect a
    /// stored key to another host.
    pub api_key: Option<BoundApiKey>,
    /// How the credential is presented.
    pub auth: AuthStyle,
    /// Extra non-secret headers sent with every request.
    pub extra_headers: Vec<(String, String)>,
    /// Capabilities the caller may exercise.
    pub capabilities: CapabilitySet,
    /// Whether to ask for usage accounting in streamed responses.
    ///
    /// `OpenAI` only reports token usage in a stream when
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
    api_key: Option<BoundApiKey>,
    auth: AuthStyle,
    extra_headers: Vec<(String, String)>,
    capabilities: CapabilitySet,
    stream_usage: bool,
    completion_dialect: CompletionDialect,
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
            && config
                .api_key
                .as_ref()
                .is_none_or(|key| key.for_url(&config.base_url).is_ok_and(ApiKey::is_empty))
        {
            return Err(ProviderError::new(
                ErrorKind::Authentication,
                config.provider.as_str(),
                Operation::Authorize,
                "this provider requires an API key",
            ));
        }
        // Credential and destination must agree here, not at send time, so a
        // mismatched pair can never become a live client.
        if let Some(key) = config.api_key.as_ref()
            && let Err(error) = key.for_url(&config.base_url)
        {
            return Err(ProviderError::new(
                ErrorKind::Authentication,
                config.provider.as_str(),
                Operation::Authorize,
                format!(
                    "the configured endpoint is not the one this credential authorises: {error}"
                ),
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
            completion_dialect: CompletionDialect::default(),
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
    ///
    /// Returns [`ErrorKind::Authentication`] when `base_url` names an origin
    /// other than the registered default. Overriding the endpoint of a
    /// registered provider is how a tampered configuration would redirect a
    /// stored credential, so it is refused here and must go through
    /// [`OpenAiCompatible::from_registry_with_enrolled_origin`] instead.
    pub fn from_registry(
        id: &str,
        api_key: Option<ApiKey>,
        base_url: Option<Url>,
    ) -> Result<Self, ProviderError> {
        Self::from_registry_inner(id, api_key, base_url, None)
    }

    /// Builds a client for a registered provider at an operator-enrolled origin.
    ///
    /// This is the deliberate path for self-hosted and enterprise deployments.
    /// The [`OriginApproval`] must be produced where a human chose to trust the
    /// endpoint; deriving one from the same configuration field that supplies
    /// `base_url` reintroduces the very redirect this guards against.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Authentication`] when `base_url` is not on the
    /// enrolled origin, plus the errors of [`OpenAiCompatible::from_registry`].
    pub fn from_registry_with_enrolled_origin(
        id: &str,
        api_key: Option<ApiKey>,
        base_url: Url,
        approval: &OriginApproval,
    ) -> Result<Self, ProviderError> {
        Self::from_registry_inner(id, api_key, Some(base_url), Some(approval))
    }

    fn from_registry_inner(
        id: &str,
        api_key: Option<ApiKey>,
        base_url: Option<Url>,
        approval: Option<&OriginApproval>,
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
        let registered = descriptor
            .base_url
            .map(|default| {
                default.parse::<Url>().map_err(|_| {
                    ProviderError::new(
                        ErrorKind::InvalidRequest,
                        id,
                        Operation::Authorize,
                        "the registered base URL is not a valid URL",
                    )
                })
            })
            .transpose()?;
        // The operator's endpoint wins; the registered default is only cloned
        // when it is actually the one being used, because `registered` is still
        // needed below to build the trust set.
        let base_url = match base_url {
            Some(url) => url,
            None => registered.clone().ok_or_else(|| {
                ProviderError::new(
                    ErrorKind::InvalidRequest,
                    id,
                    Operation::Authorize,
                    "this provider ships no default endpoint, so a base URL is required",
                )
            })?,
        };

        // The set of origins this provider may present its credential to: the
        // registered default, plus whatever the operator explicitly enrolled.
        let mut trusted = Vec::new();
        if let Some(default) = registered.as_ref() {
            trusted.push(Origin::of(default).map_err(|error| {
                ProviderError::new(
                    ErrorKind::InvalidRequest,
                    id,
                    Operation::Authorize,
                    format!("the registered base URL names no usable origin: {error}"),
                )
            })?);
        }
        if let Some(approval) = approval {
            trusted.push(approval.origin().clone());
        }
        let origin = Origin::of(&base_url).map_err(|error| {
            ProviderError::new(
                ErrorKind::Authentication,
                id,
                Operation::Authorize,
                format!("the endpoint names no usable origin: {error}"),
            )
        })?;
        if !trusted.contains(&origin) {
            let known = if trusted.is_empty() {
                "this provider ships no default endpoint".to_owned()
            } else {
                format!(
                    "the trusted origins are {}",
                    trusted
                        .iter()
                        .map(Origin::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            return Err(ProviderError::new(
                ErrorKind::Authentication,
                id,
                Operation::Authorize,
                format!(
                    "refusing to send this provider's credential to {origin}: {known}, so the \
                     endpoint must be enrolled explicitly",
                ),
            ));
        }

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
            api_key: api_key.map(|key| BoundApiKey::new(origin, key)),
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

    /// Selects the completion dialect without changing the enrolled credential origin.
    #[must_use]
    pub const fn with_completion_dialect(mut self, dialect: CompletionDialect) -> Self {
        self.completion_dialect = dialect;
        self
    }

    /// Returns the explicitly selected completion protocol.
    #[must_use]
    pub const fn completion_dialect(&self) -> CompletionDialect {
        self.completion_dialect
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
        let mut request = HttpRequest::new(method, url).header("accept", "application/json");
        // A bound credential can only be read back out for a URL on its own
        // origin, so a base URL pointing elsewhere fails here instead of
        // shipping the key to that host.
        request = match (&self.auth, self.api_key.as_ref()) {
            (AuthStyle::Header(name), Some(key)) => request
                .credential_header(name.clone(), key)
                .map_err(|error| self.origin_error(&error))?,
            (AuthStyle::None | AuthStyle::Header(_), _) | (_, None) => request,
            (_, Some(key)) => request
                .bearer(key)
                .map_err(|error| self.origin_error(&error))?,
        };
        for (name, value) in &self.extra_headers {
            request = request.header(name.clone(), value.clone());
        }
        Ok(request)
    }

    /// Reports a credential that is not authorised for the endpoint in use.
    fn origin_error(&self, error: &OriginError) -> ProviderError {
        ProviderError::new(
            ErrorKind::Authentication,
            self.id.as_str(),
            Operation::Authorize,
            format!("the credential is not authorised for this endpoint: {error}"),
        )
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

    async fn probe(
        &self,
        operation: Operation,
        phase: ProviderPhase,
        context: &RequestContext,
    ) -> Result<ProviderStatus, ProviderError> {
        let url = self.endpoint("models")?;
        self.runtime
            .execute(operation, context.cancel(), || {
                self.request(Method::Get, url.clone())
            })
            .await?;
        Ok(ProviderStatus::new(self.id.clone(), phase))
    }
}

impl Provider for OpenAiCompatible {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> CapabilitySet {
        self.capabilities
    }

    fn startup<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<ProviderStatus, ProviderError>> {
        Box::pin(self.probe(Operation::Startup, ProviderPhase::Started, context))
    }

    fn ping<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<ProviderStatus, ProviderError>> {
        Box::pin(self.probe(Operation::Ping, ProviderPhase::Reachable, context))
    }

    fn complete<'a>(
        &'a self,
        request: &'a CompletionRequest,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<CompletionResponse, ProviderError>> {
        Box::pin(async move {
            self.check_capability(Capability::Completion, Operation::Complete)?;
            validate(self.id.as_str(), request, Operation::Complete)?;
            let url = self.endpoint(self.completion_dialect.path())?;
            let body = match self.completion_dialect {
                CompletionDialect::ChatCompletions => encode_completion(request, false, false)?,
                CompletionDialect::Responses => {
                    crate::responses::encode_completion(self.id.as_str(), request, false)?
                }
            };
            self.runtime
                .execute_decoded(
                    Operation::Complete,
                    context.cancel(),
                    || {
                        Ok(self
                            .request(Method::Post, url.clone())?
                            .body(Body::Json(body.clone())))
                    },
                    |response| match self.completion_dialect {
                        CompletionDialect::ChatCompletions => {
                            decode_completion(self.id.as_str(), response.body())
                        }
                        CompletionDialect::Responses => {
                            crate::responses::decode_completion(self.id.as_str(), response.body())
                        }
                    },
                )
                .await
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
            let dialect = self.completion_dialect;
            let url = self.endpoint(dialect.path())?;
            let body = match dialect {
                CompletionDialect::ChatCompletions => {
                    encode_completion(request, true, self.stream_usage)?
                }
                CompletionDialect::Responses => {
                    crate::responses::encode_completion(self.id.as_str(), request, true)?
                }
            };
            let cancel = context.cancel().clone();
            let provider = self.id.as_str().to_owned();
            let events = self
                .runtime
                .execute_streaming(Operation::StreamCompletion, &cancel, || {
                    Ok(self
                        .request(Method::Post, url.clone())?
                        .replace_header("accept", "text/event-stream")
                        .body(Body::Json(body.clone())))
                })
                .await?
                .decode(move |chunks| match dialect {
                    CompletionDialect::ChatCompletions => event_stream(provider, chunks),
                    CompletionDialect::Responses => {
                        crate::responses::event_stream(provider, chunks)
                    }
                });
            Ok(CompletionStream::new(self.id.as_str(), cancel, events))
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
            self.runtime
                .execute_decoded(
                    Operation::Embed,
                    context.cancel(),
                    || {
                        Ok(self
                            .request(Method::Post, url.clone())?
                            .body(Body::Json(body.clone())))
                    },
                    |response| decode_embeddings(self.id.as_str(), response.body()),
                )
                .await
        })
    }

    fn list_models<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<Vec<ModelDescriptor>, ProviderError>> {
        Box::pin(async move {
            self.check_capability(Capability::ModelListing, Operation::ListModels)?;
            let url = self.endpoint("models")?;
            self.runtime
                .execute_decoded(
                    Operation::ListModels,
                    context.cancel(),
                    || self.request(Method::Get, url.clone()),
                    |response| decode_models(self.id.as_str(), response.body()),
                )
                .await
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
const fn is_false(value: &bool) -> bool {
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

/// Encodes a completion request as an `OpenAI` `chat/completions` document.
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
    prompt_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
    #[serde(default)]
    prompt_tokens_details: Option<WirePromptDetails>,
    #[serde(default)]
    completion_tokens_details: Option<WireCompletionDetails>,
}

#[derive(Debug, Deserialize)]
struct WirePromptDetails {
    #[serde(default)]
    cached_tokens: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct WireCompletionDetails {
    #[serde(default)]
    reasoning_tokens: Option<u64>,
}

impl WireUsage {
    const fn reporting(&self) -> claw_provider_sdk::model::UsageReporting {
        if self.prompt_tokens.is_some() && self.completion_tokens.is_some() {
            claw_provider_sdk::model::UsageReporting::Complete
        } else {
            claw_provider_sdk::model::UsageReporting::Partial
        }
    }

    fn validated(
        self,
        previous: Usage,
        provider: &str,
        operation: Operation,
    ) -> Result<Usage, ProviderError> {
        let usage = Usage {
            input_tokens: self.prompt_tokens.unwrap_or(previous.input_tokens),
            output_tokens: self.completion_tokens.unwrap_or(previous.output_tokens),
            cached_input_tokens: self
                .prompt_tokens_details
                .and_then(|details| details.cached_tokens)
                .unwrap_or(previous.cached_input_tokens),
            reasoning_tokens: self
                .completion_tokens_details
                .and_then(|details| details.reasoning_tokens)
                .unwrap_or(previous.reasoning_tokens),
        };
        let total = usage.input_tokens.checked_add(usage.output_tokens);
        if total.is_none()
            || self
                .total_tokens
                .is_some_and(|reported| Some(reported) != total)
            || usage.cached_input_tokens > usage.input_tokens
            || usage.reasoning_tokens > usage.output_tokens
            || usage.input_tokens < previous.input_tokens
            || usage.output_tokens < previous.output_tokens
            || usage.cached_input_tokens < previous.cached_input_tokens
            || usage.reasoning_tokens < previous.reasoning_tokens
        {
            return Err(protocol_error(
                provider,
                operation,
                "completion usage is inconsistent, regressed or overflowing",
            ));
        }
        Ok(usage)
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
    index: usize,
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

fn valid_wire_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= claw_provider_sdk::stream::MAX_TOOL_NAME_BYTES
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

/// Maps an `OpenAI` `finish_reason` onto the portable enumeration.
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
    if body.len() > MAX_COMPLETION_BODY_BYTES {
        return Err(protocol_error(
            provider,
            Operation::Complete,
            "completion body exceeds its byte limit",
        ));
    }
    let wire: WireCompletionResponse = serde_json::from_slice(body).map_err(|error| {
        protocol_error(
            provider,
            Operation::Complete,
            &format!("the completion response could not be parsed: {error}"),
        )
    })?;
    if wire.choices.len() > 1 || wire.choices.first().is_some_and(|choice| choice.index != 0) {
        return Err(protocol_error(
            provider,
            Operation::Complete,
            "completion must contain exactly the requested choice zero",
        ));
    }
    let choice = wire.choices.into_iter().next().ok_or_else(|| {
        protocol_error(
            provider,
            Operation::Complete,
            "the completion response carried no choices",
        )
    })?;
    if choice.message.tool_calls.len() > claw_provider_sdk::stream::MAX_TOOL_CALLS {
        return Err(protocol_error(
            provider,
            Operation::Complete,
            "completion function count exceeds its limit",
        ));
    }
    let reasoning = choice
        .message
        .reasoning_content
        .or(choice.message.reasoning)
        .filter(|text| !text.is_empty());
    let mut output_bytes = choice
        .message
        .content
        .as_ref()
        .map_or(0, String::len)
        .saturating_add(reasoning.as_ref().map_or(0, String::len));
    if output_bytes > claw_provider_sdk::stream::MAX_TOTAL_TOOL_ARGUMENT_BYTES {
        return Err(protocol_error(
            provider,
            Operation::Complete,
            "completion output exceeds its aggregate byte limit",
        ));
    }
    let mut content = Vec::new();
    if let Some(text) = choice.message.content.filter(|text| !text.is_empty()) {
        content.push(ContentPart::Text(text));
    }
    let mut tool_calls = Vec::with_capacity(choice.message.tool_calls.len());
    let mut call_ids = BTreeSet::new();
    for call in choice.message.tool_calls {
        output_bytes = output_bytes.saturating_add(call.function.arguments.len());
        if output_bytes > claw_provider_sdk::stream::MAX_TOTAL_TOOL_ARGUMENT_BYTES
            || call.function.arguments.len() > claw_provider_sdk::stream::MAX_TOOL_ARGUMENT_BYTES
        {
            return Err(protocol_error(
                provider,
                Operation::Complete,
                "completion function arguments exceed their byte limit",
            ));
        }
        if !valid_wire_identifier(&call.id)
            || !valid_wire_identifier(&call.function.name)
            || !call_ids.insert(call.id.clone())
        {
            return Err(protocol_error(
                provider,
                Operation::Complete,
                "completion function identities are invalid or duplicated",
            ));
        }
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
    if (!tool_calls.is_empty() && !matches!(finish, FinishReason::Stop | FinishReason::ToolCalls))
        || (tool_calls.is_empty() && finish == FinishReason::ToolCalls)
    {
        return Err(protocol_error(
            provider,
            Operation::Complete,
            "completion finish reason is inconsistent with its function calls",
        ));
    }
    Ok(CompletionResponse {
        id: wire.id,
        model,
        message: AssistantMessage {
            content,
            reasoning,
            tool_calls,
        },
        finish_reason: finish,
        usage_reporting: wire.usage.as_ref().map_or(
            claw_provider_sdk::model::UsageReporting::Unreported,
            WireUsage::reporting,
        ),
        usage: wire
            .usage
            .map(|usage| usage.validated(Usage::default(), provider, Operation::Complete))
            .transpose()?
            .unwrap_or_default(),
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
        usage: wire
            .usage
            .map(|usage| usage.validated(Usage::default(), provider, Operation::Embed))
            .transpose()?
            .unwrap_or_default(),
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
/// The `OpenAI` model catalogue publishes no capability, context-window or
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
    index: usize,
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

#[derive(Debug, Default)]
struct PrimaryUsageFields {
    input: bool,
    output: bool,
}

/// Turns `OpenAI` stream chunks into portable [`StreamEvent`] values.
///
/// The decoder is a pure state machine over already-framed SSE events, so it can
/// be driven directly from a recorded byte fixture.
#[derive(Debug)]
pub struct OpenAiStreamDecoder {
    provider: String,
    assembler: ToolCallAssembler,
    started: bool,
    response_id: String,
    response_model: String,
    call_ids: BTreeMap<usize, String>,
    output_bytes: usize,
    usage: Usage,
    usage_fields: PrimaryUsageFields,
    finish_reason: Option<FinishReason>,
    completed: bool,
    done_seen: bool,
}

impl OpenAiStreamDecoder {
    /// Creates a decoder that reports errors as coming from `provider`.
    #[must_use]
    pub fn new(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            assembler: ToolCallAssembler::new(),
            started: false,
            response_id: String::new(),
            response_model: String::new(),
            call_ids: BTreeMap::new(),
            output_bytes: 0,
            usage: Usage::default(),
            usage_fields: PrimaryUsageFields::default(),
            finish_reason: None,
            completed: false,
            done_seen: false,
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
            if !self.started {
                return Err(protocol_error(
                    &self.provider,
                    Operation::StreamCompletion,
                    "completion ended before a response was identified",
                ));
            }
            self.done_seen = true;
            return self.finish_checked();
        }
        let chunk: WireStreamChunk = serde_json::from_str(data).map_err(|error| {
            protocol_error(
                &self.provider,
                Operation::StreamCompletion,
                &format!("a stream chunk could not be parsed: {error}"),
            )
        })?;
        if chunk.choices.len() > 1
            || chunk.choices.iter().any(|choice| choice.index != 0)
            || (self.finish_reason.is_some() && !chunk.choices.is_empty())
        {
            return Err(protocol_error(
                &self.provider,
                Operation::StreamCompletion,
                "completion stream changed or repeated its finished choice",
            ));
        }
        if self.started {
            if (!chunk.id.is_empty() && chunk.id != self.response_id)
                || (!chunk.model.is_empty() && chunk.model != self.response_model)
            {
                return Err(protocol_error(
                    &self.provider,
                    Operation::StreamCompletion,
                    "completion stream response identity changed",
                ));
            }
        } else if !valid_wire_identifier(&chunk.id) || ModelId::new(chunk.model.clone()).is_err() {
            return Err(protocol_error(
                &self.provider,
                Operation::StreamCompletion,
                "completion stream did not identify a valid response and model",
            ));
        }
        let mut events = Vec::new();
        if !self.started {
            self.started = true;
            self.response_id.clone_from(&chunk.id);
            self.response_model.clone_from(&chunk.model);
            events.push(StreamEvent::Started {
                id: chunk.id,
                model: chunk.model,
            });
        }
        if let Some(usage) = chunk.usage {
            let input_reported = usage.prompt_tokens.is_some();
            let output_reported = usage.completion_tokens.is_some();
            self.usage =
                usage.validated(self.usage, &self.provider, Operation::StreamCompletion)?;
            self.usage_fields.input |= input_reported;
            self.usage_fields.output |= output_reported;
            events.push(StreamEvent::UsageReported {
                usage: self.usage,
                reporting: if self.usage_fields.input && self.usage_fields.output {
                    claw_provider_sdk::model::UsageReporting::Complete
                } else {
                    claw_provider_sdk::model::UsageReporting::Partial
                },
            });
        }
        for choice in chunk.choices {
            if let Some(text) = choice.delta.content.filter(|text| !text.is_empty()) {
                self.add_output_bytes(text.len())?;
                events.push(StreamEvent::TextDelta(text));
            }
            if let Some(text) = choice
                .delta
                .reasoning_content
                .or(choice.delta.reasoning)
                .filter(|text| !text.is_empty())
            {
                self.add_output_bytes(text.len())?;
                events.push(StreamEvent::ReasoningDelta(text));
            }
            for call in choice.delta.tool_calls {
                if call.index >= claw_provider_sdk::stream::MAX_TOOL_CALLS {
                    return Err(protocol_error(
                        &self.provider,
                        Operation::StreamCompletion,
                        "completion stream function index exceeds its limit",
                    ));
                }
                if let Some(id) = call.id.as_deref().filter(|id| !id.is_empty()) {
                    if !valid_wire_identifier(id)
                        || self
                            .call_ids
                            .get(&call.index)
                            .is_some_and(|previous| previous != id)
                        || self
                            .call_ids
                            .iter()
                            .any(|(index, previous)| *index != call.index && previous == id)
                    {
                        return Err(protocol_error(
                            &self.provider,
                            Operation::StreamCompletion,
                            "completion stream function identity changed or was duplicated",
                        ));
                    }
                    self.call_ids.insert(call.index, id.to_owned());
                }
                let (name, arguments) = call
                    .function
                    .map_or((None, None), |function| (function.name, function.arguments));
                self.add_output_bytes(arguments.as_ref().map_or(0, String::len))?;
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
    /// last argument fragment only by ending the stream. Legacy direct callers
    /// receive an `incomplete_stream` terminal on error; live and recorded streams
    /// surface typed protocol errors instead.
    #[must_use]
    pub fn finish(&mut self) -> Vec<StreamEvent> {
        self.finish_checked().unwrap_or_else(|_| {
            vec![StreamEvent::Completed {
                finish_reason: FinishReason::Other("incomplete_stream".to_owned()),
                usage: self.usage,
            }]
        })
    }

    fn add_output_bytes(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.output_bytes = self.output_bytes.saturating_add(bytes);
        if self.output_bytes > claw_provider_sdk::stream::MAX_TOTAL_TOOL_ARGUMENT_BYTES {
            return Err(protocol_error(
                &self.provider,
                Operation::StreamCompletion,
                "completion stream exceeds its aggregate output byte limit",
            ));
        }
        Ok(())
    }

    fn finish_checked(&mut self) -> Result<Vec<StreamEvent>, ProviderError> {
        if self.completed {
            return Ok(Vec::new());
        }
        self.completed = true;
        if !self.started || (!self.done_seen && self.finish_reason.is_none()) {
            return Err(protocol_error(
                &self.provider,
                Operation::StreamCompletion,
                "completion stream ended without a finish reason or DONE marker",
            ));
        }
        let mut events = Vec::new();
        let pending = self.assembler.len();
        if pending == 0 && self.finish_reason == Some(FinishReason::ToolCalls) {
            return Err(protocol_error(
                &self.provider,
                Operation::StreamCompletion,
                "completion stream requested functions without any calls",
            ));
        }
        if pending > 0
            && self.finish_reason.as_ref().is_some_and(|reason| {
                !matches!(reason, FinishReason::Stop | FinishReason::ToolCalls)
            })
        {
            return Err(protocol_error(
                &self.provider,
                Operation::StreamCompletion,
                "completion stream stopped before its function calls completed",
            ));
        }
        for index in 0..pending {
            let event = self.assembler.complete(index).map_err(|_| {
                protocol_error(
                    &self.provider,
                    Operation::StreamCompletion,
                    "completion stream contains an invalid or incomplete function call",
                )
            })?;
            if let StreamEvent::ToolCallCompleted { call, .. } = &event
                && (!valid_wire_identifier(&call.id) || !valid_wire_identifier(&call.name))
            {
                return Err(protocol_error(
                    &self.provider,
                    Operation::StreamCompletion,
                    "completion stream function identity is invalid",
                ));
            }
            events.push(event);
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
        Ok(events)
    }

    fn end_of_input(&mut self) -> Result<Vec<StreamEvent>, ProviderError> {
        self.finish_checked()
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
    events.extend(decoder.end_of_input()?);
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
    pending: VecDeque<Result<StreamEvent, ProviderError>>,
    exhausted: bool,
}

pub(crate) fn event_stream(provider: String, chunks: ChunkStream) -> EventStream {
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
                    return Some((event, (state, provider)));
                }
                if state.exhausted {
                    return None;
                }
                match state.chunks.next().await {
                    Some(Ok(bytes)) => match state.sse.push(&bytes) {
                        Ok(framed) => {
                            for event in framed {
                                match state.decoder.accept(&event) {
                                    Ok(events) => {
                                        state.pending.extend(events.into_iter().map(Ok));
                                        if state.decoder.completed {
                                            state.exhausted = true;
                                            break;
                                        }
                                    }
                                    Err(error) => {
                                        state.exhausted = true;
                                        state.pending.push_back(Err(error));
                                        break;
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
                                        Ok(events) => {
                                            state.pending.extend(events.into_iter().map(Ok));
                                        }
                                        Err(error) => {
                                            state.pending.push_back(Err(error));
                                            break;
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
                        if !state.pending.iter().any(Result::is_err) {
                            match state.decoder.end_of_input() {
                                Ok(tail) => state.pending.extend(tail.into_iter().map(Ok)),
                                Err(error) => state.pending.push_back(Err(error)),
                            }
                        }
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
                StreamEvent::UsageReported {
                    usage: Usage {
                        input_tokens: 9,
                        output_tokens: 2,
                        cached_input_tokens: 0,
                        reasoning_tokens: 0,
                    },
                    reporting: claw_provider_sdk::model::UsageReporting::Complete,
                },
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
    fn unmarked_eof_and_empty_done_do_not_fabricate_completed_answers_or_tools() {
        for body in [
            "",
            "data: [DONE]\n\n",
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"partial answer\"}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call-1\",\"function\":{\"name\":\"mutate\",\"arguments\":\"{}\"}}]}}]}\n\n",
        ] {
            let error = decode_event_stream("openai", body.as_bytes())
                .expect_err("missing completion witness");
            assert_eq!(error.kind(), ErrorKind::Protocol);
            assert!(!error.detail().contains("partial answer"));
        }
        let mut decoder = OpenAiStreamDecoder::new("openai");
        assert!(
            matches!(decoder.finish().as_slice(), [StreamEvent::Completed { finish_reason: FinishReason::Other(reason), .. }] if reason == "incomplete_stream")
        );
    }

    #[tokio::test]
    async fn live_stream_preserves_partial_text_but_rejects_unmarked_eof() {
        let body = Bytes::from_static(b"data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"partial answer\"}}]}\n\n");
        let mut events = events_from_chunks(
            "openai",
            CancelToken::new(),
            Box::pin(futures_util::stream::iter([Ok(body)])),
        );
        assert!(matches!(
            events.next().await,
            Some(Ok(StreamEvent::Started { .. }))
        ));
        assert_eq!(
            events.next().await.expect("partial text").expect("text"),
            StreamEvent::TextDelta("partial answer".to_owned())
        );
        assert_eq!(
            events
                .next()
                .await
                .expect("terminal error")
                .expect_err("not a completed answer")
                .kind(),
            ErrorKind::Protocol
        );
        assert!(events.next().await.is_none());
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

    #[tokio::test]
    async fn live_stream_rejects_incomplete_tool_rounds_without_publishing_partial_calls() {
        for (arguments, finish) in [
            ("{", "tool_calls"),
            ("{}", "length"),
            ("{}", "content_filter"),
        ] {
            let chunk = serde_json::json!({"id":"owned-response","model":"owned-model","choices":[{"delta":{"tool_calls":[
                {"index":0,"id":"first","function":{"name":"read","arguments":"{}"}},
                {"index":1,"id":"second","function":{"name":"write","arguments":arguments}}
            ]},"finish_reason":finish}]});
            let body = Bytes::from(format!("data: {chunk}\n\ndata: [DONE]\n\n"));
            let mut stream = events_from_chunks(
                "openai",
                CancelToken::new(),
                Box::pin(futures_util::stream::iter([Ok(body)])),
            );
            let mut failed = false;
            while let Some(event) = stream.next().await {
                match event {
                    Ok(StreamEvent::ToolCallCompleted { .. } | StreamEvent::Completed { .. }) => {
                        panic!("incomplete round must not publish completion")
                    }
                    Err(error) => {
                        assert_eq!(error.kind(), ErrorKind::Protocol);
                        failed = true;
                    }
                    _ => {}
                }
            }
            assert!(failed);
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
    fn chat_completion_rejects_duplicate_function_ids_and_unrequested_choices() {
        let base = serde_json::json!({"id":"owned-response","model":"owned-model","choices":[{"index":0,"finish_reason":"tool_calls","message":{"tool_calls":[
            {"id":"first","function":{"name":"lookup","arguments":"{}"}},
            {"id":"second","function":{"name":"lookup","arguments":"{}"}}
        ]}}]});
        assert!(decode_completion("openai", base.to_string().as_bytes()).is_ok());
        for (pointer, value) in [
            (
                "/choices/0/message/tool_calls/1/id",
                serde_json::json!("first"),
            ),
            ("/choices/0/message/tool_calls/1/id", serde_json::json!("")),
            (
                "/choices/0/message/tool_calls/1/function/name",
                serde_json::json!("invalid name"),
            ),
            ("/choices/0/finish_reason", serde_json::json!("length")),
            ("/choices/0/index", serde_json::json!(1)),
        ] {
            let mut changed = base.clone();
            *changed.pointer_mut(pointer).expect("field") = value;
            assert_eq!(
                decode_completion("openai", changed.to_string().as_bytes())
                    .expect_err("inconsistent completion")
                    .kind(),
                ErrorKind::Protocol
            );
        }
        let mut changed = base;
        let duplicate = changed["choices"][0].clone();
        changed["choices"]
            .as_array_mut()
            .expect("choices")
            .push(duplicate);
        assert!(decode_completion("openai", changed.to_string().as_bytes()).is_err());
    }

    #[test]
    fn chat_stream_rejects_changed_identity_choice_and_function_ids() {
        let first = serde_json::json!({"id":"owned-response","model":"owned-model","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-owned","function":{"name":"lookup","arguments":"{"}}]}}]});
        let second = serde_json::json!({"id":"owned-response","model":"owned-model","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"}"}}]},"finish_reason":"tool_calls"}]});
        let encode = |second: &serde_json::Value| {
            format!("data: {first}\n\ndata: {second}\n\ndata: [DONE]\n\n")
        };
        assert!(decode_event_stream("openai", encode(&second).as_bytes()).is_ok());
        for (pointer, value) in [
            ("/id", serde_json::json!("foreign-response")),
            ("/model", serde_json::json!("foreign-model")),
            ("/choices/0/index", serde_json::json!(1)),
            (
                "/choices/0/delta/tool_calls/0/index",
                serde_json::json!(claw_provider_sdk::stream::MAX_TOOL_CALLS),
            ),
        ] {
            let mut changed = second.clone();
            *changed.pointer_mut(pointer).expect("field") = value;
            assert_eq!(
                decode_event_stream("openai", encode(&changed).as_bytes())
                    .expect_err("stream identity mismatch")
                    .kind(),
                ErrorKind::Protocol
            );
        }
        for index in [0, 1] {
            let mut changed = second.clone();
            changed["choices"][0]["delta"]["tool_calls"][0]["id"] =
                serde_json::json!(if index == 0 {
                    "changed-id"
                } else {
                    "call-owned"
                });
            changed["choices"][0]["delta"]["tool_calls"][0]["index"] = serde_json::json!(index);
            assert!(decode_event_stream("openai", encode(&changed).as_bytes()).is_err());
        }
        let repeated =
            format!("data: {first}\n\ndata: {second}\n\ndata: {second}\n\ndata: [DONE]\n\n");
        assert!(decode_event_stream("openai", repeated.as_bytes()).is_err());
        let mut omitted = second;
        omitted.as_object_mut().expect("chunk").remove("id");
        omitted.as_object_mut().expect("chunk").remove("model");
        assert!(decode_event_stream("openai", encode(&omitted).as_bytes()).is_ok());
    }

    #[test]
    fn chat_usage_reporting_distinguishes_explicit_zero_from_missing_counters() {
        use claw_provider_sdk::model::UsageReporting;

        let mut body = serde_json::json!({"id":"owned","model":"owned","choices":[{"message":{"content":"answer"},"finish_reason":"stop"}]});
        assert_eq!(
            decode_completion("openai", body.to_string().as_bytes())
                .expect("no usage")
                .usage_reporting,
            UsageReporting::Unreported
        );
        for (usage, expected) in [
            (serde_json::json!({}), UsageReporting::Partial),
            (
                serde_json::json!({"prompt_tokens":0}),
                UsageReporting::Partial,
            ),
            (
                serde_json::json!({"completion_tokens":0}),
                UsageReporting::Partial,
            ),
            (
                serde_json::json!({"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}),
                UsageReporting::Complete,
            ),
        ] {
            body["usage"] = usage;
            let response = decode_completion("openai", body.to_string().as_bytes())
                .expect("reported usage shape");
            assert_eq!(response.usage, Usage::default());
            assert_eq!(response.usage_reporting, expected);
        }
    }

    #[test]
    fn chat_stream_usage_reporting_tracks_primary_fields_across_updates() {
        use claw_provider_sdk::model::UsageReporting;
        use claw_provider_sdk::stream::StreamAccumulator;
        use std::fmt::Write as _;

        for (snapshots, expected, total) in [
            (vec![], UsageReporting::Unreported, 0),
            (vec![serde_json::json!({})], UsageReporting::Partial, 0),
            (
                vec![serde_json::json!({"prompt_tokens":0})],
                UsageReporting::Partial,
                0,
            ),
            (
                vec![serde_json::json!({"completion_tokens":0})],
                UsageReporting::Partial,
                0,
            ),
            (
                vec![serde_json::json!({"prompt_tokens":0,"completion_tokens":0})],
                UsageReporting::Complete,
                0,
            ),
            (
                vec![
                    serde_json::json!({"prompt_tokens":0}),
                    serde_json::json!({"completion_tokens":0}),
                    serde_json::json!({}),
                ],
                UsageReporting::Complete,
                0,
            ),
            (
                vec![
                    serde_json::json!({"prompt_tokens":7}),
                    serde_json::json!({"completion_tokens":3}),
                ],
                UsageReporting::Complete,
                10,
            ),
        ] {
            let mut updates = String::new();
            for usage in snapshots {
                write!(updates, "data: {{\"usage\":{usage}}}\n\n").expect("SSE usage fixture");
            }
            let body = format!(
                "data: {{\"id\":\"owned\",\"model\":\"owned\",\"choices\":[{{\"delta\":{{\"content\":\"answer\"}},\"finish_reason\":\"stop\"}}]}}\n\n{updates}data: [DONE]\n\n"
            );
            let events = decode_event_stream("openai", body.as_bytes()).expect("usage stream");
            let mut accumulator = StreamAccumulator::new();
            for event in events {
                accumulator.accept(&event);
            }
            assert_eq!(accumulator.usage_reporting(), expected);
            assert_eq!(accumulator.usage().total_tokens(), total);
        }
    }

    #[test]
    fn chat_usage_totals_details_and_cumulative_updates_are_validated() {
        let base = serde_json::json!({"id":"owned","model":"owned","choices":[{"message":{"content":"answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5,"prompt_tokens_details":{"cached_tokens":1},"completion_tokens_details":{"reasoning_tokens":1}}});
        assert!(decode_completion("openai", base.to_string().as_bytes()).is_ok());
        for (pointer, value) in [
            ("/usage/total_tokens", serde_json::json!(4)),
            ("/usage/prompt_tokens", serde_json::json!(u64::MAX)),
            (
                "/usage/prompt_tokens_details/cached_tokens",
                serde_json::json!(3),
            ),
            (
                "/usage/completion_tokens_details/reasoning_tokens",
                serde_json::json!(4),
            ),
        ] {
            let mut changed = base.clone();
            *changed.pointer_mut(pointer).expect("field") = value;
            assert_eq!(
                decode_completion("openai", changed.to_string().as_bytes())
                    .expect_err("invalid usage")
                    .kind(),
                ErrorKind::Protocol
            );
        }
        let initial =
            serde_json::json!({"id":"owned","model":"owned","choices":[],"usage":base["usage"]});
        let update = serde_json::json!({"usage":{"completion_tokens":4,"total_tokens":6}});
        let frames = |update: &serde_json::Value| {
            format!("data: {initial}\n\ndata: {update}\n\ndata: [DONE]\n\n")
        };
        let events = decode_event_stream("openai", frames(&update).as_bytes())
            .expect("partial cumulative usage");
        assert!(matches!(
            events.last(),
            Some(StreamEvent::Completed {
                usage: Usage {
                    input_tokens: 2,
                    output_tokens: 4,
                    cached_input_tokens: 1,
                    reasoning_tokens: 1
                },
                ..
            })
        ));
        for usage in [
            serde_json::json!({"prompt_tokens":1}),
            serde_json::json!({"completion_tokens":2}),
            serde_json::json!({"prompt_tokens_details":{"cached_tokens":0}}),
            serde_json::json!({"completion_tokens_details":{"reasoning_tokens":0}}),
        ] {
            assert!(
                decode_event_stream(
                    "openai",
                    frames(&serde_json::json!({"usage":usage})).as_bytes()
                )
                .is_err()
            );
        }
        let embedding = serde_json::json!({"model":"owned","data":[],"usage":{"prompt_tokens":2,"total_tokens":1}});
        assert_eq!(
            decode_embeddings("openai", embedding.to_string().as_bytes())
                .expect_err("same usage contract")
                .operation(),
            Operation::Embed
        );
    }

    #[test]
    fn chat_output_budget_counts_utf8_and_shared_text_reasoning_and_arguments() {
        let limit = claw_provider_sdk::stream::MAX_TOTAL_TOOL_ARGUMENT_BYTES;
        let content = "\u{00e9}".repeat(limit / 2);
        let base = serde_json::json!({"id":"owned","model":"owned","choices":[{"message":{"content":content},"finish_reason":"stop"}]});
        assert!(decode_completion("openai", base.to_string().as_bytes()).is_ok());
        let mut changed = base.clone();
        changed["choices"][0]["message"]["reasoning_content"] = serde_json::json!("x");
        assert!(decode_completion("openai", changed.to_string().as_bytes()).is_err());
        let mut tool = base;
        tool["choices"][0]["message"]["tool_calls"] =
            serde_json::json!([{"id":"owned-call","function":{"name":"lookup","arguments":"{}"}}]);
        assert!(decode_completion("openai", tool.to_string().as_bytes()).is_err());
        let mut decoder = OpenAiStreamDecoder::new("openai");
        let chunk = serde_json::json!({"id":"owned","model":"owned","choices":[{"delta":{"content":"x".repeat(limit / 8)}}]});
        for _ in 0..8 {
            decoder
                .accept(&SseEvent {
                    data: chunk.to_string(),
                    ..SseEvent::default()
                })
                .expect("within aggregate bound");
        }
        assert_eq!(decoder.output_bytes, limit);
        let extra = serde_json::json!({"choices":[{"delta":{"reasoning_content":"x"}}]});
        assert!(
            decoder
                .accept(&SseEvent {
                    data: extra.to_string(),
                    ..SseEvent::default()
                })
                .is_err()
        );
        let over_body = vec![b' '; MAX_COMPLETION_BODY_BYTES + 1];
        assert!(decode_completion("openai", &over_body).is_err());
    }

    #[tokio::test]
    async fn chat_usage_error_preserves_preceding_events_in_the_same_chunk() {
        let body = concat!(
            "data: {\"id\":\"owned\",\"model\":\"owned\",\"choices\":[{\"delta\":{\"content\":\"partial answer\"}}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1,\"total_tokens\":4}}\n\n",
            "data: [DONE]\n\n",
        );
        let mut stream = events_from_chunks(
            "openai",
            CancelToken::new(),
            Box::pin(futures_util::stream::iter([Ok(Bytes::from_static(
                body.as_bytes(),
            ))])),
        );
        assert!(matches!(
            stream.next().await,
            Some(Ok(StreamEvent::Started { .. }))
        ));
        assert_eq!(
            stream
                .next()
                .await
                .expect("partial")
                .expect("accepted text"),
            StreamEvent::TextDelta("partial answer".to_owned())
        );
        assert_eq!(
            stream
                .next()
                .await
                .expect("error")
                .expect_err("invalid total")
                .kind(),
            ErrorKind::Protocol
        );
        assert!(stream.next().await.is_none());
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

        let base_url: Url = "https://api.moonshot.cn/v1".parse().expect("url");
        let unapproved =
            OpenAiCompatible::from_registry("kimi", Some(ApiKey::new("k")), Some(base_url.clone()))
                .expect_err("an endpoint-required provider still needs an enrolled origin");
        assert_eq!(unapproved.kind(), ErrorKind::Authentication);
        assert_eq!(unapproved.operation(), Operation::Authorize);

        let approval = OriginApproval::enroll(Origin::of(&base_url).expect("origin"));
        let client = OpenAiCompatible::from_registry_with_enrolled_origin(
            "kimi",
            Some(ApiKey::new("k")),
            base_url,
            &approval,
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
        let base_url: Url = "https://example.invalid/v1/".parse().expect("url");
        let approval = OriginApproval::enroll(Origin::of(&base_url).expect("origin"));
        let client = OpenAiCompatible::from_registry_with_enrolled_origin(
            "groq",
            Some(ApiKey::new("k")),
            base_url,
            &approval,
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
        let request = client
            .request(
                Method::Post,
                "https://api.openai.com/v1/chat/completions"
                    .parse()
                    .expect("url"),
            )
            .expect("request");
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

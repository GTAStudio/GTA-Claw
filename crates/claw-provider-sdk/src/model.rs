//! Typed request and response models shared by every provider.
//!
//! No variant of these types carries an opaque JSON document. The two places
//! where JSON is part of the domain — JSON-Schema tool declarations and
//! model-generated tool-call arguments — are represented by [`ToolParameters`]
//! and [`ToolArguments`], which validate their contents on construction.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use url::Url;

/// Longest accepted provider or model identifier, in bytes.
const MAX_IDENTIFIER_BYTES: usize = 256;

/// Rejection reason for an invalid model value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelError {
    /// An identifier was empty, over-long or contained forbidden bytes.
    InvalidIdentifier {
        /// The field that failed validation.
        field: &'static str,
    },
    /// Tool parameters were not a JSON Schema object.
    ToolParametersNotAnObject,
    /// Tool-call arguments were not a JSON object document.
    ToolArgumentsNotAnObject,
    /// A request had no messages, or the message sequence is unusable.
    EmptyConversation,
    /// A numeric sampling parameter was outside its documented range.
    SamplingOutOfRange {
        /// The parameter that failed validation.
        field: &'static str,
    },
    /// An embeddings request carried no input.
    EmptyEmbeddingInput,
    /// A tool name was declared twice in one request.
    DuplicateToolName {
        /// The duplicated tool name.
        name: String,
    },
    /// A forced tool choice referenced a tool that was not declared.
    UnknownToolChoice {
        /// The referenced tool name.
        name: String,
    },
}

impl Display for ModelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier { field } => {
                write!(formatter, "invalid identifier for field '{field}'")
            }
            Self::ToolParametersNotAnObject => {
                formatter.write_str("tool parameters must be a JSON Schema object")
            }
            Self::ToolArgumentsNotAnObject => {
                formatter.write_str("tool-call arguments must be a JSON object")
            }
            Self::EmptyConversation => {
                formatter.write_str("a completion needs at least one message")
            }
            Self::SamplingOutOfRange { field } => {
                write!(formatter, "sampling parameter '{field}' is out of range")
            }
            Self::EmptyEmbeddingInput => formatter.write_str("an embeddings request needs input"),
            Self::DuplicateToolName { name } => {
                write!(formatter, "tool '{name}' was declared more than once")
            }
            Self::UnknownToolChoice { name } => {
                write!(formatter, "tool choice references undeclared tool '{name}'")
            }
        }
    }
}

impl Error for ModelError {}

/// Validated provider identifier, matching a frozen inventory row.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderId(String);

impl ProviderId {
    /// Validates and wraps a provider identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidIdentifier`] when the value is empty, longer
    /// than 256 bytes, or contains anything other than ASCII alphanumerics,
    /// `-`, `_` or `.`.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidIdentifier { field: "provider" })
        }
    }

    /// Returns the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ProviderId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Validated model identifier as understood by one provider.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelId(String);

impl ModelId {
    /// Validates and wraps a model identifier.
    ///
    /// Model identifiers are looser than provider identifiers because upstream
    /// catalogues use `/`, `:` and `@` separators. Whitespace and control
    /// characters remain forbidden.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidIdentifier`] when the value is empty, longer
    /// than 256 bytes, or contains whitespace or control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let acceptable = !value.is_empty()
            && value.len() <= MAX_IDENTIFIER_BYTES
            && !value
                .chars()
                .any(|character| character.is_whitespace() || character.is_control());
        if acceptable {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidIdentifier { field: "model" })
        }
    }

    /// Returns the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ModelId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Media type of an inline image part.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ImageMediaType {
    /// `image/png`
    Png,
    /// `image/jpeg`
    Jpeg,
    /// `image/gif`
    Gif,
    /// `image/webp`
    Webp,
}

impl ImageMediaType {
    /// Returns the IANA media type string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
        }
    }
}

/// Location of image bytes referenced by a message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImageSource {
    /// Standard base64 (RFC 4648) encoded bytes carried inline.
    Base64(String),
    /// An absolute URL the provider will fetch.
    Url(Url),
}

/// One image attachment inside a message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImagePart {
    /// Media type of the referenced bytes.
    pub media_type: ImageMediaType,
    /// Where the bytes live.
    pub source: ImageSource,
}

/// One piece of message content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentPart {
    /// Plain UTF-8 text.
    Text(String),
    /// An image attachment.
    Image(ImagePart),
}

impl ContentPart {
    /// Convenience constructor for a text part.
    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// Returns the text of a [`ContentPart::Text`] part.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Image(_) => None,
        }
    }
}

/// A JSON Schema object describing a tool's parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolParameters(Map<String, Value>);

impl ToolParameters {
    /// Wraps a JSON Schema document.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ToolParametersNotAnObject`] unless `schema` is a
    /// JSON object.
    pub fn new(schema: Value) -> Result<Self, ModelError> {
        match schema {
            Value::Object(map) => Ok(Self(map)),
            _ => Err(ModelError::ToolParametersNotAnObject),
        }
    }

    /// Returns an empty object schema, meaning "no parameters".
    #[must_use]
    pub fn empty() -> Self {
        let mut map = Map::new();
        map.insert("type".to_owned(), Value::String("object".to_owned()));
        map.insert("properties".to_owned(), Value::Object(Map::new()));
        Self(map)
    }

    /// Borrows the schema as a JSON object for wire serialization.
    #[must_use]
    pub const fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }
}

/// Arguments produced by a model for one tool call.
///
/// The wrapped text is guaranteed to parse as a JSON object, so a consumer can
/// deserialize it into a concrete type without re-validating the framing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolArguments(String);

impl ToolArguments {
    /// Validates and wraps a JSON object document.
    ///
    /// An empty or whitespace-only input is normalized to `{}` because several
    /// providers emit no argument bytes at all for zero-parameter tools.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ToolArgumentsNotAnObject`] when the text is not a
    /// JSON object.
    pub fn new(raw: impl Into<String>) -> Result<Self, ModelError> {
        let raw = raw.into();
        if raw.trim().is_empty() {
            return Ok(Self("{}".to_owned()));
        }
        match serde_json::from_str::<Value>(&raw) {
            Ok(Value::Object(_)) => Ok(Self(raw)),
            _ => Err(ModelError::ToolArgumentsNotAnObject),
        }
    }

    /// Returns the raw JSON object text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Deserializes the arguments into a caller-defined type.
    ///
    /// # Errors
    ///
    /// Returns the `serde_json` error when the document does not match `T`.
    pub fn deserialize<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_str(&self.0)
    }
}

/// A tool the model may call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolDefinition {
    /// Tool name as presented to the model.
    pub name: String,
    /// Human-readable description of what the tool does.
    pub description: String,
    /// JSON Schema for the tool's arguments.
    pub parameters: ToolParameters,
}

/// A tool invocation requested by the model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCall {
    /// Provider-assigned call identifier used to correlate the tool result.
    pub id: String,
    /// Name of the tool to invoke.
    pub name: String,
    /// Validated argument document.
    pub arguments: ToolArguments,
}

/// How the model should decide whether to call a tool.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ToolChoice {
    /// Let the model decide.
    #[default]
    Auto,
    /// Forbid tool calls for this turn.
    None,
    /// Require at least one tool call.
    Required,
    /// Require a call to one specific tool.
    Function(String),
}

/// One turn in a conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChatMessage {
    /// Instructions that frame the whole conversation.
    System(String),
    /// Input from the human or calling application.
    User(Vec<ContentPart>),
    /// A previous model turn, replayed for context.
    Assistant(AssistantMessage),
    /// The result of executing a tool the model requested.
    ToolResult(ToolResultMessage),
}

impl ChatMessage {
    /// Convenience constructor for a plain-text user turn.
    #[must_use]
    pub fn user_text(text: impl Into<String>) -> Self {
        Self::User(vec![ContentPart::text(text)])
    }

    /// Returns the stable role identifier of this turn.
    #[must_use]
    pub const fn role(&self) -> &'static str {
        match self {
            Self::System(_) => "system",
            Self::User(_) => "user",
            Self::Assistant(_) => "assistant",
            Self::ToolResult(_) => "tool",
        }
    }
}

/// The result of one executed tool call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolResultMessage {
    /// Identifier of the [`ToolCall`] this result answers.
    pub tool_call_id: String,
    /// Tool output rendered as text.
    pub content: String,
    /// Whether the tool reported failure.
    pub is_error: bool,
}

/// An assistant turn.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AssistantMessage {
    /// Visible content produced by the model.
    pub content: Vec<ContentPart>,
    /// Reasoning summary, when the provider exposes one.
    pub reasoning: Option<String>,
    /// Tool calls the model requested.
    pub tool_calls: Vec<ToolCall>,
}

impl AssistantMessage {
    /// Concatenates every text part into a single string.
    #[must_use]
    pub fn text(&self) -> String {
        self.content
            .iter()
            .filter_map(ContentPart::as_text)
            .collect::<Vec<_>>()
            .concat()
    }
}

/// Why generation stopped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FinishReason {
    /// The model produced a natural stop or hit a stop sequence.
    Stop,
    /// The output token budget was exhausted.
    Length,
    /// The model requested one or more tool calls.
    ToolCalls,
    /// The provider's safety system stopped generation.
    ContentFilter,
    /// The caller cancelled the stream before completion.
    Cancelled,
    /// A provider-specific reason that has no portable meaning.
    Other(String),
}

/// Token accounting for one request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    /// Prompt tokens billed for this request.
    pub input_tokens: u64,
    /// Generated tokens billed for this request.
    pub output_tokens: u64,
    /// Portion of `input_tokens` served from a prompt cache.
    pub cached_input_tokens: u64,
    /// Portion of `output_tokens` spent on hidden reasoning.
    pub reasoning_tokens: u64,
}

impl Usage {
    /// Returns the sum of billed input and output tokens.
    #[must_use]
    pub const fn total_tokens(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }

    /// Returns the field-wise saturating sum of two usage records.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self {
            input_tokens: self.input_tokens.saturating_add(other.input_tokens),
            output_tokens: self.output_tokens.saturating_add(other.output_tokens),
            cached_input_tokens: self
                .cached_input_tokens
                .saturating_add(other.cached_input_tokens),
            reasoning_tokens: self.reasoning_tokens.saturating_add(other.reasoning_tokens),
        }
    }
}

/// The output format a provider must produce.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum ResponseFormat {
    /// Ordinary free-form text.
    #[default]
    Text,
    /// The provider must emit a syntactically valid JSON object.
    JsonObject,
}

impl ResponseFormat {
    /// Returns the stable identifier of this format.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::JsonObject => "json_object",
        }
    }
}

impl Display for ResponseFormat {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A chat-completion request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionRequest {
    /// Model to run.
    pub model: ModelId,
    /// Conversation so far.
    pub messages: Vec<ChatMessage>,
    /// Tools the model may call.
    pub tools: Vec<ToolDefinition>,
    /// Tool-selection policy.
    pub tool_choice: ToolChoice,
    /// Hard cap on generated tokens.
    pub max_output_tokens: Option<u32>,
    /// Sampling temperature in `[0.0, 2.0]`, expressed in thousandths.
    pub temperature_milli: Option<u16>,
    /// Nucleus sampling mass in `(0.0, 1.0]`, expressed in thousandths.
    pub top_p_milli: Option<u16>,
    /// Sequences that stop generation when produced.
    pub stop_sequences: Vec<String>,
    /// Whether the provider may run tool calls in parallel.
    pub parallel_tool_calls: Option<bool>,
    /// Deterministic sampling seed, when the provider supports one.
    pub seed: Option<u64>,
    /// Required output format.
    ///
    /// Providers that do not advertise [`Capability::JsonMode`] reject anything
    /// other than [`ResponseFormat::Text`].
    pub response_format: ResponseFormat,
}

impl CompletionRequest {
    /// Builds a minimal request for `model` with a single user turn.
    #[must_use]
    pub fn new(model: ModelId, messages: Vec<ChatMessage>) -> Self {
        Self {
            model,
            messages,
            tools: Vec::new(),
            tool_choice: ToolChoice::Auto,
            max_output_tokens: None,
            temperature_milli: None,
            top_p_milli: None,
            stop_sequences: Vec::new(),
            parallel_tool_calls: None,
            seed: None,
            response_format: ResponseFormat::Text,
        }
    }

    /// Checks the request against the portable constraints every provider shares.
    ///
    /// # Errors
    ///
    /// Returns the first violated constraint.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.messages.is_empty() {
            return Err(ModelError::EmptyConversation);
        }
        if self.temperature_milli.is_some_and(|value| value > 2_000) {
            return Err(ModelError::SamplingOutOfRange {
                field: "temperature",
            });
        }
        if self
            .top_p_milli
            .is_some_and(|value| value == 0 || value > 1_000)
        {
            return Err(ModelError::SamplingOutOfRange { field: "top_p" });
        }
        let mut names = Vec::with_capacity(self.tools.len());
        for tool in &self.tools {
            if names.contains(&tool.name.as_str()) {
                return Err(ModelError::DuplicateToolName {
                    name: tool.name.clone(),
                });
            }
            names.push(tool.name.as_str());
        }
        if let ToolChoice::Function(name) = &self.tool_choice
            && !names.contains(&name.as_str())
        {
            return Err(ModelError::UnknownToolChoice { name: name.clone() });
        }
        Ok(())
    }

    /// Returns the temperature as a floating-point value.
    #[must_use]
    pub fn temperature(&self) -> Option<f64> {
        self.temperature_milli
            .map(|value| f64::from(value) / 1_000.0)
    }

    /// Returns the nucleus-sampling mass as a floating-point value.
    #[must_use]
    pub fn top_p(&self) -> Option<f64> {
        self.top_p_milli.map(|value| f64::from(value) / 1_000.0)
    }
}

/// A completed chat-completion response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionResponse {
    /// Provider-assigned response identifier.
    pub id: String,
    /// Model that actually served the request.
    pub model: ModelId,
    /// The generated assistant turn.
    pub message: AssistantMessage,
    /// Why generation stopped.
    pub finish_reason: FinishReason,
    /// Token accounting.
    pub usage: Usage,
}

/// An embeddings request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddingsRequest {
    /// Embedding model to run.
    pub model: ModelId,
    /// Input documents.
    pub inputs: Vec<String>,
    /// Requested output dimensionality, when the model supports truncation.
    pub dimensions: Option<u32>,
}

impl EmbeddingsRequest {
    /// Checks the portable constraints of an embeddings request.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::EmptyEmbeddingInput`] when there is nothing to embed.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.inputs.is_empty() || self.inputs.iter().all(|input| input.is_empty()) {
            return Err(ModelError::EmptyEmbeddingInput);
        }
        Ok(())
    }
}

/// One embedding vector.
#[derive(Clone, Debug, PartialEq)]
pub struct Embedding {
    /// Index of the input this vector belongs to.
    pub index: usize,
    /// The vector itself.
    pub vector: Vec<f32>,
}

/// An embeddings response.
#[derive(Clone, Debug, PartialEq)]
pub struct EmbeddingsResponse {
    /// Model that served the request.
    pub model: ModelId,
    /// One vector per input, ordered by [`Embedding::index`].
    pub embeddings: Vec<Embedding>,
    /// Token accounting.
    pub usage: Usage,
}

/// A single capability a provider or model may advertise.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Capability {
    /// Non-streaming chat completion.
    Completion,
    /// Incremental streaming completion.
    Streaming,
    /// Tool/function calling.
    ToolCalling,
    /// Embedding generation.
    Embeddings,
    /// Runtime model-catalogue listing.
    ModelListing,
    /// Image inputs.
    Vision,
    /// Exposed reasoning traces or summaries.
    Reasoning,
    /// Guaranteed JSON output mode.
    JsonMode,
    /// Prompt caching that is billed separately.
    PromptCaching,
}

impl Capability {
    /// Every capability, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::Completion,
        Self::Streaming,
        Self::ToolCalling,
        Self::Embeddings,
        Self::ModelListing,
        Self::Vision,
        Self::Reasoning,
        Self::JsonMode,
        Self::PromptCaching,
    ];

    /// Returns the stable identifier of this capability.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completion => "completion",
            Self::Streaming => "streaming",
            Self::ToolCalling => "tool_calling",
            Self::Embeddings => "embeddings",
            Self::ModelListing => "model_listing",
            Self::Vision => "vision",
            Self::Reasoning => "reasoning",
            Self::JsonMode => "json_mode",
            Self::PromptCaching => "prompt_caching",
        }
    }

    const fn bit(self) -> u16 {
        1 << (self as u16)
    }
}

impl Display for Capability {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An immutable set of [`Capability`] values.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilitySet(u16);

impl CapabilitySet {
    /// The empty set.
    pub const EMPTY: Self = Self(0);

    /// Builds a set from a slice, usable in `const` context.
    #[must_use]
    pub const fn from_slice(capabilities: &[Capability]) -> Self {
        let mut bits = 0_u16;
        let mut index = 0;
        while index < capabilities.len() {
            bits |= capabilities[index].bit();
            index += 1;
        }
        Self(bits)
    }

    /// Returns `true` when `capability` is present.
    #[must_use]
    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & capability.bit() != 0
    }

    /// Returns `true` when every capability of `required` is present.
    ///
    /// An empty `required` set is satisfied by every set, including the empty
    /// one, so callers that route on capabilities must reject an empty
    /// requirement themselves rather than treating this as a filter.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Returns the capabilities of `required` that this set lacks, in
    /// [`Capability::ALL`] order.
    #[must_use]
    pub fn missing_from(self, required: Self) -> Vec<Capability> {
        Capability::ALL
            .into_iter()
            .filter(|capability| required.contains(*capability) && !self.contains(*capability))
            .collect()
    }

    /// Returns the number of capabilities in the set.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// Returns `true` when the set has no capabilities.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns the capabilities in [`Capability::ALL`] order.
    #[must_use]
    pub fn to_vec(self) -> Vec<Capability> {
        Capability::ALL
            .into_iter()
            .filter(|capability| self.contains(*capability))
            .collect()
    }
}

/// How a provider authenticates callers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthMode {
    /// No credential is required (typically a local runtime).
    None,
    /// A static API key sent in a provider-specific header.
    ApiKey,
    /// A static bearer token sent in `Authorization: Bearer`.
    BearerToken,
    /// RFC 8628 OAuth 2.0 device authorization grant.
    OAuthDeviceCode,
    /// OAuth 2.0 authorization-code grant with PKCE.
    OAuthAuthorizationCode,
    /// AWS SigV4 request signing.
    AwsSigV4,
    /// Google service-account or Application Default Credentials.
    GoogleServiceAccount,
    /// Azure Entra ID token or Azure API key.
    AzureIdentity,
}

impl AuthMode {
    /// Every authentication mode, in declaration order.
    ///
    /// Adding a variant without extending this constant fails to compile, so
    /// exhaustive tests over authentication cannot silently skip a new mode.
    pub const ALL: [Self; 8] = [
        Self::None,
        Self::ApiKey,
        Self::BearerToken,
        Self::OAuthDeviceCode,
        Self::OAuthAuthorizationCode,
        Self::AwsSigV4,
        Self::GoogleServiceAccount,
        Self::AzureIdentity,
    ];

    /// Returns the stable identifier of this authentication mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ApiKey => "api_key",
            Self::BearerToken => "bearer_token",
            Self::OAuthDeviceCode => "oauth_device_code",
            Self::OAuthAuthorizationCode => "oauth_authorization_code",
            Self::AwsSigV4 => "aws_sigv4",
            Self::GoogleServiceAccount => "google_service_account",
            Self::AzureIdentity => "azure_identity",
        }
    }
}

impl Display for AuthMode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One entry of a provider's model catalogue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelDescriptor {
    /// Identifier accepted by [`CompletionRequest::model`].
    pub id: ModelId,
    /// Human-readable name, when the provider publishes one.
    pub display_name: Option<String>,
    /// Total context window in tokens, when published.
    pub context_window: Option<u32>,
    /// Maximum output tokens, when published.
    pub max_output_tokens: Option<u32>,
    /// Capabilities this specific model supports.
    pub capabilities: CapabilitySet,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_identifiers_reject_separators_and_overlong_values() {
        assert_eq!(
            ProviderId::new("github-copilot").expect("valid").as_str(),
            "github-copilot"
        );
        assert_eq!(
            ProviderId::new("gpt.4o_mini").expect("valid").as_str(),
            "gpt.4o_mini"
        );
        for rejected in ["", "with space", "slash/name", "Ünicode", &"x".repeat(257)] {
            assert_eq!(
                ProviderId::new(rejected),
                Err(ModelError::InvalidIdentifier { field: "provider" }),
                "{rejected}"
            );
        }
    }

    #[test]
    fn model_identifiers_allow_catalogue_separators_but_not_whitespace() {
        for accepted in [
            "gpt-5.6",
            "anthropic/claude-opus-4.6",
            "publisher:model@2026-01-01",
        ] {
            assert_eq!(ModelId::new(accepted).expect("valid").as_str(), accepted);
        }
        for rejected in ["", "has space", "line\nbreak", &"m".repeat(257)] {
            assert_eq!(
                ModelId::new(rejected),
                Err(ModelError::InvalidIdentifier { field: "model" }),
                "{rejected}"
            );
        }
    }

    #[test]
    fn tool_parameters_require_a_json_object() {
        let schema =
            serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}});
        let parameters = ToolParameters::new(schema).expect("object schema");
        assert_eq!(
            parameters.as_map().get("type").and_then(Value::as_str),
            Some("object")
        );
        for rejected in [
            Value::Null,
            Value::Bool(true),
            Value::String("object".to_owned()),
            Value::Array(vec![]),
        ] {
            assert_eq!(
                ToolParameters::new(rejected),
                Err(ModelError::ToolParametersNotAnObject)
            );
        }
        assert_eq!(
            ToolParameters::empty().as_map().get("properties"),
            Some(&Value::Object(Map::new()))
        );
    }

    #[test]
    fn tool_arguments_validate_framing_and_normalize_empty_input() {
        let arguments = ToolArguments::new(r#"{"path":"/tmp/x","depth":2}"#).expect("object");
        assert_eq!(arguments.as_str(), r#"{"path":"/tmp/x","depth":2}"#);

        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Args {
            path: String,
            depth: u8,
        }
        assert_eq!(
            arguments.deserialize::<Args>().expect("typed"),
            Args {
                path: "/tmp/x".to_owned(),
                depth: 2
            }
        );

        assert_eq!(ToolArguments::new("").expect("empty").as_str(), "{}");
        assert_eq!(ToolArguments::new("   ").expect("blank").as_str(), "{}");
        for rejected in ["[]", "\"text\"", "42", "{", "{\"a\":}"] {
            assert_eq!(
                ToolArguments::new(rejected),
                Err(ModelError::ToolArgumentsNotAnObject),
                "{rejected}"
            );
        }
    }

    fn tool(name: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.to_owned(),
            description: format!("{name} description"),
            parameters: ToolParameters::empty(),
        }
    }

    #[test]
    fn request_validation_enforces_every_portable_constraint() {
        let model = ModelId::new("gpt-5.6").expect("valid");
        let mut request =
            CompletionRequest::new(model.clone(), vec![ChatMessage::user_text("hello")]);
        assert_eq!(request.validate(), Ok(()));

        let empty = CompletionRequest::new(model.clone(), Vec::new());
        assert_eq!(empty.validate(), Err(ModelError::EmptyConversation));

        request.temperature_milli = Some(2_001);
        assert_eq!(
            request.validate(),
            Err(ModelError::SamplingOutOfRange {
                field: "temperature"
            })
        );
        request.temperature_milli = Some(2_000);
        assert_eq!(request.validate(), Ok(()));
        assert_eq!(request.temperature(), Some(2.0));

        request.top_p_milli = Some(0);
        assert_eq!(
            request.validate(),
            Err(ModelError::SamplingOutOfRange { field: "top_p" })
        );
        request.top_p_milli = Some(1_001);
        assert_eq!(
            request.validate(),
            Err(ModelError::SamplingOutOfRange { field: "top_p" })
        );
        request.top_p_milli = Some(900);
        assert_eq!(request.validate(), Ok(()));
        assert_eq!(request.top_p(), Some(0.9));

        request.tools = vec![tool("read"), tool("read")];
        assert_eq!(
            request.validate(),
            Err(ModelError::DuplicateToolName {
                name: "read".to_owned()
            })
        );

        request.tools = vec![tool("read"), tool("write")];
        request.tool_choice = ToolChoice::Function("delete".to_owned());
        assert_eq!(
            request.validate(),
            Err(ModelError::UnknownToolChoice {
                name: "delete".to_owned()
            })
        );
        request.tool_choice = ToolChoice::Function("write".to_owned());
        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn embeddings_validation_rejects_empty_input() {
        let model = ModelId::new("text-embedding-3-small").expect("valid");
        let request = EmbeddingsRequest {
            model: model.clone(),
            inputs: Vec::new(),
            dimensions: None,
        };
        assert_eq!(request.validate(), Err(ModelError::EmptyEmbeddingInput));

        let blank = EmbeddingsRequest {
            model: model.clone(),
            inputs: vec![String::new(), String::new()],
            dimensions: None,
        };
        assert_eq!(blank.validate(), Err(ModelError::EmptyEmbeddingInput));

        let usable = EmbeddingsRequest {
            model,
            inputs: vec![String::new(), "text".to_owned()],
            dimensions: Some(256),
        };
        assert_eq!(usable.validate(), Ok(()));
    }

    #[test]
    fn capability_sets_round_trip_every_capability() {
        assert!(CapabilitySet::EMPTY.is_empty());
        assert_eq!(CapabilitySet::EMPTY.len(), 0);

        let all = CapabilitySet::from_slice(&Capability::ALL);
        assert_eq!(all.len(), 9);
        assert_eq!(all.to_vec(), Capability::ALL.to_vec());

        for capability in Capability::ALL {
            let single = CapabilitySet::from_slice(&[capability]);
            assert!(single.contains(capability));
            assert_eq!(single.len(), 1);
            for other in Capability::ALL {
                assert_eq!(single.contains(other), other == capability);
            }
        }

        let pair = CapabilitySet::from_slice(&[Capability::Streaming, Capability::Completion]);
        assert_eq!(
            pair.to_vec(),
            vec![Capability::Completion, Capability::Streaming]
        );
    }

    #[test]
    fn capability_and_auth_identifiers_are_unique() {
        let mut capability_ids = Vec::new();
        for capability in Capability::ALL {
            assert!(!capability_ids.contains(&capability.as_str()));
            capability_ids.push(capability.as_str());
        }
        let auth_modes = [
            AuthMode::None,
            AuthMode::ApiKey,
            AuthMode::BearerToken,
            AuthMode::OAuthDeviceCode,
            AuthMode::OAuthAuthorizationCode,
            AuthMode::AwsSigV4,
            AuthMode::GoogleServiceAccount,
            AuthMode::AzureIdentity,
        ];
        let mut auth_ids = Vec::new();
        for mode in auth_modes {
            assert!(!auth_ids.contains(&mode.as_str()));
            auth_ids.push(mode.as_str());
        }
        assert_eq!(auth_ids.len(), 8);
        // `AuthMode::ALL` is what exhaustive tests elsewhere iterate, so it is
        // pinned here against the hand-written list above rather than against
        // itself. A ninth variant that is not added to `ALL` fails to compile;
        // one that is added but forgotten here fails this assertion.
        assert_eq!(AuthMode::ALL, auth_modes);
    }

    #[test]
    fn a_capability_set_reports_exactly_the_requirements_it_cannot_satisfy() {
        let served = CapabilitySet::from_slice(&[
            Capability::Completion,
            Capability::Streaming,
            Capability::ToolCalling,
        ]);

        assert!(served.contains_all(CapabilitySet::EMPTY));
        assert!(CapabilitySet::EMPTY.contains_all(CapabilitySet::EMPTY));
        assert!(served.contains_all(CapabilitySet::from_slice(&[Capability::Streaming])));
        assert!(served.contains_all(served));
        assert!(!CapabilitySet::EMPTY.contains_all(served));

        let wanted = CapabilitySet::from_slice(&[
            Capability::Streaming,
            Capability::Embeddings,
            Capability::Vision,
        ]);
        assert!(!served.contains_all(wanted));
        assert_eq!(
            served.missing_from(wanted),
            vec![Capability::Embeddings, Capability::Vision],
        );
        assert_eq!(served.missing_from(served), Vec::new());
        assert_eq!(
            CapabilitySet::EMPTY.missing_from(CapabilitySet::from_slice(&Capability::ALL)),
            Capability::ALL.to_vec(),
        );
    }

    #[test]
    fn assistant_text_concatenates_only_text_parts() {
        let message = AssistantMessage {
            content: vec![
                ContentPart::text("alpha "),
                ContentPart::Image(ImagePart {
                    media_type: ImageMediaType::Png,
                    source: ImageSource::Base64("AAAA".to_owned()),
                }),
                ContentPart::text("beta"),
            ],
            reasoning: None,
            tool_calls: Vec::new(),
        };
        assert_eq!(message.text(), "alpha beta");
    }

    #[test]
    fn usage_addition_saturates_instead_of_wrapping() {
        let left = Usage {
            input_tokens: u64::MAX - 1,
            output_tokens: 3,
            cached_input_tokens: 1,
            reasoning_tokens: 2,
        };
        let right = Usage {
            input_tokens: 5,
            output_tokens: 4,
            cached_input_tokens: 0,
            reasoning_tokens: 1,
        };
        let sum = left.saturating_add(right);
        assert_eq!(sum.input_tokens, u64::MAX);
        assert_eq!(sum.output_tokens, 7);
        assert_eq!(sum.cached_input_tokens, 1);
        assert_eq!(sum.reasoning_tokens, 3);
        assert_eq!(sum.total_tokens(), u64::MAX);
    }

    #[test]
    fn message_roles_are_stable() {
        assert_eq!(ChatMessage::System("x".to_owned()).role(), "system");
        assert_eq!(ChatMessage::user_text("x").role(), "user");
        assert_eq!(
            ChatMessage::Assistant(AssistantMessage::default()).role(),
            "assistant"
        );
        assert_eq!(
            ChatMessage::ToolResult(ToolResultMessage {
                tool_call_id: "call_1".to_owned(),
                content: "ok".to_owned(),
                is_error: false,
            })
            .role(),
            "tool"
        );
    }
}

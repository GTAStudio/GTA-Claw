//! Concrete adapters for the shipped HTTP surface.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Instant;

use claw_config::{ConfigDomain, ConfigSnapshot, ReloadManager, schema_json, to_json5};
use claw_http_api::{
    AdminFailure, AdminPort, AdminSuccess, AuditPort, EmbeddingRequest, GenerationEvent,
    GenerationOutput, GenerationRequest, Model, PortError, PortErrorKind, PortFuture, ProviderPort,
    ReadinessPort, ReadinessSnapshot, ToolDefinition as HttpToolDefinition, ToolInvocation,
    ToolOutcome as HttpToolOutcome, ToolPort, Usage as HttpUsage, WatchAuthPort, WatchIdentity,
    WatchResultPort, WebhookOutcome, WebhookPort,
};
use claw_protocol::gateway::ConnectParams;
use claw_provider_sdk::model::{
    AssistantMessage, Capability, CapabilitySet, ChatMessage, CompletionRequest,
    CompletionResponse, ContentPart, EmbeddingsRequest, EmbeddingsResponse, FinishReason,
    ImageMediaType, ImagePart, ImageSource, ModelDescriptor, ModelId, ProviderId, ResponseFormat,
    ToolChoice as ProviderToolChoice, ToolDefinition, ToolParameters, Usage,
};
use claw_provider_sdk::stream::StreamAccumulator;
use claw_provider_sdk::{
    BoxFuture as ProviderFuture, CancelToken, CompletionStream, ErrorKind, Provider, ProviderError,
    RequestContext, StreamEvent,
};
use claw_security::audit::{AuditAction, AuditEvent, AuditOutcome, AuditReason, AuditSubject};
use futures_util::{StreamExt, stream};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const MAX_CONVERSATIONS: usize = 100;
const MAX_HISTORY_MESSAGES: usize = 32;

/// Dependency state shared with `/ready` and operator diagnostics.
#[derive(Debug)]
pub struct DependencyReadiness {
    started: Instant,
    dependencies: RwLock<BTreeMap<&'static str, bool>>,
}

impl DependencyReadiness {
    /// Creates a readiness set with every named dependency initially down.
    #[must_use]
    pub fn new(names: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            started: Instant::now(),
            dependencies: RwLock::new(names.into_iter().map(|name| (name, false)).collect()),
        }
    }

    /// Changes one dependency's live state.
    pub fn set(&self, name: &'static str, ready: bool) {
        self.dependencies
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name, ready);
    }

    /// Reports whether every required dependency is live.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.dependencies
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .all(|ready| *ready)
    }
}

impl ReadinessPort for DependencyReadiness {
    fn snapshot(&self) -> Result<ReadinessSnapshot, PortError> {
        let dependencies = self
            .dependencies
            .read()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "readiness lock failed"))?;
        let failing = dependencies
            .iter()
            .filter_map(|(name, ready)| (!ready).then_some((*name).to_owned()))
            .collect::<Vec<_>>();
        drop(dependencies);
        Ok(ReadinessSnapshot {
            ready: failing.is_empty(),
            failing,
            uptime_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

/// Bounded operator diagnostics retained for `logs.tail`.
#[derive(Debug)]
pub struct Diagnostics {
    capacity: usize,
    entries: Mutex<VecDeque<String>>,
}

impl Diagnostics {
    /// Creates a bounded diagnostic buffer.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: Mutex::new(VecDeque::with_capacity(capacity.max(1))),
        }
    }

    /// Records one redacted, operator-facing message.
    pub fn record(&self, message: impl Into<String>) {
        let message = message.into();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() == self.capacity {
            entries.pop_front();
        }
        entries.push_back(message);
    }

    /// Returns retained entries oldest first.
    #[must_use]
    pub fn entries(&self) -> Vec<String> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }
}

/// HTTP/provider-SDK bridge with a startup-populated model cache.
pub struct ProviderAdapter {
    provider: Arc<dyn Provider>,
    provider_name: String,
    default_model: RwLock<String>,
    role_prompt: String,
    models: RwLock<Vec<ModelDescriptor>>,
    history: Mutex<ConversationHistory>,
    readiness: Arc<DependencyReadiness>,
}

#[derive(Debug, Default)]
struct ConversationHistory {
    messages: BTreeMap<String, VecDeque<ChatMessage>>,
    recency: VecDeque<String>,
}

struct PreparedCompletion {
    request: CompletionRequest,
    session_id: String,
    user: ChatMessage,
}

impl ProviderAdapter {
    /// Creates an adapter over a provider implementation.
    #[must_use]
    pub fn new(
        provider: Arc<dyn Provider>,
        default_model: impl Into<String>,
        role_prompt: impl Into<String>,
        readiness: Arc<DependencyReadiness>,
    ) -> Self {
        Self {
            provider_name: provider.id().as_str().to_owned(),
            provider,
            default_model: RwLock::new(default_model.into()),
            role_prompt: role_prompt.into(),
            models: RwLock::new(Vec::new()),
            history: Mutex::new(ConversationHistory::default()),
            readiness,
        }
    }

    /// Pings the provider and fills the model cache before ingress is exposed.
    ///
    /// # Errors
    ///
    /// Returns the provider's typed model-listing error, or an invalid-request
    /// error when the configured default is absent from the live catalogue.
    pub async fn initialize(&self) -> Result<(), ProviderError> {
        let models = self
            .provider
            .list_models(&RequestContext::new().correlation_id("daemon-startup"))
            .await?;
        let selected = self.default_model();
        if !models.iter().any(|model| model.id.as_str() == selected) {
            return Err(ProviderError::new(
                ErrorKind::InvalidRequest,
                &self.provider_name,
                claw_provider_sdk::Operation::ListModels,
                format!("configured model `{selected}` is absent from the provider catalogue"),
            ));
        }
        *self.models.write().unwrap_or_else(PoisonError::into_inner) = models;
        self.readiness.set("provider", true);
        Ok(())
    }

    /// Returns the provider identifier used in diagnostics.
    #[must_use]
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    /// Returns the selected default model.
    #[must_use]
    pub fn default_model(&self) -> String {
        self.default_model
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Changes the default model only when the startup catalogue proves it exists.
    ///
    /// # Errors
    ///
    /// Returns an error when the model cache lock is poisoned or `model` is not
    /// present in the live startup catalogue.
    pub fn set_default_model(&self, model: &str) -> Result<(), String> {
        if !self
            .models
            .read()
            .map_err(|_| "provider model lock failed".to_owned())?
            .iter()
            .any(|descriptor| descriptor.id.as_str() == model)
        {
            return Err(format!(
                "model `{model}` is not in the live provider catalogue"
            ));
        }
        let mut selected = self
            .default_model
            .write()
            .map_err(|_| "provider model lock failed".to_owned())?;
        model.clone_into(&mut selected);
        drop(selected);
        Ok(())
    }

    /// Returns cached public model identities.
    ///
    /// # Errors
    ///
    /// Returns an internal port error when the model cache lock is poisoned.
    pub fn model_ids(&self) -> Result<Vec<String>, PortError> {
        self.models
            .read()
            .map(|models| {
                models
                    .iter()
                    .map(|model| model.id.as_str().to_owned())
                    .collect()
            })
            .map_err(|_| PortError::new(PortErrorKind::Internal, "provider model lock failed"))
    }

    fn observe<T>(&self, result: &Result<T, ProviderError>) {
        match result {
            Ok(_) => self.readiness.set("provider", true),
            Err(error) => self.observe_error(error),
        }
    }

    fn observe_error(&self, error: &ProviderError) {
        if matches!(
            error.kind(),
            ErrorKind::Authentication
                | ErrorKind::Quota
                | ErrorKind::Transport
                | ErrorKind::Protocol
                | ErrorKind::Server
                | ErrorKind::Timeout
                | ErrorKind::CircuitOpen
        ) {
            self.readiness.set("provider", false);
        }
    }

    fn history(&self, session_id: &str) -> Vec<ChatMessage> {
        let mut history = self.history.lock().unwrap_or_else(PoisonError::into_inner);
        if !history.messages.contains_key(session_id) {
            return Vec::new();
        }
        touch(&mut history.recency, session_id);
        history
            .messages
            .get(session_id)
            .map(|messages| messages.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn remember(&self, session_id: &str, user: ChatMessage, assistant: AssistantMessage) {
        let mut history = self.history.lock().unwrap_or_else(PoisonError::into_inner);
        touch(&mut history.recency, session_id);
        let messages = history.messages.entry(session_id.to_owned()).or_default();
        messages.push_back(user);
        messages.push_back(ChatMessage::Assistant(assistant));
        while messages.len() > MAX_HISTORY_MESSAGES {
            messages.pop_front();
        }
        while history.messages.len() > MAX_CONVERSATIONS {
            let Some(oldest) = history.recency.pop_front() else {
                break;
            };
            if oldest != session_id {
                history.messages.remove(&oldest);
            }
        }
        drop(history);
    }

    async fn complete(
        &self,
        request: CompletionRequest,
        cancellation: CancellationToken,
    ) -> Result<CompletionResponse, ProviderError> {
        let cancel = CancelToken::new();
        let context = RequestContext::with_cancel(cancel.clone());
        let result = tokio::select! {
            result = self.provider.complete(&request, &context) => result,
            () = cancellation.cancelled() => {
                cancel.cancel();
                Err(ProviderError::new(
                    ErrorKind::Cancelled,
                    &self.provider_name,
                    claw_provider_sdk::Operation::Complete,
                    "request cancelled",
                ))
            }
        };
        self.observe(&result);
        result
    }
}

impl std::fmt::Debug for ProviderAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderAdapter")
            .field("provider", &self.provider_name)
            .field("default_model", &self.default_model())
            .field(
                "models",
                &self
                    .models
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .len(),
            )
            .finish_non_exhaustive()
    }
}

impl ProviderPort for ProviderAdapter {
    fn models(&self) -> PortFuture<'_, Result<Vec<Model>, PortError>> {
        Box::pin(async move {
            Ok(self
                .model_ids()?
                .into_iter()
                .map(|id| Model { id })
                .collect())
        })
    }

    fn generate(
        &self,
        request: GenerationRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<GenerationOutput, PortError>> {
        Box::pin(async move {
            let prepared = self.to_completion(request)?;
            let response = self
                .complete(prepared.request, cancellation)
                .await
                .map_err(|error| map_provider_error(&error))?;
            self.remember(
                &prepared.session_id,
                prepared.user,
                response.message.clone(),
            );
            Ok(output_from(response))
        })
    }

    fn stream(
        &self,
        request: GenerationRequest,
        events: mpsc::Sender<GenerationEvent>,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<HttpUsage, PortError>> {
        Box::pin(async move {
            let prepared = self.to_completion(request)?;
            let cancel = CancelToken::new();
            let context = RequestContext::with_cancel(cancel.clone());
            let opened = tokio::select! {
                result = self.provider.stream(&prepared.request, &context) => result,
                () = cancellation.cancelled() => {
                    cancel.cancel();
                    return Err(PortError::new(PortErrorKind::Unavailable, "request cancelled"));
                }
            };
            self.observe(&opened);
            let mut stream = opened.map_err(|error| map_provider_error(&error))?;
            let mut accumulator = StreamAccumulator::new();
            loop {
                let next = tokio::select! {
                    event = stream.next() => event,
                    () = cancellation.cancelled() => {
                        cancel.cancel();
                        return Err(PortError::new(PortErrorKind::Unavailable, "request cancelled"));
                    }
                };
                let Some(event) = next else {
                    break;
                };
                let event = match event {
                    Ok(event) => event,
                    Err(error) => {
                        self.observe_error(&error);
                        return Err(map_provider_error(&error));
                    }
                };
                accumulator.accept(&event);
                let outgoing = match event {
                    StreamEvent::TextDelta(text) => Some(GenerationEvent::Text(text)),
                    StreamEvent::ToolCallCompleted { call, .. } => {
                        Some(GenerationEvent::ToolCall(claw_http_api::ToolCall {
                            id: call.id,
                            name: call.name,
                            arguments: call.arguments.as_str().to_owned(),
                        }))
                    }
                    StreamEvent::UsageUpdate(_)
                    | StreamEvent::Completed { .. }
                    | StreamEvent::Started { .. }
                    | StreamEvent::ReasoningDelta(_)
                    | StreamEvent::ToolCallStarted { .. }
                    | StreamEvent::ToolCallArgumentsDelta { .. } => None,
                };
                if let Some(outgoing) = outgoing {
                    tokio::select! {
                        result = events.send(outgoing) => {
                            if result.is_err() {
                                cancel.cancel();
                                return Err(PortError::new(
                                    PortErrorKind::Unavailable,
                                    "stream consumer disconnected",
                                ));
                            }
                        }
                        () = cancellation.cancelled() => {
                            cancel.cancel();
                            return Err(PortError::new(
                                PortErrorKind::Unavailable,
                                "request cancelled",
                            ));
                        }
                    }
                }
            }
            self.readiness.set("provider", true);
            if accumulator.finish_reason().is_some() {
                self.remember(&prepared.session_id, prepared.user, accumulator.message());
            }
            Ok(http_usage(accumulator.usage()))
        })
    }

    fn embed(
        &self,
        request: EmbeddingRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<Vec<Vec<f32>>, PortError>> {
        Box::pin(async move {
            let request = claw_provider_sdk::EmbeddingsRequest {
                model: ModelId::new(request.model)
                    .map_err(|error| invalid_request(error.to_string()))?,
                inputs: request.input,
                dimensions: request
                    .dimensions
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| invalid_request("embedding dimensions exceed u32"))?,
            };
            request
                .validate()
                .map_err(|error| invalid_request(error.to_string()))?;
            let cancel = CancelToken::new();
            let context = RequestContext::with_cancel(cancel.clone());
            let result = tokio::select! {
                result = self.provider.embed(&request, &context) => result,
                () = cancellation.cancelled() => {
                    cancel.cancel();
                    return Err(PortError::new(PortErrorKind::Unavailable, "request cancelled"));
                }
            };
            self.observe(&result);
            let mut response = result.map_err(|error| map_provider_error(&error))?;
            response.embeddings.sort_by_key(|embedding| embedding.index);
            Ok(response
                .embeddings
                .into_iter()
                .map(|embedding| embedding.vector)
                .collect())
        })
    }
}

impl ProviderAdapter {
    fn to_completion(&self, request: GenerationRequest) -> Result<PreparedCompletion, PortError> {
        if request.frequency_penalty.is_some_and(|value| value != 0.0)
            || request.presence_penalty.is_some_and(|value| value != 0.0)
        {
            return Err(invalid_request(
                "the configured provider does not support frequency or presence penalties",
            ));
        }
        if request.max_tool_calls.is_some() {
            return Err(invalid_request(
                "the configured provider does not support max_tool_calls",
            ));
        }

        let session_id = request.session_id.clone();
        let model = if matches!(
            request.model.trim(),
            "" | "openclaw" | "openclaw/default" | "openclaw/main"
        ) {
            self.default_model()
        } else {
            request.model
        };
        let mut messages = Vec::new();
        if !self.role_prompt.is_empty() {
            messages.push(ChatMessage::System(self.role_prompt.clone()));
        }
        if let Some(instructions) = request.instructions {
            messages.push(ChatMessage::System(instructions));
        }
        messages.extend(self.history(&session_id));
        let mut content = vec![ContentPart::text(request.prompt)];
        for media in request.media {
            if media.kind != claw_http_api::InputMediaKind::Image {
                return Err(invalid_request(
                    "file inputs are not implemented by the configured provider adapter",
                ));
            }
            let source = match media.source {
                claw_http_api::InputMediaSource::Url(raw) => ImageSource::Url(
                    raw.parse()
                        .map_err(|_| invalid_request("image URL is invalid"))?,
                ),
                claw_http_api::InputMediaSource::Base64 {
                    media_type, data, ..
                } => {
                    let media_type = match media_type.as_str() {
                        "image/png" => ImageMediaType::Png,
                        "image/jpeg" => ImageMediaType::Jpeg,
                        "image/gif" => ImageMediaType::Gif,
                        "image/webp" => ImageMediaType::Webp,
                        _ => return Err(invalid_request("image media type is not supported")),
                    };
                    content.push(ContentPart::Image(ImagePart {
                        media_type,
                        source: ImageSource::Base64(data),
                    }));
                    continue;
                }
            };
            content.push(ContentPart::Image(ImagePart {
                media_type: ImageMediaType::Png,
                source,
            }));
        }
        let user = ChatMessage::User(content);
        messages.push(user.clone());

        let mut completion = CompletionRequest::new(
            ModelId::new(model).map_err(|error| invalid_request(error.to_string()))?,
            messages,
        );
        completion.tools = request
            .tools
            .into_iter()
            .map(|tool| {
                Ok(ToolDefinition {
                    name: tool.name,
                    description: tool.description.unwrap_or_default(),
                    parameters: tool
                        .parameters
                        .map(ToolParameters::new)
                        .transpose()
                        .map_err(|error| invalid_request(error.to_string()))?
                        .unwrap_or_else(ToolParameters::empty),
                })
            })
            .collect::<Result<_, PortError>>()?;
        completion.tool_choice = match request.tool_choice {
            claw_http_api::ToolChoice::Auto => ProviderToolChoice::Auto,
            claw_http_api::ToolChoice::None => ProviderToolChoice::None,
            claw_http_api::ToolChoice::Required => ProviderToolChoice::Required,
            claw_http_api::ToolChoice::Function(name) => ProviderToolChoice::Function(name),
        };
        completion.max_output_tokens = request
            .max_tokens
            .map(u32::try_from)
            .transpose()
            .map_err(|_| invalid_request("max_tokens exceeds u32"))?;
        completion.temperature_milli =
            scaled_thousand(request.temperature, 2.0, true, "temperature")?;
        completion.top_p_milli = scaled_thousand(request.top_p, 1.0, false, "top_p")?;
        completion.stop_sequences = request.stop.unwrap_or_default();
        completion.seed = request
            .seed
            .map(u64::try_from)
            .transpose()
            .map_err(|_| invalid_request("seed must be non-negative"))?;
        completion.response_format = match request
            .response_format
            .as_ref()
            .and_then(|value| value.get("type"))
            .and_then(Value::as_str)
        {
            Some("json_object") => ResponseFormat::JsonObject,
            Some("text") | None => ResponseFormat::Text,
            Some(_) => return Err(invalid_request("response format is not supported")),
        };
        completion
            .validate()
            .map_err(|error| invalid_request(error.to_string()))?;
        Ok(PreparedCompletion {
            request: completion,
            session_id,
            user,
        })
    }
}

fn touch(recency: &mut VecDeque<String>, session_id: &str) {
    if let Some(position) = recency.iter().position(|candidate| candidate == session_id) {
        recency.remove(position);
    }
    recency.push_back(session_id.to_owned());
}

fn scaled_thousand(
    value: Option<f64>,
    maximum: f64,
    allow_zero: bool,
    field: &str,
) -> Result<Option<u16>, PortError> {
    value
        .map(|value| {
            if !value.is_finite() || value < 0.0 || (!allow_zero && value == 0.0) || value > maximum
            {
                return Err(invalid_request(format!(
                    "{field} is outside its supported range"
                )));
            }
            (value * 1_000.0)
                .round()
                .to_string()
                .parse::<u16>()
                .map_err(|_| invalid_request(format!("{field} cannot be represented")))
        })
        .transpose()
}

fn output_from(response: CompletionResponse) -> GenerationOutput {
    GenerationOutput {
        text: response.message.text(),
        tool_calls: response
            .message
            .tool_calls
            .into_iter()
            .map(|call| claw_http_api::ToolCall {
                id: call.id,
                name: call.name,
                arguments: call.arguments.as_str().to_owned(),
            })
            .collect(),
        usage: http_usage(response.usage),
    }
}

const fn http_usage(usage: Usage) -> HttpUsage {
    HttpUsage {
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        total_tokens: usage.total_tokens(),
    }
}

fn map_provider_error(error: &ProviderError) -> PortError {
    let kind = match error.kind() {
        ErrorKind::InvalidRequest => PortErrorKind::InvalidRequest,
        ErrorKind::Timeout => PortErrorKind::Timeout,
        ErrorKind::Unsupported => PortErrorKind::NotFound,
        ErrorKind::Protocol => PortErrorKind::Internal,
        ErrorKind::Authentication
        | ErrorKind::RateLimit
        | ErrorKind::Quota
        | ErrorKind::Transport
        | ErrorKind::Server
        | ErrorKind::Cancelled
        | ErrorKind::CircuitOpen => PortErrorKind::Unavailable,
    };
    PortError::new(kind, error.to_string())
}

fn invalid_request(message: impl Into<String>) -> PortError {
    PortError::new(PortErrorKind::InvalidRequest, message)
}

/// Result of one transactional configuration reload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedReload {
    /// New generation after commit.
    pub generation: u64,
    /// Changed domain names.
    pub changed: Vec<String>,
}

/// Last-known-good configuration owner and hot-reload transaction.
#[derive(Debug)]
pub struct ConfigController {
    state: Mutex<ConfigState>,
    provider: Arc<ProviderAdapter>,
    diagnostics: Arc<Diagnostics>,
}

#[derive(Debug)]
struct ConfigState {
    manager: ReloadManager,
    generation: u64,
}

impl ConfigController {
    /// Creates a controller over the startup snapshot.
    #[must_use]
    pub fn new(
        initial: ConfigSnapshot,
        provider: Arc<ProviderAdapter>,
        diagnostics: Arc<Diagnostics>,
    ) -> Self {
        Self {
            state: Mutex::new(ConfigState {
                manager: ReloadManager::new(initial),
                generation: 0,
            }),
            provider,
            diagnostics,
        }
    }

    /// Returns the current immutable snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the reload-manager lock is poisoned.
    pub fn snapshot(&self) -> Result<Arc<ConfigSnapshot>, String> {
        self.state
            .lock()
            .map(|state| state.manager.snapshot())
            .map_err(|_| "configuration reload lock is poisoned".to_owned())
    }

    /// Returns the committed generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .generation
    }

    /// Returns model selection and generation from one reload synchronization boundary.
    #[must_use]
    pub fn model_generation(&self) -> (String, u64) {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let status = (self.provider.default_model(), state.generation);
        drop(state);
        status
    }

    /// Parses, validates, prepares, and atomically commits one candidate.
    ///
    /// # Errors
    ///
    /// Returns the typed parse/validation failure, a hot-swap classification
    /// failure, or a provider model refusal. Every failure restores the previous
    /// manager and provider selection before it returns.
    pub fn apply_json5(&self, source: &str, source_name: &str) -> Result<AppliedReload, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "configuration reload lock is poisoned".to_owned())?;
        let previous = state.manager.snapshot();
        let previous_timeout = copilot_request_timeout_ms(&previous)?;
        let outcome = state
            .manager
            .reload_json5(source, source_name)
            .map_err(|error| error.to_string())?;
        let candidate_timeout = match copilot_request_timeout_ms(&outcome.snapshot) {
            Ok(timeout) => timeout,
            Err(error) => {
                state.manager = ReloadManager::new((*previous).clone());
                return Err(format!("reload rolled back: {error}"));
            }
        };
        let has_unsupported = outcome
            .changed_domains
            .iter()
            .copied()
            .any(|domain| domain != ConfigDomain::Copilot);
        if !outcome.restart_required_domains.is_empty()
            || has_unsupported
            || previous_timeout != candidate_timeout
        {
            state.manager = ReloadManager::new((*previous).clone());
            return Err(format!(
                "reload requires a restart or changes an adapter that is not hot-swappable: {:?}",
                outcome.changed_domains
            ));
        }
        let previous_model = previous.core().copilot().default_model();
        let candidate_model = outcome.snapshot.core().copilot().default_model();
        if previous_model != candidate_model && self.provider.default_model() != previous_model {
            state.manager = ReloadManager::new((*previous).clone());
            return Err(
                "reload rolled back: the remote role owns model selection for this run".to_owned(),
            );
        }
        if previous_model != candidate_model
            && let Err(error) = self.provider.set_default_model(candidate_model)
        {
            state.manager = ReloadManager::new((*previous).clone());
            return Err(format!("reload rolled back: {error}"));
        }
        state.generation = state.generation.saturating_add(1);
        let generation = state.generation;
        let changed = outcome
            .changed_domains
            .iter()
            .map(|domain| format!("{domain:?}").to_ascii_lowercase())
            .collect::<Vec<_>>();
        drop(state);
        self.diagnostics.record(format!(
            "configuration generation {generation} committed ({})",
            if changed.is_empty() {
                "no changes".to_owned()
            } else {
                changed.join(",")
            }
        ));
        Ok(AppliedReload {
            generation,
            changed,
        })
    }
}

/// Reads the typed Copilot timeout through the crate's deterministic public
/// serializer until `claw-config` exposes a direct accessor.
pub(crate) fn copilot_request_timeout_ms(snapshot: &ConfigSnapshot) -> Result<u64, String> {
    let encoded = to_json5(snapshot).map_err(|error| error.to_string())?;
    let value = json5::from_str::<Value>(&encoded).map_err(|error| error.to_string())?;
    value
        .get("core")
        .and_then(|core| core.get("copilot"))
        .and_then(|copilot| copilot.get("request_timeout_ms"))
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            "serialized configuration omitted core.copilot.request_timeout_ms".to_owned()
        })
}

/// Reads whether the typed configuration requests signed update checks.
pub(crate) fn updates_enabled(snapshot: &ConfigSnapshot) -> Result<bool, String> {
    let encoded = to_json5(snapshot).map_err(|error| error.to_string())?;
    let value = json5::from_str::<Value>(&encoded).map_err(|error| error.to_string())?;
    value
        .get("core")
        .and_then(|core| core.get("updates"))
        .and_then(|updates| updates.get("enabled"))
        .and_then(Value::as_bool)
        .ok_or_else(|| "serialized configuration omitted core.updates.enabled".to_owned())
}

/// Durable JSON-lines adapter for HTTP authorization decisions.
#[derive(Debug)]
pub struct DurableSecurityAudit {
    file: Mutex<File>,
    readiness: Arc<DependencyReadiness>,
}

impl DurableSecurityAudit {
    /// Opens the append-only audit file.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error raised while opening the file.
    pub fn open(path: &Path, readiness: Arc<DependencyReadiness>) -> io::Result<Self> {
        Ok(Self {
            file: Mutex::new(OpenOptions::new().create(true).append(true).open(path)?),
            readiness,
        })
    }
}

impl AuditPort for DurableSecurityAudit {
    fn persist(&self, event: &AuditEvent) -> Result<(), PortError> {
        let result = (|| {
            let encoded = serde_json::to_vec(&json!({
                "action": audit_action(event.action),
                "subject": audit_subject(&event.subject),
                "outcome": audit_outcome(event.outcome),
                "reason": audit_reason(event.reason),
                "unixMillis": event.unix_millis,
            }))
            .map_err(|_| PortError::new(PortErrorKind::Internal, "audit encoding failed"))?;
            let mut file = self
                .file
                .lock()
                .map_err(|_| PortError::new(PortErrorKind::Internal, "audit writer lock failed"))?;
            file.write_all(&encoded)
                .and_then(|()| file.write_all(b"\n"))
                .and_then(|()| file.flush())
                .and_then(|()| file.sync_data())
                .map_err(|_| PortError::new(PortErrorKind::Unavailable, "audit persistence failed"))
        })();
        self.readiness.set("audit", result.is_ok());
        result
    }
}

const fn audit_action(action: AuditAction) -> &'static str {
    match action {
        AuditAction::AuthorizationEvaluated => "authorization_evaluated",
        AuditAction::PairingChallengeIssued => "pairing_challenge_issued",
        AuditAction::PairingProofEvaluated => "pairing_proof_evaluated",
        AuditAction::PairingApprovalRequested => "pairing_approval_requested",
        AuditAction::PairingApproved => "pairing_approved",
        AuditAction::PairingDenied => "pairing_denied",
        AuditAction::PairingExpired => "pairing_expired",
        AuditAction::PairingRevoked => "pairing_revoked",
        AuditAction::SecretResolutionAuthorized => "secret_resolution_authorized",
        AuditAction::SecretResolved => "secret_resolved",
    }
}

fn audit_subject(subject: &AuditSubject) -> String {
    match subject {
        AuditSubject::Device(device) => format!("device:{device}"),
        AuditSubject::Role(role) => format!("role:{}", role.as_str()),
        AuditSubject::SecretScheme(scheme) => format!("secret:{scheme}"),
    }
}

const fn audit_outcome(outcome: AuditOutcome) -> &'static str {
    match outcome {
        AuditOutcome::Allowed => "allowed",
        AuditOutcome::Denied => "denied",
    }
}

const fn audit_reason(reason: AuditReason) -> &'static str {
    match reason {
        AuditReason::PolicySatisfied => "policy_satisfied",
        AuditReason::PolicyRejected => "policy_rejected",
        AuditReason::IllegalTransition => "illegal_transition",
        AuditReason::InvalidProof => "invalid_proof",
        AuditReason::ReplayDetected => "replay_detected",
        AuditReason::Expired => "expired",
        AuditReason::ResolverFailed => "resolver_failed",
    }
}

/// Honest adapter for tool execution that has no thread-safe registry port yet.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableTools;

impl ToolPort for UnavailableTools {
    fn list(&self) -> PortFuture<'_, Result<Vec<HttpToolDefinition>, PortError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn invoke(
        &self,
        _invocation: ToolInvocation,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<HttpToolOutcome, PortError>> {
        Box::pin(async {
            Err(PortError::new(
                PortErrorKind::Unavailable,
                "tool execution is not configured",
            ))
        })
    }
}

/// Honest adapter for pairing, watch-node, and webhook ports not yet composable.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableExternalPorts;

impl WatchAuthPort for UnavailableExternalPorts {
    fn authenticate(
        &self,
        _connect: ConnectParams,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WatchIdentity, PortError>> {
        Box::pin(async {
            Err(PortError::new(
                PortErrorKind::Unavailable,
                "watch-node pairing is not configured",
            ))
        })
    }
}

impl WatchResultPort for UnavailableExternalPorts {
    fn handle(
        &self,
        _node_id: String,
        _result: Value,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<bool, PortError>> {
        Box::pin(async {
            Err(PortError::new(
                PortErrorKind::Unavailable,
                "watch-node result routing is not configured",
            ))
        })
    }
}

impl WebhookPort for UnavailableExternalPorts {
    fn invoke(
        &self,
        _route_id: String,
        _action: Value,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WebhookOutcome, PortError>> {
        Box::pin(async {
            Err(PortError::new(
                PortErrorKind::Unavailable,
                "webhook execution is not configured",
            ))
        })
    }
}

/// Immutable configuration and capability inventory exposed to operators.
#[derive(Debug)]
pub struct OperatorInventory {
    channels: Vec<Value>,
    skill_count: usize,
    updates_enabled: bool,
    config_resolution: Value,
}

impl OperatorInventory {
    /// Creates the immutable operator-facing inventory.
    #[must_use]
    pub const fn new(
        channels: Vec<Value>,
        skill_count: usize,
        updates_enabled: bool,
        config_resolution: Value,
    ) -> Self {
        Self {
            channels,
            skill_count,
            updates_enabled,
            config_resolution,
        }
    }
}

/// Useful subset of the frozen admin surface plus explicit unavailable errors.
#[derive(Debug)]
pub struct OperatorAdmin {
    config: Arc<ConfigController>,
    provider: Arc<ProviderAdapter>,
    readiness: Arc<DependencyReadiness>,
    diagnostics: Arc<Diagnostics>,
    inventory: OperatorInventory,
}

impl OperatorAdmin {
    /// Creates the operator adapter.
    #[must_use]
    pub const fn new(
        config: Arc<ConfigController>,
        provider: Arc<ProviderAdapter>,
        readiness: Arc<DependencyReadiness>,
        diagnostics: Arc<Diagnostics>,
        inventory: OperatorInventory,
    ) -> Self {
        Self {
            config,
            provider,
            readiness,
            diagnostics,
            inventory,
        }
    }

    fn status(&self) -> Result<Value, PortError> {
        let readiness = self.readiness.snapshot()?;
        let (model, generation) = self.config.model_generation();
        Ok(json!({
            "ready": readiness.ready,
            "failing": readiness.failing,
            "uptimeMs": readiness.uptime_ms,
            "provider": self.provider.provider_name(),
            "model": model,
            "configGeneration": generation,
            "configuration": self.inventory.config_resolution,
            "channels": self.inventory.channels,
            "skills": {
                "registered": self.inventory.skill_count,
                "active": 0,
                "state": "requires_native_ports",
            },
        }))
    }
}

impl AdminPort for OperatorAdmin {
    fn dispatch(
        &self,
        method: String,
        params: Option<Value>,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<AdminSuccess, AdminFailure>> {
        Box::pin(async move {
            let payload = match method.as_str() {
                "health" | "status" => self.status().map_err(admin_port_failure)?,
                "logs.tail" => json!({"entries": self.diagnostics.entries()}),
                "models.list" => {
                    json!({"models": self.provider.model_ids().map_err(admin_port_failure)?})
                }
                "models.authStatus" => {
                    json!({"ready": self.readiness.snapshot().map_err(admin_port_failure)?.ready})
                }
                "channels.status" => json!({"channels": self.inventory.channels}),
                "update.status" => json!({
                    "configured": self.inventory.updates_enabled,
                    "state": "external_updater_required",
                    "version": env!("CARGO_PKG_VERSION"),
                    "retryOwner": "gta-claw-updater",
                    "installCleanup": "updater_owned",
                    "daemonMutation": false,
                }),
                "config.get" => {
                    let snapshot = self.config.snapshot().map_err(admin_unavailable)?;
                    json!({"json5": to_json5(&snapshot).map_err(|error| admin_unavailable(error.to_string()))?})
                }
                "config.schema" => serde_json::from_str::<Value>(
                    &schema_json().map_err(|error| admin_unavailable(error.to_string()))?,
                )
                .map_err(|_| admin_unavailable("configuration schema encoding failed"))?,
                "config.apply" => {
                    let source = params
                        .as_ref()
                        .and_then(|value| value.get("source"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| admin_invalid("config.apply requires params.source"))?;
                    let source_name = params
                        .as_ref()
                        .and_then(|value| value.get("sourceName"))
                        .and_then(Value::as_str)
                        .unwrap_or("<admin>");
                    let applied = self
                        .config
                        .apply_json5(source, source_name)
                        .map_err(admin_invalid)?;
                    json!({"generation": applied.generation, "changed": applied.changed})
                }
                _ => {
                    return Err(AdminFailure {
                        code: "UNAVAILABLE".to_owned(),
                        message: format!(
                            "{method} is catalogued but has no production adapter in this build"
                        ),
                        details: None,
                        retryable: Some(false),
                        retry_after_ms: None,
                    });
                }
            };
            Ok(AdminSuccess {
                payload,
                meta: None,
            })
        })
    }
}

fn admin_invalid(message: impl Into<String>) -> AdminFailure {
    AdminFailure {
        code: "INVALID_REQUEST".to_owned(),
        message: message.into(),
        details: None,
        retryable: Some(false),
        retry_after_ms: None,
    }
}

fn admin_unavailable(message: impl Into<String>) -> AdminFailure {
    AdminFailure {
        code: "UNAVAILABLE".to_owned(),
        message: message.into(),
        details: None,
        retryable: Some(false),
        retry_after_ms: None,
    }
}

fn admin_port_failure(error: PortError) -> AdminFailure {
    admin_unavailable(error.message)
}

/// Deterministic local provider used only by the explicit `--smoke` mode.
#[derive(Debug)]
pub struct SmokeProvider {
    id: ProviderId,
    models: Vec<ModelDescriptor>,
}

impl SmokeProvider {
    /// Creates the local provider.
    ///
    /// # Errors
    ///
    /// Returns a model error only if one of the compile-time smoke identifiers
    /// no longer satisfies the provider SDK grammar.
    pub fn new() -> Result<Self, claw_provider_sdk::ModelError> {
        let capabilities = CapabilitySet::from_slice(&[
            Capability::Completion,
            Capability::Streaming,
            Capability::Embeddings,
            Capability::ModelListing,
        ]);
        Ok(Self {
            id: ProviderId::new("smoke")?,
            models: ["gpt-4o", "gpt-4.1"]
                .into_iter()
                .map(|name| {
                    Ok(ModelDescriptor {
                        id: ModelId::new(name)?,
                        display_name: Some(format!("Smoke {name}")),
                        context_window: Some(16_384),
                        max_output_tokens: Some(4_096),
                        capabilities,
                    })
                })
                .collect::<Result<_, claw_provider_sdk::ModelError>>()?,
        })
    }

    fn answer(request: &CompletionRequest) -> String {
        let prompt = request
            .messages
            .iter()
            .filter_map(|message| match message {
                ChatMessage::User(parts) => Some(
                    parts
                        .iter()
                        .filter_map(ContentPart::as_text)
                        .collect::<Vec<_>>()
                        .concat(),
                ),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(" | ");
        format!("smoke: {prompt}")
    }
}

impl Provider for SmokeProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> CapabilitySet {
        CapabilitySet::from_slice(&[
            Capability::Completion,
            Capability::Streaming,
            Capability::Embeddings,
            Capability::ModelListing,
        ])
    }

    fn complete<'a>(
        &'a self,
        request: &'a CompletionRequest,
        _context: &'a RequestContext,
    ) -> ProviderFuture<'a, Result<CompletionResponse, ProviderError>> {
        Box::pin(async move {
            Ok(CompletionResponse {
                id: "smoke-response".to_owned(),
                model: request.model.clone(),
                message: AssistantMessage {
                    content: vec![ContentPart::text(Self::answer(request))],
                    reasoning: None,
                    tool_calls: Vec::new(),
                },
                finish_reason: FinishReason::Stop,
                usage: Usage {
                    input_tokens: 1,
                    output_tokens: 1,
                    cached_input_tokens: 0,
                    reasoning_tokens: 0,
                },
            })
        })
    }

    fn stream<'a>(
        &'a self,
        request: &'a CompletionRequest,
        context: &'a RequestContext,
    ) -> ProviderFuture<'a, Result<CompletionStream, ProviderError>> {
        let answer = Self::answer(request);
        let model = request.model.as_str().to_owned();
        let cancel = context.cancel().clone();
        Box::pin(async move {
            let usage = Usage {
                input_tokens: 1,
                output_tokens: 1,
                cached_input_tokens: 0,
                reasoning_tokens: 0,
            };
            Ok(CompletionStream::new(
                "smoke",
                cancel,
                Box::pin(stream::iter(vec![
                    Ok(StreamEvent::Started {
                        id: "smoke-response".to_owned(),
                        model,
                    }),
                    Ok(StreamEvent::TextDelta(answer)),
                    Ok(StreamEvent::Completed {
                        finish_reason: FinishReason::Stop,
                        usage,
                    }),
                ])),
            ))
        })
    }

    fn embed<'a>(
        &'a self,
        request: &'a EmbeddingsRequest,
        _context: &'a RequestContext,
    ) -> ProviderFuture<'a, Result<EmbeddingsResponse, ProviderError>> {
        Box::pin(async move {
            Ok(EmbeddingsResponse {
                model: request.model.clone(),
                embeddings: request
                    .inputs
                    .iter()
                    .enumerate()
                    .map(|(index, input)| claw_provider_sdk::Embedding {
                        index,
                        vector: vec![f32::from(u16::try_from(input.len()).unwrap_or(u16::MAX))],
                    })
                    .collect(),
                usage: Usage {
                    input_tokens: u64::try_from(request.inputs.len()).unwrap_or(u64::MAX),
                    ..Usage::default()
                },
            })
        })
    }

    fn list_models<'a>(
        &'a self,
        _context: &'a RequestContext,
    ) -> ProviderFuture<'a, Result<Vec<ModelDescriptor>, ProviderError>> {
        Box::pin(async move { Ok(self.models.clone()) })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigController, DependencyReadiness, Diagnostics, ProviderAdapter, SmokeProvider,
        copilot_request_timeout_ms,
    };
    use std::sync::Arc;

    use claw_config::{migrate_legacy_environment, to_json5};

    fn snapshot(model: &str) -> claw_config::ConfigSnapshot {
        snapshot_with_timeout(model, "120000")
    }

    fn snapshot_with_timeout(model: &str, timeout: &str) -> claw_config::ConfigSnapshot {
        migrate_legacy_environment([
            ("GITHUB_TOKEN", "test"),
            ("ENABLE_TEAMS", "false"),
            ("COPILOT_MODEL", model),
            ("SDK_REQUEST_TIMEOUT_MS", timeout),
            ("AGENT_ROLE_URL", "https://example.test/role"),
        ])
        .expect("fixture config")
        .config
    }

    #[tokio::test]
    async fn a_rejected_reload_restores_the_last_known_good_model() {
        let readiness = Arc::new(DependencyReadiness::new(["provider"]));
        let provider = Arc::new(ProviderAdapter::new(
            Arc::new(SmokeProvider::new().expect("smoke provider")),
            "gpt-4o",
            "",
            Arc::clone(&readiness),
        ));
        provider.initialize().await.expect("provider starts");
        let controller = ConfigController::new(
            snapshot("gpt-4o"),
            Arc::clone(&provider),
            Arc::new(Diagnostics::new(8)),
        );
        let rejected = to_json5(&snapshot("not-a-live-model")).expect("serialize");

        let error = controller
            .apply_json5(&rejected, "candidate")
            .expect_err("unknown model must roll back");

        assert!(error.contains("rolled back"));
        assert_eq!(provider.default_model(), "gpt-4o");
        assert_eq!(controller.generation(), 0);
        assert_eq!(
            controller
                .snapshot()
                .expect("snapshot")
                .core()
                .copilot()
                .default_model(),
            "gpt-4o"
        );
    }

    #[tokio::test]
    async fn a_timeout_only_reload_is_rejected_instead_of_falsely_committed() {
        let readiness = Arc::new(DependencyReadiness::new(["provider"]));
        let provider = Arc::new(ProviderAdapter::new(
            Arc::new(SmokeProvider::new().expect("smoke provider")),
            "gpt-4o",
            "",
            Arc::clone(&readiness),
        ));
        provider.initialize().await.expect("provider starts");
        let controller = ConfigController::new(
            snapshot_with_timeout("gpt-4o", "120000"),
            provider,
            Arc::new(Diagnostics::new(8)),
        );
        let candidate =
            to_json5(&snapshot_with_timeout("gpt-4o", "2000")).expect("serialize candidate");

        let error = controller
            .apply_json5(&candidate, "candidate")
            .expect_err("the live transport timeout is not hot-swappable");

        assert!(error.contains("not hot-swappable"));
        assert_eq!(controller.generation(), 0);
        assert_eq!(
            copilot_request_timeout_ms(&controller.snapshot().expect("snapshot"))
                .expect("timeout remains readable"),
            120_000
        );
    }
}

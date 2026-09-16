//! Concrete adapters for the shipped HTTP surface.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Instant;

use claw_config::{ConfigDomain, ConfigSnapshot, ReloadManager, schema_json, to_json5};
use claw_http_api::{
    AdminFailure, AdminPort, AdminSuccess, AuditPort, EmbeddingRequest, GenerationEvent,
    GenerationOutput, GenerationRequest, Model, PortError, PortErrorKind, PortFuture, ProviderPort,
    ReadinessPort, ReadinessSnapshot, ToolDefinition as HttpToolDefinition, Usage as HttpUsage,
    WatchAuthPort, WatchIdentity, WatchResultPort, WebhookOutcome, WebhookPort,
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
    ProviderPhase, ProviderStatus, RequestContext, StreamEvent,
};
use claw_providers::ProviderSlot;
use claw_security::audit::{AuditAction, AuditEvent, AuditOutcome, AuditReason, AuditSubject};
use futures_util::{StreamExt, stream};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

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

    pub(crate) fn set_and_aggregate(
        &self,
        name: &'static str,
        ready: bool,
        aggregate: &'static str,
        members: impl IntoIterator<Item = &'static str>,
    ) {
        let mut dependencies = self
            .dependencies
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        dependencies.insert(name, ready);
        let aggregate_ready = members
            .into_iter()
            .all(|member| dependencies.get(member).copied().unwrap_or(false));
        dependencies.insert(aggregate, aggregate_ready);
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

/// Synchronous projection of host-registered tools into provider declarations.
pub trait ModelToolCatalog: Send + Sync {
    /// Returns the current ordered tool definitions.
    fn definitions(&self) -> Vec<HttpToolDefinition>;
}

/// Empty model tool catalogue.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyModelTools;

impl ModelToolCatalog for EmptyModelTools {
    fn definitions(&self) -> Vec<HttpToolDefinition> {
        Vec::new()
    }
}

/// Dynamic runtime state projected into operator status.
pub trait OperatorRuntimeStatus: Send + Sync {
    /// Returns a machine-readable bounded status snapshot.
    fn status(&self) -> Value;

    /// Dispatches one runtime-owned admin method.
    fn dispatch<'a>(
        &'a self,
        method: &'a str,
        params: Option<&'a Value>,
        cancellation: CancellationToken,
    ) -> PortFuture<'a, Result<Option<Value>, PortError>>;
}

/// Durable Gateway device-pairing administration.
pub trait GatewayPairingAdmin: std::fmt::Debug + Send + Sync {
    /// Dispatches one device/node pairing method when owned by this adapter.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid, persistence, or internal-state failure.
    fn dispatch(&self, method: &str, params: Option<&Value>) -> Result<Option<Value>, PortError>;
}

/// HTTP/provider-SDK bridge with a startup-populated model cache.
#[derive(Clone, Copy, Debug)]
pub struct ProviderHistoryConfig {
    /// Maximum retained conversation histories.
    pub max_conversations: usize,
    /// Inactive history retention.
    pub idle_timeout: std::time::Duration,
}

impl Default for ProviderHistoryConfig {
    fn default() -> Self {
        Self {
            max_conversations: 100,
            idle_timeout: std::time::Duration::from_mins(30),
        }
    }
}

/// HTTP/provider-SDK bridge with a startup-populated model cache.
pub struct ProviderAdapter {
    provider: Arc<dyn Provider>,
    provider_name: String,
    default_model: RwLock<String>,
    model_aliases: Vec<(ModelId, ModelId)>,
    role_prompt: RwLock<String>,
    models: RwLock<Vec<ModelDescriptor>>,
    catalogue_observed_at_ms: std::sync::atomic::AtomicU64,
    history: Mutex<ConversationHistory>,
    history_config: ProviderHistoryConfig,
    model_tools: Arc<dyn ModelToolCatalog>,
    readiness: Arc<DependencyReadiness>,
    ready_gate: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
struct ConversationHistory {
    messages: BTreeMap<String, HistoryEntry>,
}

#[derive(Debug)]
struct HistoryEntry {
    messages: VecDeque<ChatMessage>,
    seen: Instant,
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
        history_config: ProviderHistoryConfig,
        model_tools: Arc<dyn ModelToolCatalog>,
        readiness: Arc<DependencyReadiness>,
        ready_gate: Arc<AtomicBool>,
    ) -> Self {
        Self {
            provider_name: provider.id().as_str().to_owned(),
            provider,
            default_model: RwLock::new(default_model.into()),
            model_aliases: Vec::new(),
            role_prompt: RwLock::new(role_prompt.into()),
            models: RwLock::new(Vec::new()),
            catalogue_observed_at_ms: std::sync::atomic::AtomicU64::new(0),
            history: Mutex::new(ConversationHistory::default()),
            history_config,
            model_tools,
            readiness,
            ready_gate,
        }
    }

    /// Pings the provider and fills the model cache before ingress is exposed.
    ///
    /// # Errors
    ///
    /// Returns the provider's typed model-listing error, or an invalid-request
    /// error when the configured default is absent from the live catalogue.
    pub async fn initialize(&self, context: &RequestContext) -> Result<(), ProviderError> {
        let models = self.provider.list_models(context).await?;
        Self::validate_catalogue(&self.provider_name, &models, &self.default_model())?;
        self.validate_model_aliases(&models)?;
        *self.models.write().unwrap_or_else(PoisonError::into_inner) = models;
        self.catalogue_observed_at_ms
            .store(Self::catalogue_time(), Ordering::Release);
        Ok(())
    }

    fn validate_model_aliases(
        &self,
        models: &[ModelDescriptor],
    ) -> Result<claw_provider_sdk::ModelAliasTable, ProviderError> {
        claw_provider_sdk::ModelAliasTable::new(models, self.model_aliases.iter().cloned()).map_err(
            |error| {
                ProviderError::new(
                    ErrorKind::InvalidRequest,
                    &self.provider_name,
                    claw_provider_sdk::Operation::ListModels,
                    error.to_string(),
                )
            },
        )
    }

    fn resolve_model_id(&self, requested: &str) -> Result<ModelId, PortError> {
        let requested = if matches!(
            requested.trim(),
            "" | "openclaw" | "openclaw/default" | "openclaw/main"
        ) {
            self.default_model()
        } else {
            requested.to_owned()
        };
        let requested =
            ModelId::new(requested).map_err(|error| invalid_request(error.to_string()))?;
        let models = self
            .models
            .read()
            .map_err(|_| invalid_request("model catalogue is unavailable"))?;
        let aliases = self
            .validate_model_aliases(&models)
            .map_err(|error| map_provider_error(&error))?;
        drop(models);
        aliases.resolve(&requested).cloned().ok_or_else(|| {
            invalid_request(
                "requested model or alias is absent from the current provider catalogue",
            )
        })
    }

    fn catalogue_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .unwrap_or(0)
    }

    fn validate_catalogue(
        provider_name: &str,
        models: &[ModelDescriptor],
        selected: &str,
    ) -> Result<(), ProviderError> {
        let mut identities = BTreeSet::new();
        if models.len() > 1024
            || models.iter().any(|model| {
                !identities.insert(model.id.as_str())
                    || model.display_name.as_deref().is_some_and(|name| {
                        name.trim().is_empty()
                            || name.len() > 512
                            || name.chars().any(char::is_control)
                    })
                    || model.context_window == Some(0)
                    || model.max_output_tokens == Some(0)
                    || model
                        .context_window
                        .zip(model.max_output_tokens)
                        .is_some_and(|(context, output)| output > context)
            })
        {
            return Err(ProviderError::new(
                ErrorKind::InvalidRequest,
                provider_name,
                claw_provider_sdk::Operation::ListModels,
                "provider catalogue has duplicate IDs, invalid model descriptors or more than 1024 entries",
            ));
        }
        if !models.iter().any(|model| model.id.as_str() == selected) {
            return Err(ProviderError::new(
                ErrorKind::InvalidRequest,
                provider_name,
                claw_provider_sdk::Operation::ListModels,
                format!("configured model `{selected}` is absent from the provider catalogue"),
            ));
        }
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

    /// Replaces the role prompt used by subsequent requests.
    pub fn set_role_prompt(&self, prompt: &str) {
        let mut role = self
            .role_prompt
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        prompt.clone_into(&mut role);
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
            Ok(_) if self.ready_gate.load(Ordering::Acquire) => {
                self.readiness.set("provider", true);
            }
            Ok(_) => {}
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
        let now = Instant::now();
        let mut history = self.history.lock().unwrap_or_else(PoisonError::into_inner);
        history
            .messages
            .retain(|_, entry| now.duration_since(entry.seen) < self.history_config.idle_timeout);
        history
            .messages
            .get_mut(session_id)
            .map(|entry| {
                entry.seen = now;
                entry.messages.iter().cloned().collect()
            })
            .unwrap_or_default()
    }

    fn remember(&self, session_id: &str, user: ChatMessage, assistant: AssistantMessage) {
        let now = Instant::now();
        let mut history = self.history.lock().unwrap_or_else(PoisonError::into_inner);
        history
            .messages
            .retain(|_, entry| now.duration_since(entry.seen) < self.history_config.idle_timeout);
        if !history.messages.contains_key(session_id)
            && history.messages.len() >= self.history_config.max_conversations.max(1)
            && let Some(oldest) = history
                .messages
                .iter()
                .min_by_key(|(_, entry)| entry.seen)
                .map(|(id, _)| id.clone())
        {
            history.messages.remove(&oldest);
        }
        let entry = history
            .messages
            .entry(session_id.to_owned())
            .or_insert_with(|| HistoryEntry {
                messages: VecDeque::new(),
                seen: now,
            });
        entry.seen = now;
        entry.messages.push_back(user);
        entry.messages.push_back(ChatMessage::Assistant(assistant));
        while entry.messages.len() > MAX_HISTORY_MESSAGES {
            entry.messages.pop_front();
        }
        drop(history);
    }

    fn clear_history(&self) {
        self.history
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .messages
            .clear();
    }

    async fn complete(
        &self,
        request: CompletionRequest,
        cancellation: CancellationToken,
    ) -> Result<CompletionResponse, ProviderError> {
        self.validate_model_request(&request, claw_provider_sdk::Operation::Complete)?;
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

    fn validate_model_request(
        &self,
        request: &CompletionRequest,
        operation: claw_provider_sdk::Operation,
    ) -> Result<(), ProviderError> {
        let mut required = vec![Capability::Completion];
        if operation == claw_provider_sdk::Operation::StreamCompletion {
            required.push(Capability::Streaming);
        }
        if !request.tools.is_empty()
            || request.parallel_tool_calls == Some(true)
            || matches!(request.tool_choice,ProviderToolChoice::Required|ProviderToolChoice::Function(_))
            || request.messages.iter().any(|message| matches!(message,ChatMessage::ToolResult(_))
                || matches!(message,ChatMessage::Assistant(assistant) if !assistant.tool_calls.is_empty()))
        {required.push(Capability::ToolCalling);}
        if request.messages.iter().any(|message| match message {
            ChatMessage::User(parts) => parts
                .iter()
                .any(|part| matches!(part, ContentPart::Image(_))),
            ChatMessage::Assistant(assistant) => assistant
                .content
                .iter()
                .any(|part| matches!(part, ContentPart::Image(_))),
            ChatMessage::System(_) | ChatMessage::ToolResult(_) => false,
        }) {
            required.push(Capability::Vision);
        }
        if request.response_format != ResponseFormat::Text {
            required.push(Capability::JsonMode);
        }
        self.validate_model_operation(
            &request.model,
            &required,
            request.max_output_tokens,
            operation,
        )
    }

    fn validate_model_operation(
        &self,
        model_id: &ModelId,
        required: &[Capability],
        max_output_tokens: Option<u32>,
        operation: claw_provider_sdk::Operation,
    ) -> Result<(), ProviderError> {
        let invalid = |message| {
            ProviderError::new(
                ErrorKind::InvalidRequest,
                &self.provider_name,
                operation,
                message,
            )
        };
        let models = self
            .models
            .read()
            .map_err(|_| invalid("model catalogue is unavailable"))?;
        let model = models
            .iter()
            .find(|model| model.id == *model_id)
            .ok_or_else(|| {
                invalid("requested model is absent from the current provider catalogue")
            })?;
        let capabilities = model.capabilities;
        let output_limit = model.max_output_tokens;
        let context_limit = model.context_window;
        drop(models);
        let required = CapabilitySet::from_slice(required);
        if !self.provider.capabilities().contains_all(required)
            || !capabilities.is_empty() && !capabilities.contains_all(required)
        {
            return Err(invalid(
                "requested operation is not supported by the configured provider or the model's advertised capabilities",
            ));
        }
        if max_output_tokens == Some(0)
            || max_output_tokens
                .zip(output_limit)
                .is_some_and(|(requested, limit)| requested > limit)
            || max_output_tokens
                .zip(context_limit)
                .is_some_and(|(requested, limit)| requested > limit)
        {
            return Err(invalid(
                "requested output exceeds the selected model's advertised output limit",
            ));
        }
        Ok(())
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
            let finish_reason = generation_finish_reason(
                &response.finish_reason,
                !response.message.tool_calls.is_empty(),
            )?;
            if finish_reason.is_complete() {
                self.remember(
                    &prepared.session_id,
                    prepared.user,
                    response.message.clone(),
                );
            }
            Ok(output_from(response, finish_reason))
        })
    }

    fn stream(
        &self,
        request: GenerationRequest,
        events: mpsc::Sender<GenerationEvent>,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<claw_http_api::GenerationSummary, PortError>> {
        Box::pin(async move {
            let prepared = self.to_completion(request)?;
            self.validate_model_request(
                &prepared.request,
                claw_provider_sdk::Operation::StreamCompletion,
            )
            .map_err(|error| map_provider_error(&error))?;
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
                    StreamEvent::ToolCallCompleted { .. }
                    | StreamEvent::UsageUpdate(_)
                    | StreamEvent::UsageReported { .. }
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
            if self.ready_gate.load(Ordering::Acquire) {
                self.readiness.set("provider", true);
            }
            if accumulator.finish_reason().is_none() {
                let error = ProviderError::new(
                    ErrorKind::Protocol,
                    &self.provider_name,
                    claw_provider_sdk::Operation::StreamCompletion,
                    "provider stream ended before its completion event",
                );
                self.observe_error(&error);
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "provider stream ended before completion",
                ));
            }
            let message = accumulator.message();
            let finish_reason = generation_finish_reason(
                accumulator.finish_reason().expect("completion was checked"),
                !message.tool_calls.is_empty(),
            )?;
            for call in &message.tool_calls {
                let outgoing = GenerationEvent::ToolCall(claw_http_api::ToolCall {
                    id: call.id.clone(),
                    name: call.name.clone(),
                    arguments: call.arguments.as_str().to_owned(),
                });
                tokio::select! {
                    result = events.send(outgoing) => {
                        if result.is_err() {
                            cancel.cancel();
                            return Err(PortError::new(PortErrorKind::Unavailable, "stream consumer disconnected"));
                        }
                    }
                    () = cancellation.cancelled() => {
                        cancel.cancel();
                        return Err(PortError::new(PortErrorKind::Unavailable, "request cancelled"));
                    }
                }
            }
            if finish_reason.is_complete() {
                self.remember(&prepared.session_id, prepared.user, message);
            }
            Ok(claw_http_api::GenerationSummary {
                usage: http_usage(accumulator.usage()),
                usage_reporting: usage_reporting(accumulator.usage_reporting()),
                finish_reason,
            })
        })
    }

    fn embed(
        &self,
        request: EmbeddingRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<Vec<Vec<f32>>, PortError>> {
        Box::pin(async move {
            let request = claw_provider_sdk::EmbeddingsRequest {
                model: self.resolve_model_id(&request.model)?,
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
            self.validate_model_operation(
                &request.model,
                &[Capability::Embeddings],
                None,
                claw_provider_sdk::Operation::Embed,
            )
            .map_err(|error| map_provider_error(&error))?;
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

/// Provider port that can start unauthenticated and atomically activate later.
pub struct SwappableProvider {
    slot: Arc<ProviderSlot>,
    shutdown_cancel: CancelToken,
    catalogue_refresh: tokio::sync::Mutex<()>,
    state: RwLock<SwappableState>,
    history_config: ProviderHistoryConfig,
    model_tools: Arc<dyn ModelToolCatalog>,
    readiness: Arc<DependencyReadiness>,
    ready_gate: Arc<AtomicBool>,
}

struct SwappableState {
    current: Option<Arc<ProviderAdapter>>,
    unavailable_reason: claw_protocol::native_models::CatalogueUnavailableReason,
    default_model: String,
    default_model_locked: bool,
    model_aliases: Vec<(ModelId, ModelId)>,
    role_prompt: String,
    generation: u64,
    retired: bool,
}

struct ProviderActivationGuard(Option<CancelToken>);

impl ProviderActivationGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ProviderActivationGuard {
    fn drop(&mut self) {
        if let Some(cancel) = self.0.take() {
            cancel.cancel();
        }
    }
}

impl SwappableProvider {
    /// Creates an unauthenticated provider slot.
    #[must_use]
    pub fn new(
        default_model: impl Into<String>,
        role_prompt: impl Into<String>,
        history_config: ProviderHistoryConfig,
        model_tools: Arc<dyn ModelToolCatalog>,
        readiness: Arc<DependencyReadiness>,
    ) -> Self {
        Self {
            slot: Arc::new(ProviderSlot::new()),
            shutdown_cancel: CancelToken::new(),
            catalogue_refresh: tokio::sync::Mutex::new(()),
            state: RwLock::new(SwappableState {
                current: None,
                unavailable_reason:
                    claw_protocol::native_models::CatalogueUnavailableReason::NotInitialized,
                default_model: default_model.into(),
                default_model_locked: false,
                model_aliases: Vec::new(),
                role_prompt: role_prompt.into(),
                generation: 0,
                retired: false,
            }),
            history_config,
            model_tools,
            readiness,
            ready_gate: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Records an explicit startup state before any provider has been published.
    ///
    /// # Errors
    /// Rejects active, retired or already configured slots and non-startup reasons.
    pub(crate) fn configure_initial_unavailability(
        &self,
        reason: claw_protocol::native_models::CatalogueUnavailableReason,
    ) -> Result<(), String> {
        use claw_protocol::native_models::CatalogueUnavailableReason;
        let mut state = self
            .state
            .write()
            .map_err(|_| "provider slot is unavailable".to_owned())?;
        if state.current.is_some()
            || state.retired
            || state.unavailable_reason != CatalogueUnavailableReason::NotInitialized
            || !matches!(
                reason,
                CatalogueUnavailableReason::Disabled
                    | CatalogueUnavailableReason::AuthenticationPending
            )
        {
            return Err(
                "provider availability requires a new trusted startup configuration".to_owned(),
            );
        }
        state.unavailable_reason = reason;
        state.generation = state.generation.saturating_add(1);
        drop(state);
        Ok(())
    }

    /// Configures explicit model aliases before any provider has been published.
    ///
    /// # Errors
    /// Rejects an active or retired provider, more than 128 aliases or a poisoned slot.
    /// Targets and collisions are validated against the complete startup catalogue.
    pub fn configure_model_aliases(&self, aliases: Vec<(ModelId, ModelId)>) -> Result<(), String> {
        if aliases.len() > 128 {
            return Err("model alias configuration exceeds 128 entries".to_owned());
        }
        let mut state = self
            .state
            .write()
            .map_err(|_| "provider slot is unavailable".to_owned())?;
        if state.current.is_some() || state.retired {
            return Err("model aliases require a new trusted startup configuration".to_owned());
        }
        state.model_aliases = aliases;
        state.generation = state.generation.saturating_add(1);
        drop(state);
        Ok(())
    }

    /// Pings and publishes a concrete provider.
    ///
    /// # Errors
    ///
    /// Returns the provider's typed model-listing failure, an unknown-model
    /// refusal, or an internal error when the provider slot is poisoned.
    pub async fn activate(&self, provider: Arc<dyn Provider>) -> Result<(), ProviderError> {
        self.activate_with_cancel(provider, CancelToken::new())
            .await
    }

    /// Activates a provider under caller-owned cooperative cancellation.
    ///
    /// # Errors
    ///
    /// Returns the provider's typed startup, ping, or model-listing failure.
    pub async fn activate_with_cancel(
        &self,
        provider: Arc<dyn Provider>,
        cancel: CancelToken,
    ) -> Result<(), ProviderError> {
        {
            let state = self.state.read().map_err(|_| provider_slot_error())?;
            if state.retired
                || state.unavailable_reason
                    == claw_protocol::native_models::CatalogueUnavailableReason::Disabled
            {
                return Err(ProviderError::new(
                    ErrorKind::Cancelled,
                    provider.id().as_str(),
                    claw_provider_sdk::Operation::Startup,
                    "provider is disabled or has been shut down",
                ));
            }
        }
        let mut cancel_on_drop = ProviderActivationGuard(Some(cancel.clone()));
        let activation =
            RequestContext::with_cancel(cancel).correlation_id("daemon-provider-activation");
        let publication = self.slot.activate_validated(
            provider,
            &activation,
            |candidate| async {
                let (generation, model, aliases, role) = {
                    let state = self.state.read().map_err(|_| provider_slot_error())?;
                    if state.retired
                        || state.unavailable_reason
                            == claw_protocol::native_models::CatalogueUnavailableReason::Disabled
                    {
                        return Err(ProviderError::new(
                            ErrorKind::Cancelled,
                            candidate.id().as_str(),
                            claw_provider_sdk::Operation::Startup,
                            "provider has been shut down",
                        ));
                    }
                    (
                        state.generation,
                        state.default_model.clone(),
                        state.model_aliases.clone(),
                        state.role_prompt.clone(),
                    )
                };
                let mut adapter = ProviderAdapter::new(
                    candidate,
                    model,
                    role,
                    self.history_config,
                    Arc::clone(&self.model_tools),
                    Arc::clone(&self.readiness),
                    Arc::clone(&self.ready_gate),
                );
                adapter.model_aliases = aliases;
                let adapter = Arc::new(adapter);
                adapter.initialize(&activation).await?;
                Ok((generation, adapter))
            },
            |(generation, adapter)| {
                let mut state = self.state.write().map_err(|_| provider_slot_error())?;
                if state.retired || state.generation != generation {
                    return Err(ProviderError::new(
                        ErrorKind::Cancelled,
                        adapter.provider_name(),
                        claw_provider_sdk::Operation::Startup,
                        "provider configuration changed before publication",
                    )
                    .with_upstream_code("reload_fenced"));
                }
                state.current = Some(adapter);
                Ok(state)
            },
        );
        tokio::select! {
            biased;
            () = self.shutdown_cancel.cancelled() => {
                return Err(ProviderError::new(ErrorKind::Cancelled, "daemon", claw_provider_sdk::Operation::Startup, "provider has been shut down"));
            }
            result = publication => { result?; }
        }
        cancel_on_drop.disarm();
        Ok(())
    }

    /// Fences new calls and clears the active provider.
    pub async fn shutdown(&self) {
        if let Ok(mut state) = self.state.write() {
            state.retired = true;
        }
        self.shutdown_cancel.cancel();
        let _ = self
            .slot
            .clear_with(|| {
                if let Ok(mut state) = self.state.write() {
                    state.current = None;
                    state.generation = state.generation.saturating_add(1);
                }
                self.ready_gate.store(false, Ordering::Release);
                self.readiness.set("provider", false);
            })
            .await;
    }

    /// Returns the shared provider-generation fence.
    #[must_use]
    pub fn provider_generation(&self) -> u64 {
        self.slot.current_generation().get()
    }

    /// Returns tool names already supplied by the host-owned model catalogue.
    #[must_use]
    pub fn model_tool_names(&self) -> BTreeSet<String> {
        self.model_tools
            .definitions()
            .into_iter()
            .map(|tool| tool.name)
            .collect()
    }

    /// Returns whether a provider is currently active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .current
            .is_some()
    }

    /// Returns the active provider identity or the pending state.
    #[must_use]
    pub fn provider_name(&self) -> String {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .current
            .as_ref()
            .map_or_else(
                || "device-flow-pending".to_owned(),
                |provider| provider.provider_name().to_owned(),
            )
    }

    /// Returns the selected model.
    #[must_use]
    pub fn default_model(&self) -> String {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .default_model
            .clone()
    }

    /// Changes the default model, validating it when a provider is active.
    ///
    /// # Errors
    ///
    /// Returns an error when the active catalogue rejects `model` or a provider
    /// slot lock is poisoned.
    pub fn set_default_model(&self, model: &str) -> Result<(), String> {
        let mut state = self
            .state
            .write()
            .map_err(|_| "provider slot is unavailable".to_owned())?;
        if state.default_model_locked && state.default_model != model {
            return Err("default model is pinned by explicit native provider policy; change the trusted startup policy and restart".to_owned());
        }
        if let Some(provider) = state.current.as_ref() {
            provider.set_default_model(model)?;
        }
        model.clone_into(&mut state.default_model);
        state.generation = state.generation.saturating_add(1);
        drop(state);
        Ok(())
    }

    /// Pins the current model against role, administrative and file-based reloads.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider slot lock is poisoned.
    pub fn pin_default_model(&self) -> Result<(), String> {
        self.state
            .write()
            .map_err(|_| "provider slot is unavailable".to_owned())?
            .default_model_locked = true;
        Ok(())
    }

    /// Replaces the role prompt for the active provider and future activations.
    pub fn set_role_prompt(&self, prompt: &str) {
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(provider) = state.current.as_ref() {
            provider.set_role_prompt(prompt);
        }
        prompt.clone_into(&mut state.role_prompt);
        state.generation = state.generation.saturating_add(1);
    }

    /// Publishes provider readiness after every dependent runtime sees activation.
    pub fn mark_ready(&self) {
        let Ok(state) = self.state.read() else {
            return;
        };
        if state.retired || state.current.is_none() {
            return;
        }
        self.ready_gate.store(true, Ordering::Release);
        self.readiness.set("provider", true);
        drop(state);
    }

    /// Clears all retained conversation context.
    pub fn clear_history(&self) {
        if let Some(provider) = self
            .state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .current
            .as_ref()
        {
            provider.clear_history();
        }
    }

    /// Explicitly refreshes a reviewed current catalogue without selecting a model or invoking inference.
    ///
    /// # Errors
    /// Rejects stale snapshots, concurrent refresh, cancellation, invalid descriptors and changed providers.
    pub(crate) async fn refresh_catalogue(
        &self,
        expected_sha256: &str,
        cancellation: CancellationToken,
    ) -> Result<Value, PortError> {
        let invalid = || {
            PortError::new(
                PortErrorKind::InvalidRequest,
                "catalogue refresh was refused or its provider selection changed",
            )
        };
        let _refresh = self.catalogue_refresh.try_lock().map_err(|_| invalid())?;
        let (provider, generation, model, pinned) = {
            let state = self.state.read().map_err(|_| invalid())?;
            let snapshot = self.catalogue_snapshot(&state)?;
            if Self::catalogue_digest(&snapshot)? != expected_sha256 {
                return Err(invalid());
            }
            let provider = state
                .current
                .as_ref()
                .filter(|_| !state.retired)
                .ok_or_else(invalid)?;
            (
                Arc::clone(provider),
                state.generation,
                state.default_model.clone(),
                state.default_model_locked,
            )
        };
        if cancellation.is_cancelled() || self.shutdown_cancel.is_cancelled() {
            return Err(invalid());
        }
        let cancel = CancelToken::new();
        let mut on_drop = ProviderActivationGuard(Some(cancel.clone()));
        let context = RequestContext::with_cancel(cancel);
        let models = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(invalid()),
            () = self.shutdown_cancel.cancelled() => return Err(invalid()),
            result = tokio::time::timeout(std::time::Duration::from_secs(10), provider.provider.list_models(&context)) => {
                result.map_err(|_|PortError::new(PortErrorKind::Timeout,"model catalogue refresh exceeded its time budget"))?
                    .map_err(|error|map_provider_error(&error))?
            }
        };
        ProviderAdapter::validate_catalogue(provider.provider_name(), &models, &model)
            .map_err(|error| map_provider_error(&error))?;
        provider
            .validate_model_aliases(&models)
            .map_err(|error| map_provider_error(&error))?;
        let state = self.state.write().map_err(|_| invalid())?;
        if state.retired
            || state.generation != generation
            || state.default_model != model
            || state.default_model_locked != pinned
            || state
                .current
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(current, &provider))
            || cancellation.is_cancelled()
        {
            return Err(invalid());
        }
        let count = models.len();
        *provider.models.write().map_err(|_| invalid())? = models;
        provider
            .catalogue_observed_at_ms
            .store(ProviderAdapter::catalogue_time(), Ordering::Release);
        let result = json!({"schemaVersion":1,"refreshed":true,"provider":provider.provider_name(),"providerGeneration":self.slot.current_generation().get(),
            "requestedSha256":expected_sha256,"selectedModel":model,"totalModels":count,
            "selectionChanged":false,"networkContacted":true,"inferenceInvoked":false});
        drop(state);
        on_drop.disarm();
        Ok(result)
    }

    /// Returns one bounded cached model page without network, selection changes or inference.
    ///
    /// # Errors
    /// Rejects invalid cursors, changed snapshot digests and unavailable cached state.
    pub(crate) fn catalogue_page(&self, params: &Value) -> Result<Value, PortError> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Cursor {
            offset: usize,
            sha256: Option<String>,
            #[serde(default)]
            include_availability: bool,
        }
        let invalid = || {
            PortError::new(
                PortErrorKind::InvalidRequest,
                "invalid or changed native model catalogue cursor",
            )
        };
        let cursor: Cursor = serde_json::from_value(params.clone()).map_err(|_| invalid())?;
        if cursor.offset > 1024
            || cursor.offset > 0 && cursor.sha256.is_none()
            || cursor.sha256.as_ref().is_some_and(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(invalid());
        }
        let state = self.state.read().map_err(|_| invalid())?;
        if state.current.is_none() || state.retired {
            if cursor.offset != 0 || cursor.sha256.is_some() {
                return Err(invalid());
            }
            let mut page = json!({"schemaVersion":1,"available":false,"selectionChanged":false,"networkContacted":false});
            if cursor.include_availability {
                page["unavailableReason"] = json!(if state.retired {
                    claw_protocol::native_models::CatalogueUnavailableReason::Retired
                } else {
                    state.unavailable_reason
                });
            }
            return Ok(page);
        }
        let snapshot = self.catalogue_snapshot(&state)?;
        drop(state);
        let total = snapshot["models"]
            .as_array()
            .expect("snapshot model array")
            .len();
        if cursor.offset > total || (cursor.offset > 0 && cursor.offset == total) {
            return Err(invalid());
        }
        let digest = Self::catalogue_digest(&snapshot)?;
        if cursor
            .sha256
            .as_ref()
            .is_some_and(|expected| *expected != digest)
        {
            return Err(invalid());
        }
        let mut end = cursor.offset.saturating_add(8).min(total);
        loop {
            let page = json!({"schemaVersion":1,"available":true,"offset":cursor.offset,"endOffset":end,"nextOffset":(end < total).then_some(end),
            "totalModels":total,"sha256":digest,"provider":snapshot["provider"],"selectedModel":snapshot["selectedModel"],
            "providerGeneration":snapshot["providerGeneration"],
            "selectionPinned":snapshot["selectionPinned"],"observedAtMs":snapshot["observedAtMs"],"source":snapshot["source"],
            "liveCapabilitiesVerified":false,"selectionChanged":false,"networkContacted":false,
            "models":&snapshot["models"].as_array().expect("catalogue entries")[cursor.offset..end]});
            if serde_json::to_vec(&page).map_err(|_| invalid())?.len() <= 16 * 1024 {
                return Ok(page);
            }
            if end <= cursor.offset.saturating_add(1) {
                return Err(invalid());
            }
            end -= 1;
        }
    }

    fn catalogue_snapshot(&self, state: &SwappableState) -> Result<Value, PortError> {
        let unavailable = || {
            PortError::new(
                PortErrorKind::Unavailable,
                "current model catalogue is unavailable",
            )
        };
        let provider = state
            .current
            .as_ref()
            .filter(|_| !state.retired)
            .ok_or_else(unavailable)?;
        let models = provider.models.read().map_err(|_| unavailable())?;
        let aliases = provider
            .validate_model_aliases(&models)
            .map_err(|_| unavailable())?;
        let entries: Vec<Value> = models.iter().map(|model| {
            let mut entry = json!({
            "id":model.id.as_str(),"displayName":model.display_name,"contextWindow":model.context_window,"maxOutputTokens":model.max_output_tokens,
            "advertisedCapabilities":model.capabilities.to_vec().into_iter().map(claw_provider_sdk::Capability::as_str).collect::<Vec<_>>(),
            });
            let names = aliases.aliases().filter(|(_, target)| *target == &model.id).map(|(alias, _)| alias.as_str()).collect::<Vec<_>>();
            if !names.is_empty() {
                entry["aliases"] = json!(names);
            }
            entry
        }).collect();
        drop(models);
        Ok(
            json!({"provider":provider.provider_name(),"providerGeneration":self.slot.current_generation().get(),
            "selectedModel":state.default_model,"selectionPinned":state.default_model_locked,
            "observedAtMs":match provider.catalogue_observed_at_ms.load(Ordering::Acquire) {0=>None,value=>Some(value)},
            "source":"provider_sdk_catalogue","liveCapabilitiesVerified":false,"models":entries}),
        )
    }

    fn catalogue_digest(snapshot: &Value) -> Result<String, PortError> {
        use sha2::Digest as _;
        use std::fmt::Write as _;
        let bytes = serde_json::to_vec(snapshot).map_err(|_| {
            PortError::new(PortErrorKind::Internal, "model catalogue encoding failed")
        })?;
        let mut digest = String::with_capacity(64);
        for byte in sha2::Sha256::digest(&bytes) {
            write!(digest, "{byte:02x}").expect("bounded digest");
        }
        Ok(digest)
    }

    /// Returns cached model identities from the active provider.
    ///
    /// # Errors
    ///
    /// Returns unavailable while Device Flow is pending, or the active
    /// provider's typed cache error.
    pub fn model_ids(&self) -> Result<Vec<String>, PortError> {
        self.active()?.model_ids()
    }

    pub(super) async fn generate_context(
        &self,
        mut request: GenerationRequest,
        context: Vec<ChatMessage>,
        cancellation: CancellationToken,
    ) -> Result<
        (
            GenerationOutput,
            claw_application::ports::provider::ProviderResponseReport,
        ),
        PortError,
    > {
        let (provider, model) = self.active_for_model(&request.model)?;
        request.model = model.as_str().to_owned();
        let prepared = provider.to_completion_with_context(request, Some(context))?;
        let response = provider
            .complete(prepared.request, cancellation)
            .await
            .map_err(|error| map_provider_error(&error))?;
        let finish_reason = generation_finish_reason(
            &response.finish_reason,
            !response.message.tool_calls.is_empty(),
        )?;
        let report = provider_response_report(&provider.provider_name, &response, finish_reason)?;
        Ok((output_from(response, finish_reason), report))
    }

    fn active_for_model(
        &self,
        requested: &str,
    ) -> Result<(Arc<ProviderAdapter>, ModelId), PortError> {
        let state = self
            .state
            .read()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "provider slot unavailable"))?;
        let provider = state
            .current
            .as_ref()
            .filter(|_| !state.retired)
            .ok_or_else(|| {
                PortError::new(
                    PortErrorKind::Unavailable,
                    "provider authentication is pending",
                )
            })?;
        let model = provider.resolve_model_id(requested)?;
        if state.default_model_locked && model.as_str() != state.default_model {
            return Err(invalid_request(
                "requested model does not match the explicitly pinned provider model",
            ));
        }
        let provider = Arc::clone(provider);
        drop(state);
        Ok((provider, model))
    }

    fn active(&self) -> Result<Arc<ProviderAdapter>, PortError> {
        self.state
            .read()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "provider slot unavailable"))?
            .current
            .clone()
            .ok_or_else(|| {
                PortError::new(
                    PortErrorKind::Unavailable,
                    "provider authentication is pending",
                )
            })
    }
}

impl std::fmt::Debug for SwappableProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SwappableProvider")
            .field("provider", &self.provider_name())
            .field("default_model", &self.default_model())
            .finish_non_exhaustive()
    }
}

impl ProviderPort for SwappableProvider {
    fn models(&self) -> PortFuture<'_, Result<Vec<Model>, PortError>> {
        let provider = self.active();
        Box::pin(async move { provider?.models().await })
    }

    fn resolve_model_alias(&self, alias: &str) -> Result<Option<String>, PortError> {
        if !self
            .state
            .read()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "provider slot unavailable"))?
            .model_aliases
            .iter()
            .any(|(name, _)| name.as_str() == alias)
        {
            return Ok(None);
        }
        let (_, exact) = self.active_for_model(alias)?;
        Ok(Some(exact.as_str().to_owned()))
    }

    fn generate(
        &self,
        mut request: GenerationRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<GenerationOutput, PortError>> {
        let provider = self.active_for_model(&request.model);
        Box::pin(async move {
            let (provider, model) = provider?;
            request.model = model.as_str().to_owned();
            provider.generate(request, cancellation).await
        })
    }

    fn stream(
        &self,
        mut request: GenerationRequest,
        events: mpsc::Sender<GenerationEvent>,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<claw_http_api::GenerationSummary, PortError>> {
        let provider = self.active_for_model(&request.model);
        Box::pin(async move {
            let (provider, model) = provider?;
            request.model = model.as_str().to_owned();
            provider.stream(request, events, cancellation).await
        })
    }

    fn embed(
        &self,
        mut request: EmbeddingRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<Vec<Vec<f32>>, PortError>> {
        let provider = self.active_for_model(&request.model);
        Box::pin(async move {
            let (provider, model) = provider?;
            request.model = model.as_str().to_owned();
            provider.embed(request, cancellation).await
        })
    }
}

impl ProviderAdapter {
    fn to_completion(&self, request: GenerationRequest) -> Result<PreparedCompletion, PortError> {
        self.to_completion_with_context(request, None)
    }

    fn to_completion_with_context(
        &self,
        request: GenerationRequest,
        history_override: Option<Vec<ChatMessage>>,
    ) -> Result<PreparedCompletion, PortError> {
        let automatic_runtime_tools =
            history_override.is_some() && request.tool_choice == claw_http_api::ToolChoice::Auto;
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
        let model = self.resolve_model_id(&request.model)?.as_str().to_owned();
        let mut messages = Vec::new();
        let role_prompt = self
            .role_prompt
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if !role_prompt.is_empty() {
            messages.push(ChatMessage::System(role_prompt));
        }
        if let Some(instructions) = request.instructions {
            messages.push(ChatMessage::System(instructions));
        }
        if history_override.is_none() {
            messages.extend(self.history(&session_id));
        }
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
        if let Some(history) = history_override {
            messages.extend(history);
        } else {
            messages.push(user.clone());
        }

        let mut completion = CompletionRequest::new(
            ModelId::new(model).map_err(|error| invalid_request(error.to_string()))?,
            messages,
        );
        let tools_supported = self
            .validate_model_operation(
                &completion.model,
                &[Capability::ToolCalling],
                None,
                claw_provider_sdk::Operation::Complete,
            )
            .is_ok();
        let tools = if automatic_runtime_tools && !tools_supported {
            Vec::new()
        } else {
            request.tools
        };
        completion.tools = tools
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
        completion.tools.extend(
            self.model_tools
                .definitions()
                .into_iter()
                .filter(|_| tools_supported)
                .map(|tool| {
                    Ok(ToolDefinition {
                        name: tool.name,
                        description: tool.description.unwrap_or_default(),
                        parameters: ToolParameters::new(tool.input_schema)
                            .map_err(|error| invalid_request(error.to_string()))?,
                    })
                })
                .collect::<Result<Vec<_>, PortError>>()?,
        );
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

fn generation_finish_reason(
    reason: &FinishReason,
    has_tools: bool,
) -> Result<claw_http_api::GenerationFinishReason, PortError> {
    use claw_http_api::GenerationFinishReason;

    match reason {
        FinishReason::Stop | FinishReason::ToolCalls if has_tools => {
            Ok(GenerationFinishReason::ToolCalls)
        }
        FinishReason::Stop => Ok(GenerationFinishReason::Stop),
        FinishReason::Length if !has_tools => Ok(GenerationFinishReason::Length),
        FinishReason::ContentFilter if !has_tools => Ok(GenerationFinishReason::ContentFilter),
        FinishReason::Length => Err(PortError::new(
            PortErrorKind::Unavailable,
            "provider output was truncated before completion",
        )),
        FinishReason::ContentFilter => Err(PortError::new(
            PortErrorKind::Unavailable,
            "provider output was stopped by a content filter",
        )),
        FinishReason::Cancelled => Err(PortError::new(
            PortErrorKind::Unavailable,
            "provider generation was cancelled",
        )),
        FinishReason::Other(_) | FinishReason::ToolCalls => Err(PortError::new(
            PortErrorKind::Unavailable,
            "provider generation did not reach a supported complete state",
        )),
    }
}

const fn usage_reporting(
    reporting: claw_provider_sdk::model::UsageReporting,
) -> claw_http_api::UsageReporting {
    match reporting {
        claw_provider_sdk::model::UsageReporting::Unreported => {
            claw_http_api::UsageReporting::Unreported
        }
        claw_provider_sdk::model::UsageReporting::Partial => claw_http_api::UsageReporting::Partial,
        claw_provider_sdk::model::UsageReporting::Complete => {
            claw_http_api::UsageReporting::Complete
        }
    }
}

fn provider_response_report(
    provider: &str,
    response: &CompletionResponse,
    finish: claw_http_api::GenerationFinishReason,
) -> Result<claw_application::ports::provider::ProviderResponseReport, PortError> {
    use claw_application::ports::provider::{ProviderResponseFinish, ProviderResponseReport};

    let report = ProviderResponseReport {
        provider: provider.to_owned(),
        model: response.model.as_str().to_owned(),
        response_id: (!response.id.is_empty()).then(|| response.id.clone()),
        usage_reporting: usage_reporting(response.usage_reporting),
        input_tokens: response.usage.input_tokens,
        output_tokens: response.usage.output_tokens,
        cached_input_tokens: response.usage.cached_input_tokens,
        reasoning_tokens: response.usage.reasoning_tokens,
        finish_reason: match finish {
            claw_http_api::GenerationFinishReason::Stop => ProviderResponseFinish::Stop,
            claw_http_api::GenerationFinishReason::ToolCalls => ProviderResponseFinish::ToolCalls,
            claw_http_api::GenerationFinishReason::Length => ProviderResponseFinish::Length,
            claw_http_api::GenerationFinishReason::ContentFilter => {
                ProviderResponseFinish::ContentFilter
            }
        },
    };
    report.validate().map_err(|_| {
        PortError::new(
            PortErrorKind::Internal,
            "provider response accounting is invalid",
        )
    })?;
    Ok(report)
}

fn output_from(
    response: CompletionResponse,
    finish_reason: claw_http_api::GenerationFinishReason,
) -> GenerationOutput {
    GenerationOutput {
        usage_reporting: usage_reporting(response.usage_reporting),
        finish_reason,
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

fn provider_slot_error() -> ProviderError {
    ProviderError::new(
        ErrorKind::Protocol,
        "daemon",
        claw_provider_sdk::Operation::ListModels,
        "provider slot is unavailable",
    )
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
    provider: Arc<SwappableProvider>,
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
        provider: Arc<SwappableProvider>,
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
        if !outcome.changed_domains.is_empty() {
            self.provider.clear_history();
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

/// Reads the active explicit Copilot timeout, otherwise the legacy typed setting.
pub(crate) fn copilot_request_timeout_ms(snapshot: &ConfigSnapshot) -> Result<u64, String> {
    if let Some(provider) = snapshot.core().provider()
        && provider.kind() == claw_config::ProviderKind::Copilot
    {
        return provider
            .request_timeout_ms()
            .ok_or_else(|| "explicit Copilot request timeout is missing".to_owned());
    }
    Ok(snapshot.core().copilot().request_timeout_ms())
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
    failed: std::sync::atomic::AtomicBool,
}

impl DurableSecurityAudit {
    /// Opens the append-only audit file.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error raised while opening the file.
    pub fn open(path: &Path, readiness: Arc<DependencyReadiness>) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x0020_0000).share_mode(3);
        }
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::other("audit path is not a regular file"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(io::Error::other("audit path is a reparse point"));
            }
        }
        Ok(Self {
            file: Mutex::new(file),
            readiness,
            failed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub(super) fn persist_tool(
        &self,
        record: &claw_tools::ToolAuditRecord,
        authority: &claw_application::ports::tool::InvocationAuthority,
        invocation: &claw_application::ports::tool::ToolInvocation,
    ) -> Result<(), PortError> {
        self.persist_value(&json!({
            "action": "native_tool", "source": format!("{:?}", authority.source()), "subject": authority.subject(),
            "account": authority.account(), "permissionGeneration": authority.generation(),
            "sessionId": invocation.session_id.as_str(), "turn": invocation.turn.ordinal(), "callId": invocation.call.call_id.as_str(),
            "record": record,
        }))
    }

    pub(super) fn persist_internal_tool(
        &self,
        invocation: &claw_application::ports::tool::ToolInvocation,
        authority: &claw_application::ports::tool::InvocationAuthority,
        binding: &claw_application::ports::tool::ToolBinding,
        phase: claw_application::ports::tool::InternalToolAuditPhase,
    ) -> Result<(), PortError> {
        use claw_application::ports::tool::InternalToolAuditPhase;
        let phase = match phase {
            InternalToolAuditPhase::Authorized => "authorized",
            InternalToolAuditPhase::Completed => "completed",
            InternalToolAuditPhase::Failed => "failed",
        };
        self.persist_value(&json!({
            "action": "internal_tool", "phase": phase, "tool": invocation.call.name,
            "source": format!("{:?}", authority.source()), "subject": authority.subject(), "account": authority.account(),
            "permissionGeneration": authority.generation(), "sessionId": invocation.session_id.as_str(),
            "turn": invocation.turn.ordinal(), "callId": invocation.call.call_id.as_str(),
            "toolPublication": binding.identity(), "toolRevision": binding.revision(), "resourceScope": binding.resource(),
        }))
    }

    pub(super) fn persist_plugin_tool(
        &self,
        invocation: &claw_http_api::ToolInvocation,
        phase: claw_application::ports::tool::InternalToolAuditPhase,
    ) -> Result<(), PortError> {
        use claw_application::ports::tool::InternalToolAuditPhase;
        let authority = invocation.context.authority.as_ref().ok_or_else(|| {
            PortError::new(
                PortErrorKind::InvalidRequest,
                "plugin audit requires verified authority",
            )
        })?;
        let binding = invocation.context.binding.as_ref().ok_or_else(|| {
            PortError::new(
                PortErrorKind::InvalidRequest,
                "plugin audit requires an approved binding",
            )
        })?;
        let phase = match phase {
            InternalToolAuditPhase::Authorized => "authorized",
            InternalToolAuditPhase::Completed => "completed",
            InternalToolAuditPhase::Failed => "failed",
        };
        self.persist_value(&json!({
            "action": "plugin_tool", "phase": phase, "tool": invocation.name,
            "source": format!("{:?}", authority.source()), "subject": authority.subject(), "account": authority.account(),
            "permissionGeneration": authority.generation(), "sessionId": invocation.context.session_key,
            "callId": invocation.context.idempotency_key, "toolPublication": binding.identity(), "toolRevision": binding.revision(),
        }))
    }

    pub(super) fn persist_skill_tool(
        &self,
        invocation: &claw_application::ports::tool::ToolInvocation,
        authority: &claw_application::ports::tool::InvocationAuthority,
        binding: &claw_application::ports::tool::ToolBinding,
        target: &str,
        phase: claw_application::ports::tool::InternalToolAuditPhase,
    ) -> Result<(), PortError> {
        use claw_application::ports::tool::InternalToolAuditPhase;
        let phase = match phase {
            InternalToolAuditPhase::Authorized => "authorized",
            InternalToolAuditPhase::Completed => "completed",
            InternalToolAuditPhase::Failed => "failed",
        };
        self.persist_value(&json!({
            "action":"skill_tool", "phase":phase, "skill":invocation.call.name, "target":target,
            "source":format!("{:?}", authority.source()), "subject":authority.subject(), "account":authority.account(),
            "permissionGeneration":authority.generation(), "sessionId":invocation.session_id.as_str(),
            "callId":invocation.call.call_id.as_str(), "skillBinding":binding.identity(), "targetRevision":binding.revision(),
        }))
    }

    fn persist_value(&self, value: &Value) -> Result<(), PortError> {
        let mut file = self.file.lock().map_err(|_| {
            self.failed
                .store(true, std::sync::atomic::Ordering::Release);
            self.readiness.set("audit", false);
            PortError::new(PortErrorKind::Internal, "audit writer lock failed")
        })?;
        let result = (|| {
            if self.failed.load(std::sync::atomic::Ordering::Acquire) {
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "audit writer requires recovery",
                ));
            }
            let encoded = serde_json::to_vec(value)
                .map_err(|_| PortError::new(PortErrorKind::Internal, "audit encoding failed"))?;
            if encoded.len() > 64 * 1024 {
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "audit record exceeds its bound",
                ));
            }
            file.write_all(&encoded)
                .and_then(|()| file.write_all(b"\n"))
                .and_then(|()| file.flush())
                .and_then(|()| file.sync_data())
                .map_err(|_| PortError::new(PortErrorKind::Unavailable, "audit persistence failed"))
        })();
        if result.is_err() {
            self.failed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        self.readiness.set("audit", result.is_ok());
        drop(file);
        result
    }
}

impl AuditPort for DurableSecurityAudit {
    fn persist(&self, event: &AuditEvent) -> Result<(), PortError> {
        self.persist_value(&json!({
            "action": audit_action(event.action), "subject": audit_subject(&event.subject),
            "outcome": audit_outcome(event.outcome), "reason": audit_reason(event.reason), "unixMillis": event.unix_millis,
        }))
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

/// Fail-closed adapter for optional watch and task-flow routes with no configuration.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledExternalPorts;

impl WatchAuthPort for DisabledExternalPorts {
    fn authenticate(
        &self,
        _connect: ConnectParams,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WatchIdentity, PortError>> {
        Box::pin(async {
            Err(PortError::new(
                PortErrorKind::NotFound,
                "watch-node pairing is not configured",
            ))
        })
    }
}

impl WatchResultPort for DisabledExternalPorts {
    fn handle(
        &self,
        _node_id: String,
        _result: Value,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<bool, PortError>> {
        Box::pin(async { Ok(false) })
    }
}

impl WebhookPort for DisabledExternalPorts {
    fn invoke(
        &self,
        _route_id: String,
        _action: Value,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WebhookOutcome, PortError>> {
        Box::pin(async {
            Err(PortError::new(
                PortErrorKind::NotFound,
                "webhook route is not configured",
            ))
        })
    }
}

/// Immutable configuration and capability inventory exposed to operators.
pub struct OperatorInventory {
    channels: Vec<Value>,
    registered_skill_count: usize,
    active_skill_count: usize,
    updates_enabled: bool,
    config_resolution: Value,
    plugin_activation: Value,
    runtime: Arc<dyn OperatorRuntimeStatus>,
}

impl std::fmt::Debug for OperatorInventory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperatorInventory")
            .field("channels", &self.channels)
            .field("registered_skill_count", &self.registered_skill_count)
            .field("active_skill_count", &self.active_skill_count)
            .field("updates_enabled", &self.updates_enabled)
            .finish_non_exhaustive()
    }
}

impl OperatorInventory {
    /// Creates the immutable operator-facing inventory.
    #[must_use]
    pub const fn new(
        channels: Vec<Value>,
        registered_skill_count: usize,
        active_skill_count: usize,
        updates_enabled: bool,
        config_resolution: Value,
        plugin_activation: Value,
        runtime: Arc<dyn OperatorRuntimeStatus>,
    ) -> Self {
        Self {
            channels,
            registered_skill_count,
            active_skill_count,
            updates_enabled,
            config_resolution,
            plugin_activation,
            runtime,
        }
    }
}

/// Useful subset of the frozen admin surface plus explicit unavailable errors.
#[derive(Debug)]
pub struct OperatorAdmin {
    config: Arc<ConfigController>,
    provider: Arc<SwappableProvider>,
    readiness: Arc<DependencyReadiness>,
    diagnostics: Arc<Diagnostics>,
    inventory: OperatorInventory,
    reload_lock: Arc<tokio::sync::Mutex<()>>,
    gateway_pairing: Arc<dyn GatewayPairingAdmin>,
}

impl OperatorAdmin {
    /// Creates the operator adapter.
    #[must_use]
    pub const fn new(
        config: Arc<ConfigController>,
        provider: Arc<SwappableProvider>,
        readiness: Arc<DependencyReadiness>,
        diagnostics: Arc<Diagnostics>,
        inventory: OperatorInventory,
        reload_lock: Arc<tokio::sync::Mutex<()>>,
        gateway_pairing: Arc<dyn GatewayPairingAdmin>,
    ) -> Self {
        Self {
            config,
            provider,
            readiness,
            diagnostics,
            inventory,
            reload_lock,
            gateway_pairing,
        }
    }

    fn status(&self) -> Result<Value, PortError> {
        let readiness = self.readiness.snapshot()?;
        let (model, generation) = self.config.model_generation();
        let runtime = self.inventory.runtime.status();
        let active_skills = runtime
            .pointer("/skills/active")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| u64::try_from(self.inventory.active_skill_count).unwrap_or(0));
        Ok(json!({
            "ready": readiness.ready,
            "failing": readiness.failing,
            "uptimeMs": readiness.uptime_ms,
            "provider": self.provider.provider_name(),
            "providerGeneration": self.provider.provider_generation(),
            "model": model,
            "configGeneration": generation,
            "configuration": self.inventory.config_resolution,
            "plugins": self.inventory.plugin_activation,
            "runtime": runtime,
            "channels": self.inventory.channels,
            "skills": {
                "registered": self.inventory.registered_skill_count,
                "active": active_skills,
                "state": if active_skills > 0 {
                    "native_skills_configured"
                } else {
                    "requires_native_ports"
                },
            },
        }))
    }
}

impl AdminPort for OperatorAdmin {
    fn dispatch(
        &self,
        method: String,
        params: Option<Value>,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<AdminSuccess, AdminFailure>> {
        Box::pin(async move {
            let payload = match method.as_str() {
                "health" | "status" => self.status().map_err(admin_port_failure)?,
                "logs.tail" => json!({"entries": self.diagnostics.entries()}),
                "models.list" => {
                    if let Some(page) = params
                        .as_ref()
                        .and_then(|params| params.get("nativeCatalogPage"))
                    {
                        if params
                            .as_ref()
                            .and_then(Value::as_object)
                            .is_none_or(|fields| fields.len() != 1)
                        {
                            return Err(admin_port_failure(PortError::new(
                                PortErrorKind::InvalidRequest,
                                "native catalogue paging cannot be mixed with other fields",
                            )));
                        }
                        self.provider
                            .catalogue_page(page)
                            .map_err(admin_port_failure)?
                    } else if let Some(refresh) = params
                        .as_ref()
                        .and_then(|params| params.get("nativeCatalogRefresh"))
                    {
                        if params
                            .as_ref()
                            .and_then(Value::as_object)
                            .is_none_or(|fields| fields.len() != 1)
                            || refresh.as_object().is_none_or(|fields| fields.len() != 1)
                        {
                            return Err(admin_port_failure(PortError::new(
                                PortErrorKind::InvalidRequest,
                                "native catalogue refresh requires only a snapshot SHA256",
                            )));
                        }
                        let digest = refresh["sha256"].as_str().ok_or_else(|| {
                            admin_port_failure(PortError::new(
                                PortErrorKind::InvalidRequest,
                                "native catalogue refresh SHA256 is missing",
                            ))
                        })?;
                        self.provider
                            .refresh_catalogue(digest, cancellation)
                            .await
                            .map_err(admin_port_failure)?
                    } else {
                        json!({"models": self.provider.model_ids().map_err(admin_port_failure)?})
                    }
                }
                "models.authStatus" => {
                    json!({"ready": self.readiness.snapshot().map_err(admin_port_failure)?.ready})
                }
                "channels.status" => {
                    let recovery = if params
                        .as_ref()
                        .is_some_and(|params| params.get("nativeRecovery").is_some())
                    {
                        self.inventory
                            .runtime
                            .dispatch(&method, params.as_ref(), cancellation)
                            .await
                            .map_err(admin_port_failure)?
                    } else {
                        None
                    };
                    let mut status = json!({"channels": self.inventory.channels});
                    if let Some(recovery) = recovery {
                        status["nativeRecovery"] = recovery;
                    }
                    status
                }
                "update.status" => json!({
                    "configured": self.inventory.updates_enabled,
                    "state": if self.inventory.updates_enabled {
                        "signed_check_scheduled"
                    } else {
                        "disabled"
                    },
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
                    let _reload = self.reload_lock.lock().await;
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
                    if is_pairing_method(&method) {
                        let gateway_pairing = Arc::clone(&self.gateway_pairing);
                        let pairing_method = method.clone();
                        let pairing_params = params.clone();
                        let dispatched = tokio::task::spawn_blocking(move || {
                            gateway_pairing.dispatch(&pairing_method, pairing_params.as_ref())
                        })
                        .await
                        .map_err(|_| admin_internal("gateway pairing task failed"))?
                        .map_err(admin_port_failure)?;
                        if let Some(payload) = dispatched {
                            return Ok(AdminSuccess {
                                payload,
                                meta: None,
                            });
                        }
                    }
                    if let Some(payload) = self
                        .inventory
                        .runtime
                        .dispatch(&method, params.as_ref(), cancellation)
                        .await
                        .map_err(admin_port_failure)?
                    {
                        return Ok(AdminSuccess {
                            payload,
                            meta: None,
                        });
                    }
                    return Err(AdminFailure {
                        code: "NOT_CONFIGURED".to_owned(),
                        message: format!("{method} is allowlisted but has no configured service"),
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

fn admin_internal(message: impl Into<String>) -> AdminFailure {
    AdminFailure {
        code: "INTERNAL".to_owned(),
        message: message.into(),
        details: None,
        retryable: Some(false),
        retry_after_ms: None,
    }
}

fn is_pairing_method(method: &str) -> bool {
    matches!(
        method,
        "device.pair.list"
            | "device.pair.approve"
            | "device.pair.reject"
            | "device.pair.remove"
            | "node.pair.list"
            | "node.pair.approve"
            | "node.pair.reject"
            | "node.pair.remove"
    )
}

fn admin_port_failure(error: PortError) -> AdminFailure {
    match error.kind {
        PortErrorKind::InvalidRequest => admin_invalid(error.message),
        PortErrorKind::NotFound => AdminFailure {
            code: "NOT_FOUND".to_owned(),
            message: error.message,
            details: None,
            retryable: Some(false),
            retry_after_ms: None,
        },
        PortErrorKind::Unavailable => admin_unavailable(error.message),
        PortErrorKind::Timeout => AdminFailure {
            code: "AGENT_TIMEOUT".to_owned(),
            message: error.message,
            details: None,
            retryable: Some(true),
            retry_after_ms: None,
        },
        PortErrorKind::CommittedButNotDurable => AdminFailure {
            code: "COMMITTED_BUT_NOT_DURABLE".to_owned(),
            message: error.message,
            details: None,
            retryable: Some(false),
            retry_after_ms: None,
        },
        PortErrorKind::OutcomeUnknown => AdminFailure {
            code: "OUTCOME_UNKNOWN".to_owned(),
            message: error.message,
            details: Some(json!({"recoveryRequired": true})),
            retryable: Some(false),
            retry_after_ms: None,
        },
        PortErrorKind::Internal => AdminFailure {
            code: "INTERNAL".to_owned(),
            message: error.message,
            details: None,
            retryable: Some(false),
            retry_after_ms: None,
        },
    }
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

    fn startup<'a>(
        &'a self,
        _context: &'a RequestContext,
    ) -> ProviderFuture<'a, Result<ProviderStatus, ProviderError>> {
        Box::pin(async move { Ok(ProviderStatus::new(self.id.clone(), ProviderPhase::Started)) })
    }

    fn ping<'a>(
        &'a self,
        _context: &'a RequestContext,
    ) -> ProviderFuture<'a, Result<ProviderStatus, ProviderError>> {
        Box::pin(async move {
            Ok(ProviderStatus::new(
                self.id.clone(),
                ProviderPhase::Reachable,
            ))
        })
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
                usage_reporting: claw_provider_sdk::model::UsageReporting::Complete,
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
                    Ok(StreamEvent::UsageReported {
                        usage,
                        reporting: claw_provider_sdk::model::UsageReporting::Complete,
                    }),
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
        ConfigController, DependencyReadiness, Diagnostics, EmptyModelTools, ProviderHistoryConfig,
        SmokeProvider, SwappableProvider, admin_port_failure, copilot_request_timeout_ms,
    };
    use std::sync::Arc;

    use claw_config::{migrate_legacy_environment, to_json5};
    use claw_http_api::{PortError, PortErrorKind};

    struct ModelCapabilityProvider {
        source: SmokeProvider,
        capabilities: super::CapabilitySet,
        lifecycle_calls: std::sync::atomic::AtomicUsize,
        completions: std::sync::atomic::AtomicUsize,
        streams: std::sync::atomic::AtomicUsize,
        embeddings: std::sync::atomic::AtomicUsize,
        last_request: std::sync::Mutex<Option<super::CompletionRequest>>,
    }

    impl ModelCapabilityProvider {
        fn new(model: super::CapabilitySet, provider: super::CapabilitySet) -> Self {
            let mut source = SmokeProvider::new().expect("model capability fixture");
            source.models[0].capabilities = model;
            source.models[0].max_output_tokens = Some(16);
            Self {
                source,
                capabilities: provider,
                lifecycle_calls: std::sync::atomic::AtomicUsize::new(0),
                completions: std::sync::atomic::AtomicUsize::new(0),
                streams: std::sync::atomic::AtomicUsize::new(0),
                embeddings: std::sync::atomic::AtomicUsize::new(0),
                last_request: std::sync::Mutex::new(None),
            }
        }

        fn calls(&self) -> usize {
            self.completions.load(std::sync::atomic::Ordering::SeqCst)
                + self.streams.load(std::sync::atomic::Ordering::SeqCst)
                + self.embeddings.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl super::Provider for ModelCapabilityProvider {
        fn id(&self) -> &super::ProviderId {
            super::Provider::id(&self.source)
        }
        fn capabilities(&self) -> super::CapabilitySet {
            self.capabilities
        }
        fn list_models<'a>(
            &'a self,
            context: &'a super::RequestContext,
        ) -> super::ProviderFuture<'a, Result<Vec<super::ModelDescriptor>, super::ProviderError>>
        {
            self.lifecycle_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            super::Provider::list_models(&self.source, context)
        }
        fn startup<'a>(
            &'a self,
            context: &'a super::RequestContext,
        ) -> super::ProviderFuture<'a, Result<super::ProviderStatus, super::ProviderError>>
        {
            self.lifecycle_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            super::Provider::startup(&self.source, context)
        }
        fn ping<'a>(
            &'a self,
            context: &'a super::RequestContext,
        ) -> super::ProviderFuture<'a, Result<super::ProviderStatus, super::ProviderError>>
        {
            self.lifecycle_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            super::Provider::ping(&self.source, context)
        }
        fn complete<'a>(
            &'a self,
            request: &'a super::CompletionRequest,
            context: &'a super::RequestContext,
        ) -> super::ProviderFuture<'a, Result<super::CompletionResponse, super::ProviderError>>
        {
            self.completions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_request.lock().expect("fixture request") = Some(request.clone());
            super::Provider::complete(&self.source, request, context)
        }
        fn stream<'a>(
            &'a self,
            request: &'a super::CompletionRequest,
            context: &'a super::RequestContext,
        ) -> super::ProviderFuture<'a, Result<super::CompletionStream, super::ProviderError>>
        {
            self.streams
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_request.lock().expect("fixture stream request") = Some(request.clone());
            super::Provider::stream(&self.source, request, context)
        }
        fn embed<'a>(
            &'a self,
            request: &'a super::EmbeddingsRequest,
            context: &'a super::RequestContext,
        ) -> super::ProviderFuture<'a, Result<super::EmbeddingsResponse, super::ProviderError>>
        {
            self.embeddings
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            super::Provider::embed(&self.source, request, context)
        }
    }

    #[tokio::test]
    async fn model_alias_requests_preserve_exact_ids_and_pinned_selection_before_provider_calls() {
        use super::{Capability, CapabilitySet, ModelId};
        use claw_http_api::ProviderPort as _;
        let mut fixture = ModelCapabilityProvider::new(
            CapabilitySet::from_slice(&Capability::ALL),
            CapabilitySet::from_slice(&Capability::ALL),
        );
        let alternate = ModelId::new("alternate-exact").expect("alternate");
        fixture.source.models.push(super::ModelDescriptor {
            id: alternate.clone(),
            ..fixture.source.models[0].clone()
        });
        let source = Arc::new(fixture);
        let provider = SwappableProvider::new(
            "gpt-4o",
            "",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            Arc::new(DependencyReadiness::new(["provider"])),
        );
        provider
            .configure_model_aliases(vec![
                (
                    ModelId::new("work").expect("alias"),
                    ModelId::new("gpt-4o").expect("exact"),
                ),
                (ModelId::new("other").expect("alias"), alternate),
            ])
            .expect("explicit aliases");
        provider.pin_default_model().expect("pin before activation");
        provider.activate(source.clone()).await.expect("activate");
        let request = claw_http_api::GenerationRequest {
            model: "work".to_owned(),
            prompt: "hello".to_owned(),
            instructions: None,
            media: Vec::new(),
            tools: Vec::new(),
            tool_choice: claw_http_api::ToolChoice::Auto,
            max_tokens: Some(16),
            max_tool_calls: None,
            temperature: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            stop: None,
            response_format: None,
            request_id: "alias-request".to_owned(),
            session_id: "alias-session".to_owned(),
        };
        for name in ["work", "gpt-4o", "openclaw/default"] {
            let mut allowed = request.clone();
            allowed.model = name.to_owned();
            provider
                .generate(allowed, tokio_util::sync::CancellationToken::new())
                .await
                .expect("same exact model");
            assert_eq!(
                source
                    .last_request
                    .lock()
                    .expect("request")
                    .as_ref()
                    .expect("captured")
                    .model
                    .as_str(),
                "gpt-4o"
            );
        }
        let (events, mut receiver) = tokio::sync::mpsc::channel(16);
        provider
            .stream(
                request.clone(),
                events,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .expect("alias stream");
        assert!(receiver.try_recv().is_ok());
        assert_eq!(
            source
                .last_request
                .lock()
                .expect("stream request")
                .as_ref()
                .expect("captured")
                .model
                .as_str(),
            "gpt-4o"
        );
        provider
            .embed(
                claw_http_api::EmbeddingRequest {
                    model: "work".to_owned(),
                    input: vec!["text".to_owned()],
                    dimensions: None,
                },
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .expect("alias embeddings");
        let calls = source.calls();
        for name in ["other", "alternate-exact", "WORK", "missing"] {
            let mut denied = request.clone();
            denied.model = name.to_owned();
            assert!(
                provider
                    .generate(denied.clone(), tokio_util::sync::CancellationToken::new())
                    .await
                    .is_err(),
                "{name}"
            );
            let (events, mut receiver) = tokio::sync::mpsc::channel(16);
            assert!(
                provider
                    .stream(denied, events, tokio_util::sync::CancellationToken::new())
                    .await
                    .is_err()
            );
            assert!(receiver.try_recv().is_err());
            assert!(
                provider
                    .embed(
                        claw_http_api::EmbeddingRequest {
                            model: name.to_owned(),
                            input: vec!["text".to_owned()],
                            dimensions: None
                        },
                        tokio_util::sync::CancellationToken::new()
                    )
                    .await
                    .is_err()
            );
            assert_eq!(source.calls(), calls, "{name}: no provider operation");
        }
        assert_eq!(provider.default_model(), "gpt-4o");
        provider.shutdown().await;
    }

    #[tokio::test]
    async fn provider_model_declared_limits_reject_incompatible_requests_before_generation() {
        use super::{
            Capability, CapabilitySet, ChatMessage, CompletionRequest, ContentPart, ImageMediaType,
            ImagePart, ImageSource, ModelId, ProviderAdapter, RequestContext,
        };
        let source = Arc::new(ModelCapabilityProvider::new(
            CapabilitySet::from_slice(&[Capability::Completion]),
            CapabilitySet::from_slice(&Capability::ALL),
        ));
        let adapter = ProviderAdapter::new(
            source.clone(),
            "gpt-4o",
            "role",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            Arc::new(DependencyReadiness::new(["provider"])),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        );
        adapter
            .initialize(&RequestContext::new())
            .await
            .expect("published catalogue");
        let plain = CompletionRequest::new(
            ModelId::new("gpt-4o").expect("model"),
            vec![ChatMessage::user_text("hello")],
        );
        for scenario in [
            "tools",
            "image",
            "assistant-image",
            "tool-history",
            "assistant-tools",
            "parallel-tools",
            "output-limit",
            "zero-output",
            "json-mode",
            "absent-model",
        ] {
            let mut request = plain.clone();
            match scenario {
                "tools" => request.tools.push(super::ToolDefinition {
                    name: "lookup".to_owned(),
                    description: "fixture".to_owned(),
                    parameters: super::ToolParameters::empty(),
                }),
                "image" => request
                    .messages
                    .push(ChatMessage::User(vec![ContentPart::Image(ImagePart {
                        media_type: ImageMediaType::Png,
                        source: ImageSource::Base64("AA==".to_owned()),
                    })])),
                "output-limit" => request.max_output_tokens = Some(17),
                "zero-output" => request.max_output_tokens = Some(0),
                "assistant-image" => {
                    request
                        .messages
                        .push(ChatMessage::Assistant(super::AssistantMessage {
                            content: vec![ContentPart::Image(ImagePart {
                                media_type: ImageMediaType::Png,
                                source: ImageSource::Base64("AA==".to_owned()),
                            })],
                            ..super::AssistantMessage::default()
                        }));
                }
                "tool-history" => request.messages.push(ChatMessage::ToolResult(
                    claw_provider_sdk::model::ToolResultMessage {
                        tool_call_id: "call".to_owned(),
                        content: "result".to_owned(),
                        is_error: false,
                    },
                )),
                "assistant-tools" => {
                    request
                        .messages
                        .push(ChatMessage::Assistant(super::AssistantMessage {
                            tool_calls: vec![claw_provider_sdk::ToolCall {
                                id: "call".to_owned(),
                                name: "lookup".to_owned(),
                                arguments: claw_provider_sdk::ToolArguments::new("{}")
                                    .expect("arguments"),
                            }],
                            ..super::AssistantMessage::default()
                        }));
                }
                "parallel-tools" => request.parallel_tool_calls = Some(true),
                "absent-model" => request.model = ModelId::new("absent").expect("unknown model"),
                _ => request.response_format = super::ResponseFormat::JsonObject,
            }
            let result = adapter
                .complete(request, tokio_util::sync::CancellationToken::new())
                .await;
            assert!(
                result.is_err(),
                "model catalogue restrictions must stop {scenario}"
            );
            assert_eq!(
                source.calls(),
                0,
                "{scenario}: rejected before provider invocation"
            );
        }
        assert!(
            adapter
                .complete(plain, tokio_util::sync::CancellationToken::new())
                .await
                .is_ok()
        );
        assert_eq!(source.calls(), 1);
    }

    #[tokio::test]
    async fn model_capability_admission_covers_streams_embeddings_runtime_and_unknown_declarations()
    {
        use super::{Capability, CapabilitySet, ProviderAdapter};
        use claw_http_api::ProviderPort as _;
        let request = claw_http_api::GenerationRequest {
            model: "gpt-4o".to_owned(),
            prompt: "hello".to_owned(),
            instructions: None,
            media: Vec::new(),
            tools: Vec::new(),
            tool_choice: claw_http_api::ToolChoice::Auto,
            max_tokens: Some(16),
            max_tool_calls: None,
            temperature: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            stop: None,
            response_format: None,
            request_id: "capability-read".to_owned(),
            session_id: "capability-session".to_owned(),
        };
        for scenario in [
            "model-no-stream",
            "provider-no-stream",
            "unknown-model-capabilities",
            "declared-complete",
        ] {
            let model = match scenario {
                "model-no-stream" => CapabilitySet::from_slice(&[Capability::Completion]),
                "unknown-model-capabilities" => CapabilitySet::EMPTY,
                _ => CapabilitySet::from_slice(&Capability::ALL),
            };
            let capabilities = if scenario == "provider-no-stream" {
                CapabilitySet::from_slice(&[Capability::Completion])
            } else {
                CapabilitySet::from_slice(&Capability::ALL)
            };
            let source = Arc::new(ModelCapabilityProvider::new(model, capabilities));
            let adapter = ProviderAdapter::new(
                source.clone(),
                "gpt-4o",
                "",
                ProviderHistoryConfig::default(),
                Arc::new(EmptyModelTools),
                Arc::new(DependencyReadiness::new(["provider"])),
                Arc::new(std::sync::atomic::AtomicBool::new(true)),
            );
            adapter
                .initialize(&super::RequestContext::new())
                .await
                .expect("catalogue");
            let (events, mut receiver) = tokio::sync::mpsc::channel(4);
            let result = adapter
                .stream(
                    request.clone(),
                    events,
                    tokio_util::sync::CancellationToken::new(),
                )
                .await;
            let accepted = matches!(scenario, "unknown-model-capabilities" | "declared-complete");
            assert_eq!(result.is_ok(), accepted, "{scenario}");
            if accepted {
                assert!(receiver.try_recv().is_ok());
            } else {
                assert!(receiver.try_recv().is_err());
            }
            assert_eq!(source.calls(), usize::from(accepted));
            let embedded = adapter
                .embed(
                    claw_http_api::EmbeddingRequest {
                        model: "gpt-4o".to_owned(),
                        input: vec!["text".to_owned()],
                        dimensions: None,
                    },
                    tokio_util::sync::CancellationToken::new(),
                )
                .await;
            assert_eq!(embedded.is_ok(), accepted, "{scenario}");
            assert_eq!(source.calls(), 2 * usize::from(accepted));
        }
        let source = Arc::new(ModelCapabilityProvider::new(
            CapabilitySet::from_slice(&[Capability::Completion]),
            CapabilitySet::from_slice(&Capability::ALL),
        ));
        let provider = SwappableProvider::new(
            "gpt-4o",
            "",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            Arc::new(DependencyReadiness::new(["provider"])),
        );
        provider
            .activate(source.clone())
            .await
            .expect("runtime provider");
        let mut tool_request = request.clone();
        tool_request.tool_choice = claw_http_api::ToolChoice::Required;
        let generated = provider
            .generate_context(
                tool_request,
                vec![super::ChatMessage::user_text("owned context")],
                tokio_util::sync::CancellationToken::new(),
            )
            .await;
        assert!(generated.is_err());
        assert_eq!(
            source.calls(),
            0,
            "runtime must share the model admission gate"
        );
        let mut automatic = request.clone();
        automatic.tools.push(claw_http_api::ClientTool {
            name: "update_goal".to_owned(),
            description: None,
            parameters: None,
        });
        assert!(
            provider
                .generate_context(
                    automatic.clone(),
                    vec![super::ChatMessage::user_text("text context")],
                    tokio_util::sync::CancellationToken::new()
                )
                .await
                .is_ok()
        );
        assert_eq!(source.calls(), 1);
        assert!(
            source
                .last_request
                .lock()
                .expect("fixture request")
                .as_ref()
                .expect("complete request")
                .tools
                .is_empty(),
            "optional runtime tools are not offered to a text-only model"
        );
        assert!(
            provider
                .generate(automatic, tokio_util::sync::CancellationToken::new())
                .await
                .is_err(),
            "explicit HTTP client tools cannot be silently removed"
        );
        assert_eq!(source.calls(), 1);
    }

    #[tokio::test]
    async fn model_admission_uses_known_bounds_without_inventing_unknown_limits_or_fallbacks() {
        use super::{
            Capability, CapabilitySet, ChatMessage, CompletionRequest, ModelId, ProviderAdapter,
        };
        for (context, output, requested, accepted) in [
            (Some(8), None, 9, false),
            (Some(8), None, 8, true),
            (None, Some(16), 17, false),
            (None, Some(16), 16, true),
            (None, None, 100_000, true),
            (None, None, 0, false),
        ] {
            let mut source = ModelCapabilityProvider::new(
                CapabilitySet::from_slice(&[Capability::Completion]),
                CapabilitySet::from_slice(&Capability::ALL),
            );
            source.source.models[0].context_window = context;
            source.source.models[0].max_output_tokens = output;
            let source = Arc::new(source);
            let readiness = Arc::new(DependencyReadiness::new(["provider"]));
            readiness.set("provider", true);
            let adapter = ProviderAdapter::new(
                source.clone(),
                "gpt-4o",
                "",
                ProviderHistoryConfig::default(),
                Arc::new(EmptyModelTools),
                readiness.clone(),
                Arc::new(std::sync::atomic::AtomicBool::new(true)),
            );
            let mut request = CompletionRequest::new(
                ModelId::new("gpt-4o").expect("model"),
                vec![ChatMessage::user_text("hello")],
            );
            request.max_output_tokens = Some(requested);
            assert!(
                adapter
                    .complete(request.clone(), tokio_util::sync::CancellationToken::new())
                    .await
                    .is_err(),
                "uninitialized catalogue cannot authorize generation"
            );
            assert_eq!(source.calls(), 0);
            adapter
                .initialize(&super::RequestContext::new())
                .await
                .expect("catalogue");
            assert_eq!(
                adapter
                    .complete(request, tokio_util::sync::CancellationToken::new())
                    .await
                    .is_ok(),
                accepted
            );
            assert_eq!(source.calls(), usize::from(accepted));
            assert!(
                readiness.is_ready(),
                "request rejection does not mark a healthy provider down"
            );
            assert_eq!(adapter.default_model(), "gpt-4o");
        }
    }

    #[tokio::test]
    async fn model_catalogue_snapshot_does_not_alias_a_replaced_provider_at_the_same_time() {
        let provider = SwappableProvider::new(
            "gpt-4o",
            "role",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            Arc::new(DependencyReadiness::new(["provider"])),
        );
        provider
            .activate(Arc::new(SmokeProvider::new().expect("first provider")))
            .await
            .expect("initial activation");
        let first = provider
            .catalogue_page(&serde_json::json!({"offset":0}))
            .expect("first snapshot");
        let timestamp = provider
            .active()
            .expect("first adapter")
            .catalogue_observed_at_ms
            .load(std::sync::atomic::Ordering::Acquire);
        provider
            .activate(Arc::new(
                SmokeProvider::new().expect("replacement provider"),
            ))
            .await
            .expect("replacement activation");
        provider
            .active()
            .expect("replacement adapter")
            .catalogue_observed_at_ms
            .store(timestamp, std::sync::atomic::Ordering::Release);
        let replacement = provider
            .catalogue_page(&serde_json::json!({"offset":0}))
            .expect("replacement snapshot");
        assert_eq!(replacement["models"], first["models"]);
        assert_eq!(replacement["observedAtMs"], first["observedAtMs"]);
        assert_ne!(
            replacement["sha256"], first["sha256"],
            "old instance must not authorize a new instance's catalogue refresh"
        );
        assert!(
            provider
                .refresh_catalogue(
                    first["sha256"].as_str().expect("old digest"),
                    tokio_util::sync::CancellationToken::new()
                )
                .await
                .is_err()
        );
        provider.shutdown().await;
    }

    #[tokio::test]
    async fn model_catalogue_refresh_is_bounded_cancel_safe_and_preserves_selected_provider() {
        use super::{ModelDescriptor, Provider, ProviderFuture, RequestContext};
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct RefreshFixture {
            provider: SmokeProvider,
            reads: AtomicUsize,
            entered: tokio::sync::Notify,
            release: tokio::sync::Notify,
            missing: bool,
            alias_change: Option<&'static str>,
        }
        impl Provider for RefreshFixture {
            fn id(&self) -> &super::ProviderId {
                self.provider.id()
            }
            fn capabilities(&self) -> super::CapabilitySet {
                self.provider.capabilities()
            }
            fn startup<'a>(
                &'a self,
                context: &'a RequestContext,
            ) -> ProviderFuture<'a, Result<super::ProviderStatus, super::ProviderError>>
            {
                self.provider.startup(context)
            }
            fn ping<'a>(
                &'a self,
                context: &'a RequestContext,
            ) -> ProviderFuture<'a, Result<super::ProviderStatus, super::ProviderError>>
            {
                self.provider.ping(context)
            }
            fn list_models<'a>(
                &'a self,
                _context: &'a RequestContext,
            ) -> ProviderFuture<'a, Result<Vec<ModelDescriptor>, super::ProviderError>>
            {
                Box::pin(async move {
                    let ordinal = self.reads.fetch_add(1, Ordering::SeqCst);
                    if ordinal > 0 {
                        self.entered.notify_one();
                        self.release.notified().await;
                    }
                    let mut models = self.provider.models.clone();
                    if ordinal > 0 {
                        if self.missing {
                            models.clear();
                        } else {
                            models.push(ModelDescriptor {
                                id: super::ModelId::new("new-catalogue-model").expect("model"),
                                ..models[0].clone()
                            });
                            match self.alias_change {
                                Some("alias-collision") => models.push(ModelDescriptor {
                                    id: super::ModelId::new("work").expect("new exact identifier"),
                                    ..models[0].clone()
                                }),
                                Some("alias-target-deleted") => {
                                    models.retain(|model| model.id.as_str() != "alternate-exact");
                                }
                                _ => {}
                            }
                        }
                    }
                    Ok(models)
                })
            }
        }
        for scenario in [
            "success",
            "cancelled",
            "dropped",
            "missing-model",
            "selection-changed",
            "provider-changed",
            "shutdown",
            "timeout",
            "alias-collision",
            "alias-target-deleted",
        ] {
            let alias_change =
                matches!(scenario, "alias-collision" | "alias-target-deleted").then_some(scenario);
            let mut source = SmokeProvider::new().expect("fixture");
            if alias_change.is_some() {
                source.models.push(ModelDescriptor {
                    id: super::ModelId::new("alternate-exact").expect("alias target"),
                    ..source.models[0].clone()
                });
            }
            let fixture = Arc::new(RefreshFixture {
                provider: source,
                reads: AtomicUsize::new(0),
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
                missing: scenario == "missing-model",
                alias_change,
            });
            let provider = SwappableProvider::new(
                "gpt-4o",
                "role",
                ProviderHistoryConfig::default(),
                Arc::new(EmptyModelTools),
                Arc::new(DependencyReadiness::new(["provider"])),
            );
            if alias_change.is_some() {
                provider
                    .configure_model_aliases(vec![(
                        super::ModelId::new("work").expect("alias"),
                        super::ModelId::new("alternate-exact").expect("target"),
                    )])
                    .expect("explicit aliases");
            }
            provider
                .activate(fixture.clone())
                .await
                .expect("initial catalogue");
            let initial = provider
                .catalogue_page(&serde_json::json!({"offset":0}))
                .expect("snapshot");
            let digest = initial["sha256"].as_str().expect("digest");
            let generation = provider.provider_generation();
            let cancel = tokio_util::sync::CancellationToken::new();
            let mut pending = Box::pin(provider.refresh_catalogue(digest, cancel.clone()));
            tokio::select! {result=&mut pending=>panic!("refresh must wait: {result:?}"),()=fixture.entered.notified()=>{}}
            assert!(
                provider
                    .refresh_catalogue(digest, tokio_util::sync::CancellationToken::new())
                    .await
                    .is_err(),
                "no concurrent refresh"
            );
            assert_eq!(fixture.reads.load(Ordering::SeqCst), 2);
            assert_eq!(
                provider
                    .catalogue_page(&serde_json::json!({"offset":0}))
                    .expect("old cache"),
                initial
            );
            match scenario {
                "dropped" => drop(pending),
                "cancelled" => {
                    cancel.cancel();
                    assert!(pending.await.is_err());
                }
                "timeout" => {
                    assert_eq!(
                        pending
                            .await
                            .expect_err("bounded non-cooperative refresh")
                            .kind,
                        PortErrorKind::Timeout
                    );
                }
                "shutdown" => {
                    let (result, ()) = tokio::join!(pending, provider.shutdown());
                    assert!(result.is_err());
                }
                _ => {
                    if scenario == "selection-changed" {
                        provider.set_role_prompt("new role");
                    }
                    if scenario == "provider-changed" {
                        provider
                            .activate(Arc::new(SmokeProvider::new().expect("replacement")))
                            .await
                            .expect("replace provider");
                    }
                    fixture.release.notify_one();
                    assert_eq!(pending.await.is_ok(), scenario == "success", "{scenario}");
                }
            }
            if !matches!(scenario, "shutdown" | "provider-changed") {
                assert_eq!(provider.provider_generation(), generation);
                assert_eq!(provider.default_model(), "gpt-4o");
                if alias_change.is_some() {
                    assert_eq!(
                        provider
                            .catalogue_page(&serde_json::json!({"offset":0}))
                            .expect("unchanged cached snapshot"),
                        initial
                    );
                    assert_eq!(
                        provider
                            .active_for_model("work")
                            .expect("original alias target")
                            .1
                            .as_str(),
                        "alternate-exact"
                    );
                }
                assert_eq!(
                    provider
                        .model_ids()
                        .expect("retained models")
                        .contains(&"new-catalogue-model".to_owned()),
                    scenario == "success"
                );
            }
            provider.shutdown().await;
        }
    }

    #[tokio::test]
    async fn model_alias_catalogue_pages_fit_the_wire_byte_budget_and_preserve_exact_ids() {
        let mut source = SmokeProvider::new().expect("source");
        let original = source.models[0].clone();
        source.models = (0..10)
            .map(|index| super::ModelDescriptor {
                id: super::ModelId::new(format!("model-{index}")).expect("id"),
                display_name: Some("\"".repeat(512)),
                ..original.clone()
            })
            .collect();
        let provider = SwappableProvider::new(
            "model-0",
            "",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            Arc::new(DependencyReadiness::new(["provider"])),
        );
        let aliases = (0..16)
            .map(|index| {
                (
                    super::ModelId::new(format!("{}{index}", "\"".repeat(240)))
                        .expect("escaped alias"),
                    super::ModelId::new("model-0").expect("target"),
                )
            })
            .collect();
        provider
            .configure_model_aliases(aliases)
            .expect("bounded aliases");
        provider
            .activate(Arc::new(source))
            .await
            .expect("catalogue");
        let first = provider
            .catalogue_page(&serde_json::json!({"offset":0}))
            .expect("first page");
        assert!(
            first["endOffset"].as_u64().expect("end") < 8,
            "escaped metadata must shrink the page"
        );
        assert_eq!(first["models"][0]["id"], "model-0");
        assert_eq!(
            first["models"][0]["aliases"]
                .as_array()
                .expect("aliases")
                .len(),
            16
        );
        claw_protocol::native_models::validate_page(&first.to_string(), 0, None)
            .expect("validated first page");
        let next =
            usize::try_from(first["nextOffset"].as_u64().expect("next")).expect("bounded offset");
        let last = provider
            .catalogue_page(&serde_json::json!({"offset":next,"sha256":first["sha256"]}))
            .expect("continuation");
        claw_protocol::native_models::validate_page(
            &last.to_string(),
            next,
            first["sha256"].as_str(),
        )
        .expect("validated continuation");
        assert_eq!(last["endOffset"], 10);
        provider.shutdown().await;
    }

    #[tokio::test]
    async fn native_model_catalogue_unavailability_is_opt_in_and_tracks_actual_lifecycle() {
        use claw_protocol::native_models::CatalogueUnavailableReason;
        let readiness = Arc::new(DependencyReadiness::new(["provider"]));
        let fixture = SmokeProvider::new().expect("fixture");
        let model = fixture.models[0].id.as_str().to_owned();
        let provider = SwappableProvider::new(
            model.clone(),
            "role",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            Arc::clone(&readiness),
        );
        let legacy = serde_json::json!({"schemaVersion":1,"available":false,"selectionChanged":false,"networkContacted":false});
        let detailed = serde_json::json!({"offset":0,"includeAvailability":true});
        assert_eq!(
            provider
                .catalogue_page(&serde_json::json!({"offset":0}))
                .expect("legacy page"),
            legacy
        );
        assert_eq!(
            provider.catalogue_page(&detailed).expect("initial state")["unavailableReason"],
            "not_initialized"
        );
        provider
            .configure_initial_unavailability(CatalogueUnavailableReason::AuthenticationPending)
            .expect("startup auth state");
        assert_eq!(
            provider.catalogue_page(&detailed).expect("pending state")["unavailableReason"],
            "authentication_pending"
        );
        assert!(
            provider
                .configure_initial_unavailability(CatalogueUnavailableReason::Disabled)
                .is_err()
        );
        provider
            .activate(Arc::new(fixture))
            .await
            .expect("authenticated catalogue");
        let available = provider
            .catalogue_page(&detailed)
            .expect("cached directory");
        assert_eq!(available["available"], true);
        assert!(available.get("unavailableReason").is_none());
        assert!(
            !provider
                .ready_gate
                .load(std::sync::atomic::Ordering::Acquire),
            "published cache is not live readiness"
        );
        claw_protocol::native_models::validate_page(&available.to_string(), 0, None)
            .expect("unchanged available format");
        provider.shutdown().await;
        let retired = provider.catalogue_page(&detailed).expect("retired state");
        assert_eq!(retired["unavailableReason"], "retired");
        claw_protocol::native_models::validate_page(&retired.to_string(), 0, None)
            .expect("typed unavailable page");
        assert_eq!(
            provider
                .catalogue_page(&serde_json::json!({"offset":0}))
                .expect("legacy shutdown"),
            legacy
        );
        assert!(
            provider
                .configure_initial_unavailability(CatalogueUnavailableReason::AuthenticationPending)
                .is_err()
        );

        let disabled = SwappableProvider::new(
            model,
            "role",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            readiness,
        );
        disabled
            .configure_initial_unavailability(CatalogueUnavailableReason::Disabled)
            .expect("explicit disable");
        let blocked = Arc::new(ModelCapabilityProvider::new(
            super::CapabilitySet::EMPTY,
            super::CapabilitySet::EMPTY,
        ));
        assert!(disabled.activate(blocked.clone()).await.is_err());
        assert_eq!(
            blocked
                .lifecycle_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert!(provider.activate(blocked.clone()).await.is_err());
        assert_eq!(
            blocked
                .lifecycle_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            disabled.catalogue_page(&detailed).expect("disabled state")["unavailableReason"],
            "disabled"
        );
        assert_eq!(disabled.provider_generation(), 0);
        assert!(
            disabled
                .catalogue_page(&serde_json::json!({"offset":0,"includeAvailability":"true"}))
                .is_err()
        );
    }

    #[tokio::test]
    async fn native_model_catalogue_pages_preserve_metadata_and_pin_selection_without_network() {
        let readiness = Arc::new(DependencyReadiness::new(["provider"]));
        let mut fixture = SmokeProvider::new().expect("fixture");
        let original = fixture.models[0].clone();
        fixture.models = (0..10)
            .map(|ordinal| super::ModelDescriptor {
                id: super::ModelId::new(format!("fixture-model-{ordinal}")).expect("ID"),
                display_name: Some(format!("Fixture {ordinal}")),
                context_window: None,
                max_output_tokens: None,
                ..original.clone()
            })
            .collect();
        let provider = SwappableProvider::new(
            "fixture-model-0",
            "role",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            readiness,
        );
        assert_eq!(
            provider
                .catalogue_page(&serde_json::json!({"offset":0}))
                .expect("not authenticated")["available"],
            false
        );
        provider
            .activate(Arc::new(fixture))
            .await
            .expect("valid catalogue");
        let generation = provider.provider_generation();
        let first = provider
            .catalogue_page(&serde_json::json!({"offset":0}))
            .expect("first page");
        assert_eq!(first["nextOffset"], 8);
        assert_eq!(first["totalModels"], 10);
        assert_eq!(first["selectedModel"], "fixture-model-0");
        assert_eq!(first["source"], "provider_sdk_catalogue");
        assert_eq!(first["liveCapabilitiesVerified"], false);
        assert!(first["models"][0]["contextWindow"].is_null());
        assert_eq!(first["models"][0]["displayName"], "Fixture 0");
        assert_eq!(
            first["models"][0]["advertisedCapabilities"],
            serde_json::json!(
                original
                    .capabilities
                    .to_vec()
                    .into_iter()
                    .map(claw_provider_sdk::Capability::as_str)
                    .collect::<Vec<_>>()
            )
        );
        let cursor = serde_json::json!({"offset":8,"sha256":first["sha256"]});
        let last = provider.catalogue_page(&cursor).expect("continuation");
        assert_eq!(last["models"].as_array().expect("models").len(), 2);
        assert!(last["nextOffset"].is_null());
        assert_eq!(provider.provider_generation(), generation);
        assert_eq!(provider.default_model(), "fixture-model-0");
        for invalid in [
            serde_json::json!({"offset":1}),
            serde_json::json!({"offset":1025}),
            serde_json::json!({"offset":10,"sha256":first["sha256"]}),
            serde_json::json!({"offset":0,"refresh":true}),
        ] {
            assert!(provider.catalogue_page(&invalid).is_err());
        }
        provider
            .set_default_model("fixture-model-1")
            .expect("explicit permitted selection");
        assert!(
            provider.catalogue_page(&cursor).is_err(),
            "selection change invalidates the snapshot"
        );
        provider
            .pin_default_model()
            .expect("pin explicit selection");
        assert_eq!(
            provider
                .catalogue_page(&serde_json::json!({"offset":0}))
                .expect("fresh snapshot")["selectionPinned"],
            true
        );
        provider.shutdown().await;
        assert_eq!(
            provider
                .catalogue_page(&serde_json::json!({"offset":0}))
                .expect("closed catalogue")["available"],
            false
        );
    }

    #[tokio::test]
    async fn model_alias_publication_rejects_collisions_and_deleted_targets_without_replacing_current()
     {
        use super::ModelId;
        let provider = SwappableProvider::new(
            "gpt-4o",
            "role",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            Arc::new(DependencyReadiness::new(["provider"])),
        );
        let mut source = SmokeProvider::new().expect("source");
        let alternate = ModelId::new("alternate-exact").expect("exact model");
        source.models.push(super::ModelDescriptor {
            id: alternate.clone(),
            ..source.models[0].clone()
        });
        provider
            .configure_model_aliases(vec![(
                ModelId::new("work").expect("alias"),
                alternate.clone(),
            )])
            .expect("startup aliases");
        let models = source.models.clone();
        provider
            .activate(Arc::new(source))
            .await
            .expect("valid publication");
        let generation = provider.provider_generation();
        let original = provider.model_ids().expect("catalogue");
        assert!(
            provider.configure_model_aliases(Vec::new()).is_err(),
            "no hot alias edits"
        );
        for scenario in ["collision", "deleted"] {
            let mut candidate = SmokeProvider::new().expect("candidate");
            candidate.models = models.clone();
            if scenario == "collision" {
                candidate.models.push(super::ModelDescriptor {
                    id: ModelId::new("work").expect("new exact ID"),
                    ..candidate.models[0].clone()
                });
            } else {
                candidate.models.retain(|model| model.id != alternate);
            }
            assert!(
                provider.activate(Arc::new(candidate)).await.is_err(),
                "{scenario}"
            );
            assert_eq!(provider.provider_generation(), generation);
            assert_eq!(
                provider.model_ids().expect("old catalogue retained"),
                original
            );
        }
        provider.shutdown().await;
        assert!(
            provider.configure_model_aliases(Vec::new()).is_err(),
            "retired provider cannot revive"
        );
    }

    #[tokio::test]
    async fn provider_catalogue_rejects_ambiguous_or_unbounded_descriptors_before_publication() {
        let readiness = Arc::new(DependencyReadiness::new(["provider"]));
        let initial = SmokeProvider::new().expect("initial fixture");
        let selected = initial.models[0].id.as_str().to_owned();
        let provider = SwappableProvider::new(
            selected,
            "role",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            readiness,
        );
        provider
            .activate(Arc::new(initial))
            .await
            .expect("initial publication");
        let generation = provider.provider_generation();
        let original_models = provider.model_ids().expect("original models");
        for scenario in [
            "duplicate",
            "too-many",
            "display-name",
            "zero-context",
            "zero-output",
            "output-exceeds-context",
        ] {
            let mut candidate = SmokeProvider::new().expect("candidate fixture");
            let first = candidate.models[0].clone();
            match scenario {
                "duplicate" => candidate.models.push(first),
                "too-many" => {
                    candidate.models = (0..1025)
                        .map(|ordinal| super::ModelDescriptor {
                            id: if ordinal == 0 {
                                first.id.clone()
                            } else {
                                super::ModelId::new(format!("fixture-model-{ordinal}"))
                                    .expect("fixture ID")
                            },
                            ..first.clone()
                        })
                        .collect();
                }
                "display-name" => {
                    candidate.models[0].display_name = Some("untrusted\nlabel".to_owned());
                }
                "zero-context" => candidate.models[0].context_window = Some(0),
                "zero-output" => candidate.models[0].max_output_tokens = Some(0),
                _ => {
                    candidate.models[0].context_window = Some(100);
                    candidate.models[0].max_output_tokens = Some(101);
                }
            }
            assert!(
                provider.activate(Arc::new(candidate)).await.is_err(),
                "{scenario}: malformed catalogue was published"
            );
            assert_eq!(provider.provider_generation(), generation, "{scenario}");
            assert_eq!(
                provider
                    .model_ids()
                    .expect("previous valid catalogue retained"),
                original_models
            );
        }
        provider.shutdown().await;
    }

    #[tokio::test]
    async fn provider_response_report_keeps_actual_identity_and_usage_coverage() {
        use super::Provider as _;

        let provider = SmokeProvider::new().expect("owned provider");
        let request = super::CompletionRequest::new(
            super::ModelId::new("actual-model").expect("model"),
            vec![super::ChatMessage::user_text("owned input")],
        );
        let mut response = provider
            .complete(&request, &super::RequestContext::new())
            .await
            .expect("owned response");
        let report = super::provider_response_report(
            "actual-provider",
            &response,
            claw_http_api::GenerationFinishReason::Length,
        )
        .expect("response report");
        assert_eq!(report.provider, "actual-provider");
        assert_eq!(report.model, "actual-model");
        assert_eq!(report.response_id.as_deref(), Some("smoke-response"));
        assert_eq!(report.input_tokens, 1);
        assert_eq!(
            report.usage_reporting,
            claw_http_api::UsageReporting::Complete
        );
        assert_eq!(
            report.finish_reason,
            claw_application::ports::provider::ProviderResponseFinish::Length
        );
        response.id.clear();
        response.usage = super::Usage::default();
        response.usage_reporting = claw_provider_sdk::model::UsageReporting::Unreported;
        let unknown = super::provider_response_report(
            "actual-provider",
            &response,
            claw_http_api::GenerationFinishReason::Stop,
        )
        .expect("unreported remains unknown");
        assert!(unknown.response_id.is_none());
        assert_eq!(
            unknown.usage_reporting,
            claw_http_api::UsageReporting::Unreported
        );
        response.usage_reporting = claw_provider_sdk::model::UsageReporting::Complete;
        let zero = super::provider_response_report(
            "actual-provider",
            &response,
            claw_http_api::GenerationFinishReason::Stop,
        )
        .expect("explicit zero remains known");
        assert_ne!(unknown, zero);
        assert_eq!(
            zero.usage_reporting,
            claw_http_api::UsageReporting::Complete
        );
    }

    #[test]
    fn provider_adapter_preserves_partial_status_and_rejects_unknown_or_partial_tools() {
        use claw_provider_sdk::FinishReason;

        for reason in [
            FinishReason::Length,
            FinishReason::ContentFilter,
            FinishReason::Cancelled,
            FinishReason::Other("private-provider-reason".to_owned()),
        ] {
            for has_tools in [false, true] {
                if !has_tools
                    && matches!(reason, FinishReason::Length | FinishReason::ContentFilter)
                {
                    assert!(
                        !super::generation_finish_reason(&reason, has_tools)
                            .expect("known partial result")
                            .is_complete()
                    );
                    continue;
                }
                let error = super::generation_finish_reason(&reason, has_tools)
                    .expect_err("not an ordinary complete answer");
                assert!(!error.to_string().contains("private-provider-reason"));
            }
        }
        assert!(super::generation_finish_reason(&FinishReason::Stop, false).is_ok());
        assert!(super::generation_finish_reason(&FinishReason::Stop, true).is_ok());
        assert!(super::generation_finish_reason(&FinishReason::ToolCalls, true).is_ok());
        assert!(super::generation_finish_reason(&FinishReason::ToolCalls, false).is_err());
    }

    #[tokio::test]
    async fn provider_adapter_holds_tools_until_complete_and_does_not_remember_failed_turns() {
        use claw_http_api::ProviderPort as _;
        use futures_util::StreamExt as _;
        use tokio::sync::Notify;

        struct TerminalProvider {
            id: super::ProviderId,
            reason: super::FinishReason,
            has_tools: bool,
            usage: super::Usage,
            reporting: Option<claw_provider_sdk::model::UsageReporting>,
            waiting: Arc<Notify>,
            release: Arc<Notify>,
        }

        impl TerminalProvider {
            fn message(&self) -> super::AssistantMessage {
                super::AssistantMessage {
                    content: vec![super::ContentPart::text("partial text")],
                    tool_calls: if self.has_tools {
                        vec![claw_provider_sdk::ToolCall {
                            id: "owned-call".to_owned(),
                            name: "lookup".to_owned(),
                            arguments: claw_provider_sdk::ToolArguments::new("{}")
                                .expect("arguments"),
                        }]
                    } else {
                        Vec::new()
                    },
                    reasoning: None,
                }
            }
        }

        impl super::Provider for TerminalProvider {
            fn id(&self) -> &super::ProviderId {
                &self.id
            }
            fn capabilities(&self) -> super::CapabilitySet {
                super::CapabilitySet::from_slice(&[
                    super::Capability::Completion,
                    super::Capability::Streaming,
                ])
            }
            fn list_models<'a>(
                &'a self,
                _context: &'a super::RequestContext,
            ) -> super::ProviderFuture<'a, Result<Vec<super::ModelDescriptor>, super::ProviderError>>
            {
                Box::pin(async move {
                    Ok(vec![super::ModelDescriptor {
                        id: super::ModelId::new("owned-model").expect("fixture model"),
                        display_name: None,
                        context_window: None,
                        max_output_tokens: None,
                        capabilities: self.capabilities(),
                    }])
                })
            }
            fn complete<'a>(
                &'a self,
                request: &'a super::CompletionRequest,
                _context: &'a super::RequestContext,
            ) -> super::ProviderFuture<'a, Result<super::CompletionResponse, super::ProviderError>>
            {
                Box::pin(async move {
                    Ok(super::CompletionResponse {
                        id: "owned-response".to_owned(),
                        model: request.model.clone(),
                        message: self.message(),
                        finish_reason: self.reason.clone(),
                        usage_reporting: self.reporting.unwrap_or_else(|| {
                            if self.usage.total_tokens() == 0 {
                                claw_provider_sdk::model::UsageReporting::Unreported
                            } else {
                                claw_provider_sdk::model::UsageReporting::Partial
                            }
                        }),
                        usage: self.usage,
                    })
                })
            }
            fn stream<'a>(
                &'a self,
                request: &'a super::CompletionRequest,
                context: &'a super::RequestContext,
            ) -> super::ProviderFuture<'a, Result<super::CompletionStream, super::ProviderError>>
            {
                let waiting = Arc::clone(&self.waiting);
                let release = Arc::clone(&self.release);
                let reason = self.reason.clone();
                let usage = self.usage;
                let reporting = self.reporting;
                let model = request.model.as_str().to_owned();
                let cancel = context.cancel().clone();
                let mut message = self.message();
                Box::pin(async move {
                    let mut prefix = vec![
                        Ok(super::StreamEvent::Started {
                            id: "owned-response".to_owned(),
                            model,
                        }),
                        Ok(super::StreamEvent::TextDelta("partial text".to_owned())),
                    ];
                    if let Some(reporting) = reporting {
                        prefix.push(Ok(super::StreamEvent::UsageReported { usage, reporting }));
                    }
                    if let Some(call) = message.tool_calls.pop() {
                        prefix.push(Ok(super::StreamEvent::ToolCallCompleted { index: 0, call }));
                    }
                    let terminal = futures_util::stream::once(async move {
                        waiting.notify_one();
                        release.notified().await;
                        Ok(super::StreamEvent::Completed {
                            finish_reason: reason,
                            usage,
                        })
                    });
                    Ok(super::CompletionStream::new(
                        "terminal-fixture",
                        cancel,
                        Box::pin(futures_util::stream::iter(prefix).chain(terminal)),
                    ))
                })
            }
        }

        let request = claw_http_api::GenerationRequest {
            model: "owned-model".to_owned(),
            prompt: "owned request".to_owned(),
            instructions: None,
            media: Vec::new(),
            tools: Vec::new(),
            tool_choice: claw_http_api::ToolChoice::Auto,
            max_tokens: None,
            max_tool_calls: None,
            temperature: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            stop: None,
            response_format: None,
            request_id: "owned-request".to_owned(),
            session_id: "owned-session".to_owned(),
        };
        let known_usage = super::Usage {
            input_tokens: 4,
            output_tokens: 3,
            ..super::Usage::default()
        };
        let usage_profiles = [
            (
                super::Usage::default(),
                None,
                claw_http_api::UsageReporting::Unreported,
            ),
            (
                super::Usage::default(),
                Some(claw_provider_sdk::model::UsageReporting::Partial),
                claw_http_api::UsageReporting::Partial,
            ),
            (
                super::Usage::default(),
                Some(claw_provider_sdk::model::UsageReporting::Complete),
                claw_http_api::UsageReporting::Complete,
            ),
            (
                known_usage,
                Some(claw_provider_sdk::model::UsageReporting::Complete),
                claw_http_api::UsageReporting::Complete,
            ),
            (known_usage, None, claw_http_api::UsageReporting::Partial),
        ];
        for (reason, has_tools, usage, reporting, expected_reporting) in [
            super::FinishReason::ToolCalls,
            super::FinishReason::Length,
            super::FinishReason::ContentFilter,
            super::FinishReason::Cancelled,
            super::FinishReason::Other("private-terminal".to_owned()),
        ]
        .into_iter()
        .flat_map(|reason| [false, true].map(|has_tools| (reason.clone(), has_tools)))
        .flat_map(|(reason, has_tools)| {
            usage_profiles.map(|(usage, reporting, expected)| {
                (reason.clone(), has_tools, usage, reporting, expected)
            })
        }) {
            let expected_finish = super::generation_finish_reason(&reason, has_tools).ok();
            let expected_success = expected_finish.is_some();
            let expected_history =
                expected_finish.is_some_and(claw_http_api::GenerationFinishReason::is_complete);
            let waiting = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let provider = Arc::new(TerminalProvider {
                id: super::ProviderId::new("terminal-fixture").expect("id"),
                reason,
                has_tools,
                usage,
                reporting,
                waiting: Arc::clone(&waiting),
                release: Arc::clone(&release),
            });
            let adapter = Arc::new(super::ProviderAdapter::new(
                provider,
                "owned-model",
                "",
                ProviderHistoryConfig::default(),
                Arc::new(EmptyModelTools),
                Arc::new(DependencyReadiness::new(["provider"])),
                Arc::new(std::sync::atomic::AtomicBool::new(true)),
            ));
            adapter
                .initialize(&super::RequestContext::new())
                .await
                .expect("fixture catalogue initialization");
            let generated = adapter
                .generate(request.clone(), tokio_util::sync::CancellationToken::new())
                .await;
            assert_eq!(generated.is_ok(), expected_success);
            if let Ok(output) = generated {
                assert_eq!(Some(output.finish_reason), expected_finish);
                assert_eq!(output.usage.total_tokens, usage.total_tokens());
                assert_eq!(output.usage_reporting, expected_reporting);
                assert_eq!(output.text, "partial text");
            }
            assert_eq!(
                adapter.history("owned-session").len(),
                if expected_history { 2 } else { 0 }
            );
            adapter.clear_history();
            let (events, mut receiver) = tokio::sync::mpsc::channel(4);
            let worker = tokio::spawn({
                let adapter = Arc::clone(&adapter);
                let request = request.clone();
                async move {
                    adapter
                        .stream(request, events, tokio_util::sync::CancellationToken::new())
                        .await
                }
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), waiting.notified())
                .await
                .expect("provider reached terminal barrier");
            assert_eq!(
                receiver.try_recv().expect("partial text before terminal"),
                claw_http_api::GenerationEvent::Text("partial text".to_owned())
            );
            assert!(
                matches!(
                    receiver.try_recv(),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                ),
                "completed tool must still be held before terminal"
            );
            assert!(adapter.history("owned-session").is_empty());
            release.notify_one();
            let streamed = tokio::time::timeout(std::time::Duration::from_secs(2), worker)
                .await
                .expect("adapter terminates")
                .expect("worker joined");
            assert_eq!(streamed.is_ok(), expected_success);
            if let Ok(summary) = streamed {
                assert_eq!(Some(summary.finish_reason), expected_finish);
                assert_eq!(summary.usage.total_tokens, usage.total_tokens());
                assert_eq!(summary.usage_reporting, expected_reporting);
            }
            if expected_success && has_tools {
                assert!(
                    matches!(receiver.try_recv(),Ok(claw_http_api::GenerationEvent::ToolCall(call)) if call.id == "owned-call")
                );
            }
            assert!(matches!(
                receiver.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
            ));
            assert_eq!(
                adapter.history("owned-session").len(),
                if expected_history { 2 } else { 0 }
            );
        }
    }

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

    #[test]
    fn durable_audit_latches_failed_writes_for_all_subsequent_writers() {
        let readiness = Arc::new(DependencyReadiness::new(["audit"]));
        let audit = Arc::new(super::DurableSecurityAudit {
            file: std::sync::Mutex::new(
                std::fs::File::open(std::env::current_exe().expect("test executable"))
                    .expect("read-only file handle"),
            ),
            readiness: Arc::clone(&readiness),
            failed: std::sync::atomic::AtomicBool::new(false),
        });
        let first = audit
            .persist_value(&serde_json::json!({"action": "fixture"}))
            .expect_err("read-only audit cannot append");
        assert_eq!(first.message, "audit persistence failed");
        assert!(!readiness.is_ready());
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let audit = Arc::clone(&audit);
                scope.spawn(move || {
                    let refused = audit
                        .persist_value(&serde_json::json!({"action": "must_not_append"}))
                        .expect_err("failed audit remains closed");
                    assert_eq!(refused.message, "audit writer requires recovery");
                });
            }
        });
        assert!(!readiness.is_ready());
    }

    #[test]
    fn admin_port_errors_retain_their_http_classification() {
        let cases = [
            (
                PortErrorKind::InvalidRequest,
                "INVALID_REQUEST",
                Some(false),
            ),
            (PortErrorKind::NotFound, "NOT_FOUND", Some(false)),
            (PortErrorKind::Unavailable, "UNAVAILABLE", Some(false)),
            (PortErrorKind::Timeout, "AGENT_TIMEOUT", Some(true)),
            (
                PortErrorKind::OutcomeUnknown,
                "OUTCOME_UNKNOWN",
                Some(false),
            ),
            (PortErrorKind::Internal, "INTERNAL", Some(false)),
        ];
        for (kind, code, retryable) in cases {
            let failure = admin_port_failure(PortError::new(kind, "safe message"));
            assert_eq!(failure.code, code);
            assert_eq!(failure.message, "safe message");
            assert_eq!(failure.retryable, retryable);
        }
    }

    #[tokio::test]
    async fn provider_slot_transitions_from_device_pending_to_live() {
        let readiness = Arc::new(DependencyReadiness::new(["provider"]));
        let provider = SwappableProvider::new(
            "gpt-4o",
            "",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            Arc::clone(&readiness),
        );

        assert!(!provider.is_active());
        assert_eq!(provider.provider_name(), "device-flow-pending");
        assert!(!readiness.is_ready());

        provider
            .activate(Arc::new(SmokeProvider::new().expect("smoke provider")))
            .await
            .expect("provider activates");
        provider.mark_ready();

        assert!(provider.is_active());
        assert_eq!(provider.provider_name(), "smoke");
        assert!(readiness.is_ready());
    }

    #[tokio::test]
    async fn provider_preparation_is_cancel_safe_and_configuration_and_shutdown_fenced() {
        use super::{Provider, ProviderFuture, ProviderStatus, RequestContext};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::Notify;

        struct Candidate {
            provider: SmokeProvider,
            starts: AtomicUsize,
            model_reads: AtomicUsize,
            entered: Notify,
            release: Notify,
        }
        impl Provider for Candidate {
            fn id(&self) -> &super::ProviderId {
                self.provider.id()
            }
            fn capabilities(&self) -> super::CapabilitySet {
                self.provider.capabilities()
            }
            fn startup<'a>(
                &'a self,
                context: &'a RequestContext,
            ) -> ProviderFuture<'a, Result<ProviderStatus, super::ProviderError>> {
                self.starts.fetch_add(1, Ordering::SeqCst);
                self.provider.startup(context)
            }
            fn ping<'a>(
                &'a self,
                context: &'a RequestContext,
            ) -> ProviderFuture<'a, Result<ProviderStatus, super::ProviderError>> {
                self.provider.ping(context)
            }
            fn list_models<'a>(
                &'a self,
                _context: &'a RequestContext,
            ) -> ProviderFuture<'a, Result<Vec<super::ModelDescriptor>, super::ProviderError>>
            {
                Box::pin(async move {
                    self.model_reads.fetch_add(1, Ordering::SeqCst);
                    self.entered.notify_one();
                    self.release.notified().await;
                    Ok(self.provider.models.clone())
                })
            }
        }
        for scenario in [
            "rejected",
            "cancelled",
            "dropped",
            "reconfigured",
            "success",
            "shutdown",
        ] {
            let readiness = Arc::new(DependencyReadiness::new(["provider"]));
            let provider = SwappableProvider::new(
                "gpt-4o",
                "original",
                ProviderHistoryConfig::default(),
                Arc::new(EmptyModelTools),
                Arc::clone(&readiness),
            );
            provider
                .activate(Arc::new(SmokeProvider::new().expect("original")))
                .await
                .expect("original published");
            provider.mark_ready();
            let original = provider.active().expect("current original");
            let generation = provider.provider_generation();
            let mut candidate = SmokeProvider::new().expect("candidate");
            candidate.id = super::ProviderId::new("candidate").expect("candidate ID");
            if scenario == "rejected" {
                candidate.models.clear();
            }
            let candidate = Arc::new(Candidate {
                provider: candidate,
                starts: AtomicUsize::new(0),
                model_reads: AtomicUsize::new(0),
                entered: Notify::new(),
                release: Notify::new(),
            });
            let cancel = super::CancelToken::new();
            let mut pending =
                Box::pin(provider.activate_with_cancel(candidate.clone(), cancel.clone()));
            tokio::select! {
                result = &mut pending => panic!("candidate must wait for models: {result:?}"),
                () = candidate.entered.notified() => {}
            }
            assert!(Arc::ptr_eq(
                &provider.active().expect("original remains active"),
                &original
            ));
            assert_eq!(provider.provider_generation(), generation);
            assert!(readiness.is_ready());
            let output = original
                .provider
                .complete(
                    &super::CompletionRequest::new(
                        super::ModelId::new("gpt-4o").expect("model"),
                        vec![super::ChatMessage::user_text("old instance remains usable")],
                    ),
                    &RequestContext::new(),
                )
                .await
                .expect("old provider can finish");
            assert_eq!(output.id, "smoke-response");
            match scenario {
                "dropped" => drop(pending),
                "cancelled" => {
                    cancel.cancel();
                    assert!(pending.await.is_err());
                }
                "shutdown" => {
                    let (result, ()) =
                        tokio::time::timeout(std::time::Duration::from_secs(2), async {
                            tokio::join!(pending, provider.shutdown())
                        })
                        .await
                        .expect("shutdown cancels uncooperative model preparation");
                    assert!(result.is_err());
                    assert!(!provider.is_active());
                    provider.mark_ready();
                    assert!(!readiness.is_ready());
                    assert_eq!(provider.provider_generation(), generation + 1);
                    assert!(provider.activate(candidate.clone()).await.is_err());
                }
                _ => {
                    if scenario == "reconfigured" {
                        provider.set_role_prompt("new reviewed role");
                    }
                    candidate.release.notify_one();
                    assert_eq!(pending.await.is_ok(), scenario == "success", "{scenario}");
                }
            }
            assert_eq!(candidate.starts.load(Ordering::SeqCst), 1);
            assert_eq!(candidate.model_reads.load(Ordering::SeqCst), 1);
            if scenario == "success" {
                assert_eq!(provider.provider_name(), "candidate");
                assert_eq!(provider.provider_generation(), generation + 1);
                assert!(!cancel.is_cancelled());
            } else {
                assert!(cancel.is_cancelled(), "{scenario}");
                if scenario != "shutdown" {
                    assert!(Arc::ptr_eq(
                        &provider.active().expect("original preserved"),
                        &original
                    ));
                    assert_eq!(provider.provider_generation(), generation);
                    assert!(readiness.is_ready());
                }
            }
        }
    }

    #[tokio::test]
    async fn provider_model_rejection_never_advances_published_generation() {
        let readiness = Arc::new(DependencyReadiness::new(["provider"]));
        let provider = SwappableProvider::new(
            "not-a-live-model",
            "",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            Arc::clone(&readiness),
        );
        let generation = provider.provider_generation();
        provider
            .activate(Arc::new(SmokeProvider::new().expect("local provider")))
            .await
            .expect_err("selected model is absent");
        assert!(!provider.is_active());
        assert!(!readiness.is_ready());
        assert_eq!(provider.provider_generation(), generation);
        assert_eq!(provider.default_model(), "not-a-live-model");
    }

    #[tokio::test]
    async fn a_rejected_reload_restores_the_last_known_good_model() {
        let readiness = Arc::new(DependencyReadiness::new(["provider"]));
        let provider = Arc::new(SwappableProvider::new(
            "gpt-4o",
            "",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            Arc::clone(&readiness),
        ));
        provider
            .activate(Arc::new(SmokeProvider::new().expect("smoke provider")))
            .await
            .expect("provider starts");
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
        let provider = Arc::new(SwappableProvider::new(
            "gpt-4o",
            "",
            ProviderHistoryConfig::default(),
            Arc::new(EmptyModelTools),
            Arc::clone(&readiness),
        ));
        provider
            .activate(Arc::new(SmokeProvider::new().expect("smoke provider")))
            .await
            .expect("provider starts");
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

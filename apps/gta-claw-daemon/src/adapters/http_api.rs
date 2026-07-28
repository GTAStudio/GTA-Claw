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
use claw_providers::{ProviderLease, ProviderSlot};
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
    role_prompt: RwLock<String>,
    models: RwLock<Vec<ModelDescriptor>>,
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
            role_prompt: RwLock::new(role_prompt.into()),
            models: RwLock::new(Vec::new()),
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
            if self.ready_gate.load(Ordering::Acquire) {
                self.readiness.set("provider", true);
            }
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

/// Provider port that can start unauthenticated and atomically activate later.
pub struct SwappableProvider {
    slot: Arc<ProviderSlot>,
    state: RwLock<SwappableState>,
    history_config: ProviderHistoryConfig,
    model_tools: Arc<dyn ModelToolCatalog>,
    readiness: Arc<DependencyReadiness>,
    ready_gate: Arc<AtomicBool>,
}

struct SwappableState {
    current: Option<Arc<ProviderAdapter>>,
    default_model: String,
    role_prompt: String,
    generation: u64,
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
            state: RwLock::new(SwappableState {
                current: None,
                default_model: default_model.into(),
                role_prompt: role_prompt.into(),
                generation: 0,
            }),
            history_config,
            model_tools,
            readiness,
            ready_gate: Arc::new(AtomicBool::new(false)),
        }
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
        let mut cancel_on_drop = ProviderActivationGuard(Some(cancel.clone()));
        let previous = self.slot.active().await;
        let activation =
            RequestContext::with_cancel(cancel).correlation_id("daemon-provider-activation");
        let lease = self.slot.activate(provider, &activation).await?;
        loop {
            let (generation, model, role) = {
                let state = self.state.read().map_err(|_| provider_slot_error())?;
                (
                    state.generation,
                    state.default_model.clone(),
                    state.role_prompt.clone(),
                )
            };
            let adapter = Arc::new(ProviderAdapter::new(
                lease.provider_arc(),
                model,
                role,
                self.history_config,
                Arc::clone(&self.model_tools),
                Arc::clone(&self.readiness),
                Arc::clone(&self.ready_gate),
            ));
            if let Err(error) = adapter.initialize(&activation).await {
                self.restore_slot(previous).await;
                return Err(error);
            }
            lease.ensure_current(self.slot.as_ref(), claw_provider_sdk::Operation::Startup)?;
            let mut state = self.state.write().map_err(|_| provider_slot_error())?;
            if state.generation != generation {
                continue;
            }
            state.current = Some(adapter);
            drop(state);
            cancel_on_drop.disarm();
            return Ok(());
        }
    }

    async fn restore_slot(&self, previous: Option<ProviderLease>) {
        if let Some(previous) = previous {
            let context = RequestContext::new().correlation_id("daemon-provider-rollback");
            let _ = self.slot.activate(previous.provider_arc(), &context).await;
        } else {
            let _ = self.slot.clear().await;
        }
    }

    /// Fences new calls and clears the active provider.
    pub async fn shutdown(&self) {
        let _ = self.slot.clear().await;
        if let Ok(mut state) = self.state.write() {
            state.current = None;
            state.generation = state.generation.saturating_add(1);
        }
        self.ready_gate.store(false, Ordering::Release);
        self.readiness.set("provider", false);
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
        if let Some(provider) = state.current.as_ref() {
            provider.set_default_model(model)?;
        }
        model.clone_into(&mut state.default_model);
        state.generation = state.generation.saturating_add(1);
        drop(state);
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
        self.ready_gate.store(true, Ordering::Release);
        self.readiness.set("provider", true);
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

    /// Returns cached model identities from the active provider.
    ///
    /// # Errors
    ///
    /// Returns unavailable while Device Flow is pending, or the active
    /// provider's typed cache error.
    pub fn model_ids(&self) -> Result<Vec<String>, PortError> {
        self.active()?.model_ids()
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

    fn generate(
        &self,
        request: GenerationRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<GenerationOutput, PortError>> {
        let provider = self.active();
        Box::pin(async move { provider?.generate(request, cancellation).await })
    }

    fn stream(
        &self,
        request: GenerationRequest,
        events: mpsc::Sender<GenerationEvent>,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<HttpUsage, PortError>> {
        let provider = self.active();
        Box::pin(async move { provider?.stream(request, events, cancellation).await })
    }

    fn embed(
        &self,
        request: EmbeddingRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<Vec<Vec<f32>>, PortError>> {
        let provider = self.active();
        Box::pin(async move { provider?.embed(request, cancellation).await })
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
        completion.tools.extend(
            self.model_tools
                .definitions()
                .into_iter()
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
    ) -> Self {
        Self {
            config,
            provider,
            readiness,
            diagnostics,
            inventory,
            reload_lock,
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
            "providerGeneration": self.provider.provider_generation(),
            "model": model,
            "configGeneration": generation,
            "configuration": self.inventory.config_resolution,
            "plugins": self.inventory.plugin_activation,
            "runtime": self.inventory.runtime.status(),
            "channels": self.inventory.channels,
            "skills": {
                "registered": self.inventory.registered_skill_count,
                "active": self.inventory.active_skill_count,
                "state": if self.inventory.active_skill_count > 0 {
                    "signed_plugins_active"
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
                    json!({"models": self.provider.model_ids().map_err(admin_port_failure)?})
                }
                "models.authStatus" => {
                    json!({"ready": self.readiness.snapshot().map_err(admin_port_failure)?.ready})
                }
                "channels.status" => json!({"channels": self.inventory.channels}),
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
        ConfigController, DependencyReadiness, Diagnostics, EmptyModelTools, ProviderHistoryConfig,
        SmokeProvider, SwappableProvider, copilot_request_timeout_ms,
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

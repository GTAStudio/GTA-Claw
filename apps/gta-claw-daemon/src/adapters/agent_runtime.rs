//! Shared provider, memory, goal, and conversation runtime composition.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use claw_application::model::ids::{ToolCallId, TurnId};
use claw_application::model::time::Timestamp;
use claw_application::ports::PortError as RuntimePortError;
use claw_application::ports::clock::ClockPort;
use claw_application::ports::context::{
    AssembledContext as RuntimeContext, BootstrapReason, CompactionReport, ContextAssembly,
    ContextBootstrap, ContextCompaction, ContextEnginePort, ContextIngest, ContextItem,
    ContextMaintenance, ContextState,
};
use claw_application::ports::provider::{
    PromptMessage, ProviderChunk, ProviderPort as RuntimeProviderPort,
    ProviderRequest as RuntimeProviderRequest, ProviderStream as RuntimeProviderStream,
};
use claw_application::ports::state::{SessionSnapshot, StatePort, TurnRecord};
use claw_application::ports::tool::{
    ToolDescriptor, ToolInvocation as RuntimeToolInvocation, ToolOutcome as RuntimeToolOutcome,
    ToolPort as RuntimeToolPort, ToolStatus,
};
use claw_application::ports::{PortFuture as RuntimeFuture, goal::GoalStorePort};
use claw_channels::ConversationService;
use claw_domain::SessionId;
use claw_goals::FileGoalStore;
use claw_http_api::{
    ClientTool, GenerationRequest, LegacyChannelMessage, LegacyChannelMessagePort,
    LegacyRuntimePort, LegacyRuntimeSnapshot, PortError, PortErrorKind, PortFuture, ToolChoice,
    ToolDefinition as HttpToolDefinition, ToolInvocation, ToolInvocationContext,
    ToolOutcome as HttpToolOutcome, ToolPort,
};
use claw_memory::{
    ContextAssembler, ExtractiveSummarizer, HeuristicTokenCounter, KeywordRetriever, MemoryRecord,
    RecordId, RecordKind, RetrievalCoverage, RetrievalQuery, Retriever, Role, Session,
    SessionId as MemorySessionId, SummarizationPolicy, TokenBudget, compact,
};
use claw_runtime::approval::SilentApprovalPort;
use claw_runtime::{
    CommandEffect, CommandOutcome, Runtime, RuntimeConfig, RuntimeError, RuntimePorts,
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use super::http_api::{Diagnostics, ModelToolCatalog, OperatorRuntimeStatus, SwappableProvider};
use super::signed_plugins::PluginToolSurface;

fn goal_http_definition() -> HttpToolDefinition {
    HttpToolDefinition {
        name: claw_runtime::GOAL_TOOL_NAME.to_owned(),
        description: Some(
            "Create, update, close, or supersede the durable session goal".to_owned(),
        ),
        input_schema: json!({
            "type":"object",
            "required":["action"],
            "properties":{
                "action":{"type":"string"},
                "objective":{"type":"string"},
                "note":{"type":"string"},
                "status":{"type":"string"}
            }
        }),
    }
}

/// Provider catalogue combining signed plugin tools with the durable goal tool.
pub struct RuntimeModelTools {
    plugins: Arc<PluginToolSurface>,
}

impl RuntimeModelTools {
    /// Creates the shared provider catalogue.
    #[must_use]
    pub fn new(plugins: Arc<PluginToolSurface>) -> Arc<Self> {
        Arc::new(Self { plugins })
    }
}

impl ModelToolCatalog for RuntimeModelTools {
    fn definitions(&self) -> Vec<HttpToolDefinition> {
        let mut tools = ModelToolCatalog::definitions(self.plugins.as_ref());
        tools.push(goal_http_definition());
        tools
    }
}

/// Runtime clock backed by wall time and Tokio timers.
#[derive(Clone, Copy, Debug, Default)]
pub struct RuntimeClock;

impl ClockPort for RuntimeClock {
    fn now(&self) -> Timestamp {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        Timestamp::from_millis(i64::try_from(millis).unwrap_or(i64::MAX))
    }

    fn sleep(&self, duration: Duration) -> RuntimeFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

#[derive(Default)]
struct StateData {
    sessions: HashMap<String, SessionSnapshot>,
    turns: HashMap<(String, u64), TurnRecord>,
}

/// In-process runtime state with optimistic-concurrency enforcement.
#[derive(Default)]
pub struct RuntimeStateStore {
    data: Mutex<StateData>,
}

impl StatePort for RuntimeStateStore {
    fn load_session(
        &self,
        session_id: &SessionId,
    ) -> RuntimeFuture<'_, Result<Option<SessionSnapshot>, RuntimePortError>> {
        let found = self
            .data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sessions
            .get(session_id.as_str())
            .cloned();
        Box::pin(async move { Ok(found) })
    }

    fn save_session(
        &self,
        snapshot: SessionSnapshot,
    ) -> RuntimeFuture<'_, Result<u64, RuntimePortError>> {
        let mut data = self.data.lock().unwrap_or_else(PoisonError::into_inner);
        let key = snapshot.session_id.as_str().to_owned();
        let current = data.sessions.get(&key).map_or(0, |stored| stored.revision);
        if current != snapshot.revision {
            return Box::pin(async move {
                Err(RuntimePortError::Conflict(format!(
                    "session revision changed from {} to {current}",
                    snapshot.revision
                )))
            });
        }
        let revision = current.saturating_add(1);
        data.sessions.insert(
            key,
            SessionSnapshot {
                revision,
                ..snapshot
            },
        );
        drop(data);
        Box::pin(async move { Ok(revision) })
    }

    fn save_turn(&self, record: TurnRecord) -> RuntimeFuture<'_, Result<(), RuntimePortError>> {
        self.data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .turns
            .insert(
                (record.session_id.as_str().to_owned(), record.turn.ordinal()),
                record,
            );
        Box::pin(async { Ok(()) })
    }

    fn load_turn(
        &self,
        session_id: &SessionId,
        turn: TurnId,
    ) -> RuntimeFuture<'_, Result<Option<TurnRecord>, RuntimePortError>> {
        let found = self
            .data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .turns
            .get(&(session_id.as_str().to_owned(), turn.ordinal()))
            .cloned();
        Box::pin(async move { Ok(found) })
    }

    fn list_sessions(&self) -> RuntimeFuture<'_, Result<Vec<SessionSnapshot>, RuntimePortError>> {
        let mut sessions: Vec<_> = self
            .data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sessions
            .values()
            .cloned()
            .collect();
        sessions.sort_by(|left, right| left.session_id.as_str().cmp(right.session_id.as_str()));
        Box::pin(async move { Ok(sessions) })
    }
}

struct MemorySession {
    session: Session,
    budget: TokenBudget,
    latest_query: Option<String>,
    latest_record: Option<RecordId>,
    used_tokens: usize,
    compacted_items: u32,
}

#[derive(Clone, Debug, Default)]
struct MemoryReport {
    inserts_refused: u64,
    examined_records: usize,
    matched_records: usize,
    coverage: Option<RetrievalCoverage>,
    dropped_messages: usize,
    dropped_retrieved: usize,
    unexamined_retrieved: usize,
}

struct MemoryData {
    sessions: BTreeMap<String, MemorySession>,
    retriever: KeywordRetriever,
    report: MemoryReport,
}

/// `claw-memory` implementation of the runtime context-engine SPI.
pub struct MemoryContextEngine {
    data: Mutex<MemoryData>,
    capacity: usize,
    diagnostics: Arc<Diagnostics>,
}

impl MemoryContextEngine {
    /// Creates a bounded keyword-backed context engine.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured index capacity is zero.
    pub fn new(capacity: usize, diagnostics: Arc<Diagnostics>) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            data: Mutex::new(MemoryData {
                sessions: BTreeMap::new(),
                retriever: KeywordRetriever::with_capacity(capacity)
                    .map_err(|error| error.to_string())?,
                report: MemoryReport::default(),
            }),
            capacity,
            diagnostics,
        }))
    }

    /// Machine-readable bounded-work and truncation report.
    #[must_use]
    pub fn report(&self) -> Value {
        let report = self
            .data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .report
            .clone();
        json!({
            "insertRefusals": report.inserts_refused,
            "retrieval": {
                "examined": report.examined_records,
                "matched": report.matched_records,
                "coverage": report.coverage.map(|coverage| match coverage {
                    RetrievalCoverage::Complete => "complete",
                    RetrievalCoverage::Partial => "partial",
                    RetrievalCoverage::Unknown => "unknown",
                }),
            },
            "context": {
                "droppedMessages": report.dropped_messages,
                "droppedRetrieved": report.dropped_retrieved,
                "unexaminedRetrieved": report.unexamined_retrieved,
            },
        })
    }

    fn clear(&self) {
        let mut data = self.data.lock().unwrap_or_else(PoisonError::into_inner);
        data.sessions.clear();
        data.retriever =
            KeywordRetriever::with_capacity(self.capacity).expect("validated memory capacity");
        data.report = MemoryReport::default();
    }

    fn state(entry: &MemorySession) -> ContextState {
        ContextState {
            item_count: u32::try_from(
                entry
                    .session
                    .messages()
                    .len()
                    .saturating_add(entry.session.summaries().len()),
            )
            .unwrap_or(u32::MAX),
            used_tokens: u32::try_from(entry.used_tokens).unwrap_or(u32::MAX),
            token_budget: u32::try_from(entry.budget.available()).unwrap_or(u32::MAX),
            needs_compaction: entry.used_tokens > entry.budget.available().saturating_mul(4) / 5,
            compacted_items: entry.compacted_items,
        }
    }

    fn memory_session_id(session_id: &SessionId) -> Result<MemorySessionId, RuntimePortError> {
        MemorySessionId::new(session_id.as_str())
            .map_err(|error| RuntimePortError::Invalid(error.to_string()))
    }

    fn append(
        data: &mut MemoryData,
        request: ContextIngest,
    ) -> Result<ContextState, RuntimePortError> {
        let memory_id = Self::memory_session_id(&request.session_id)?;
        let (role, content, pinned, tag, latest_query) = match request.item {
            ContextItem::UserInput { text } => {
                (Role::User, text.clone(), false, "user", Some(text))
            }
            ContextItem::AssistantMessage { text } => {
                (Role::Assistant, text, false, "assistant", None)
            }
            ContextItem::ToolResult {
                tool_name,
                output,
                failed,
            } => (
                Role::Tool,
                format!(
                    "{tool_name} {}: {output}",
                    if failed { "failed" } else { "completed" }
                ),
                false,
                "tool",
                None,
            ),
            ContextItem::GoalStatement { objective } => (
                Role::System,
                format!("Current goal: {objective}"),
                true,
                "goal",
                None,
            ),
            ContextItem::SystemNote { text } => (Role::System, text, true, "system", None),
        };
        let at = u64::try_from(request.at.as_millis()).unwrap_or_default();
        let next_ordinal = data
            .sessions
            .get(request.session_id.as_str())
            .ok_or_else(|| RuntimePortError::NotFound("context session is not open".to_owned()))?
            .session
            .messages()
            .last()
            .map_or(Some(0), |message| message.id.get().checked_add(1))
            .ok_or_else(|| {
                RuntimePortError::Unavailable("memory session is exhausted".to_owned())
            })?;
        let record_id = RecordId::new(&format!(
            "mem:{:016x}:{}:{}",
            stable_hash(request.session_id.as_str()),
            request.turn.ordinal(),
            next_ordinal,
        ))
        .map_err(|error| RuntimePortError::Invalid(error.to_string()))?;
        let mut tags = BTreeSet::new();
        tags.insert(tag.to_owned());
        let record = MemoryRecord {
            id: record_id.clone(),
            session: memory_id,
            kind: RecordKind::Message,
            text: content.clone(),
            unix_millis: at,
            tags,
        };
        if let Err(error) = data.retriever.insert(record) {
            data.report.inserts_refused = data.report.inserts_refused.saturating_add(1);
            return Err(match error {
                claw_memory::RetrievalError::RetrieverFull => RuntimePortError::Unavailable(
                    "memory index is full; remove records or raise its bound".to_owned(),
                ),
                other => RuntimePortError::Invalid(other.to_string()),
            });
        }
        let entry = data
            .sessions
            .get_mut(request.session_id.as_str())
            .expect("session checked above");
        let message_id = match entry.session.append(role, content, at) {
            Ok(message_id) => message_id,
            Err(error) => {
                let _ = data.retriever.remove(&record_id);
                return Err(RuntimePortError::Invalid(error.to_string()));
            }
        };
        if message_id.get() != next_ordinal {
            let _ = data.retriever.remove(&record_id);
            return Err(RuntimePortError::Conflict(
                "memory session changed during ingest".to_owned(),
            ));
        }
        if pinned {
            let _ = entry.session.pin(message_id);
        }
        if let Some(query) = latest_query {
            entry.latest_query = Some(query);
            entry.latest_record = Some(record_id);
        }
        Ok(Self::state(entry))
    }
}

impl ContextEnginePort for MemoryContextEngine {
    fn bootstrap(
        &self,
        request: ContextBootstrap,
    ) -> RuntimeFuture<'_, Result<ContextState, RuntimePortError>> {
        Box::pin(async move {
            let mut data = self.data.lock().unwrap_or_else(PoisonError::into_inner);
            let memory_id = Self::memory_session_id(&request.session_id)?;
            let budget = TokenBudget::new(
                usize::try_from(request.token_budget).unwrap_or(usize::MAX),
                0,
            )
            .map_err(|error| RuntimePortError::Invalid(error.to_string()))?;
            let key = request.session_id.as_str().to_owned();
            let entry = data.sessions.entry(key).or_insert_with(|| MemorySession {
                session: Session::new(memory_id),
                budget,
                latest_query: None,
                latest_record: None,
                used_tokens: 0,
                compacted_items: 0,
            });
            if request.reason == BootstrapReason::NewSession {
                entry.budget = budget;
            }
            let state = Self::state(entry);
            drop(data);
            Ok(state)
        })
    }

    fn ingest(
        &self,
        request: ContextIngest,
    ) -> RuntimeFuture<'_, Result<ContextState, RuntimePortError>> {
        Box::pin(async move {
            let mut data = self.data.lock().unwrap_or_else(PoisonError::into_inner);
            let result = Self::append(&mut data, request);
            drop(data);
            if let Err(error) = &result {
                self.diagnostics
                    .record(format!("memory ingest refused: {error}"));
            }
            result
        })
    }

    fn assemble(
        &self,
        request: ContextAssembly,
    ) -> RuntimeFuture<'_, Result<RuntimeContext, RuntimePortError>> {
        Box::pin(async move {
            let mut data = self.data.lock().unwrap_or_else(PoisonError::into_inner);
            let (memory_id, query, latest_record, budget) = {
                let entry = data
                    .sessions
                    .get(request.session_id.as_str())
                    .ok_or_else(|| {
                        RuntimePortError::NotFound("context session is not open".to_owned())
                    })?;
                (
                    entry.session.id().clone(),
                    entry.latest_query.clone(),
                    entry.latest_record.clone(),
                    entry.budget,
                )
            };
            let mut retrieval = if let Some(query) = query.filter(|query| !query.trim().is_empty())
            {
                let query = RetrievalQuery::new(&query, 16)
                    .map_err(|error| RuntimePortError::Invalid(error.to_string()))?
                    .in_session(memory_id);
                Some(
                    data.retriever
                        .retrieve_with_report(&query)
                        .map_err(|error| RuntimePortError::Unavailable(error.to_string()))?,
                )
            } else {
                None
            };
            if let Some(report) = retrieval.as_mut()
                && let Some(latest_record) = latest_record
            {
                report.items.retain(|item| item.record.id != latest_record);
            }
            if let Some(report) = &retrieval {
                data.report.examined_records = report.examined_records;
                data.report.matched_records = report.matched_records;
                data.report.coverage = Some(report.coverage);
            }
            let retrieved = retrieval
                .as_ref()
                .map_or(&[][..], |report| report.items.as_slice());
            let context_assembler =
                ContextAssembler::new(budget, HeuristicTokenCounter::default(), 20)
                    .map_err(|error| RuntimePortError::Invalid(error.to_string()))?;
            let assembled = {
                let entry = data
                    .sessions
                    .get(request.session_id.as_str())
                    .expect("session checked above");
                context_assembler
                    .assemble(&entry.session, retrieved)
                    .map_err(|error| RuntimePortError::Invalid(error.to_string()))?
            };
            let dropped_messages = assembled.dropped_messages;
            let dropped_retrieved = assembled.dropped_retrieved;
            let unexamined_retrieved = assembled.truncation.unexamined_retrieved;
            let mut messages = Vec::new();
            for summary in assembled.summaries {
                messages.push(PromptMessage::System {
                    text: format!("Conversation summary: {}", summary.text),
                });
            }
            for message in assembled.messages {
                messages.push(match message.role {
                    Role::System => PromptMessage::System {
                        text: message.content,
                    },
                    Role::User => PromptMessage::User {
                        text: message.content,
                    },
                    Role::Assistant => PromptMessage::Assistant {
                        text: message.content,
                        tool_calls: Vec::new(),
                    },
                    Role::Tool => PromptMessage::System {
                        text: format!("Tool result: {}", message.content),
                    },
                });
            }
            for item in assembled.retrieved {
                messages.push(PromptMessage::System {
                    text: format!("Relevant memory: {}", item.record.text),
                });
            }
            let state = {
                let entry = data
                    .sessions
                    .get_mut(request.session_id.as_str())
                    .expect("session checked above");
                entry.used_tokens = assembled.used_tokens;
                Self::state(entry)
            };
            data.report.dropped_messages = dropped_messages;
            data.report.dropped_retrieved = dropped_retrieved;
            data.report.unexamined_retrieved = unexamined_retrieved;
            drop(data);
            Ok(RuntimeContext { messages, state })
        })
    }

    fn maintain(
        &self,
        request: ContextMaintenance,
    ) -> RuntimeFuture<'_, Result<ContextState, RuntimePortError>> {
        Box::pin(async move {
            let data = self.data.lock().unwrap_or_else(PoisonError::into_inner);
            let entry = data
                .sessions
                .get(request.session_id.as_str())
                .ok_or_else(|| {
                    RuntimePortError::NotFound("context session is not open".to_owned())
                })?;
            let state = Self::state(entry);
            drop(data);
            Ok(state)
        })
    }

    fn compact(
        &self,
        request: ContextCompaction,
    ) -> RuntimeFuture<'_, Result<CompactionReport, RuntimePortError>> {
        Box::pin(async move {
            let mut data = self.data.lock().unwrap_or_else(PoisonError::into_inner);
            let entry = data
                .sessions
                .get_mut(request.session_id.as_str())
                .ok_or_else(|| {
                    RuntimePortError::NotFound("context session is not open".to_owned())
                })?;
            let before = entry.session.messages().len();
            let mut summarizer = ExtractiveSummarizer::default();
            let _summary = compact(
                &mut entry.session,
                entry.budget,
                &HeuristicTokenCounter::default(),
                SummarizationPolicy::default(),
                &mut summarizer,
                u64::try_from(request.at.as_millis()).unwrap_or_default(),
            )
            .map_err(|error| RuntimePortError::Invalid(error.to_string()))?;
            let removed = before.saturating_sub(entry.session.messages().len());
            entry.compacted_items = entry
                .compacted_items
                .saturating_add(u32::try_from(removed).unwrap_or(u32::MAX));
            let reclaimed_tokens = u32::try_from(removed.saturating_mul(4)).unwrap_or(u32::MAX);
            entry.used_tokens = entry
                .used_tokens
                .saturating_sub(usize::try_from(reclaimed_tokens).unwrap_or(usize::MAX));
            let report = CompactionReport {
                removed_items: u32::try_from(removed).unwrap_or(u32::MAX),
                reclaimed_tokens,
                state: Self::state(entry),
            };
            drop(data);
            Ok(report)
        })
    }
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in value.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

struct BufferedProviderStream {
    chunks: VecDeque<ProviderChunk>,
}

impl RuntimeProviderStream for BufferedProviderStream {
    fn next_chunk(&mut self) -> RuntimeFuture<'_, Result<Option<ProviderChunk>, RuntimePortError>> {
        let next = self.chunks.pop_front();
        Box::pin(async move { Ok(next) })
    }
}

struct RequestCancellation(Option<CancellationToken>);

impl RequestCancellation {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for RequestCancellation {
    fn drop(&mut self) {
        if let Some(token) = self.0.take() {
            token.cancel();
        }
    }
}

struct RuntimeProviderAdapter {
    provider: Arc<SwappableProvider>,
}

impl RuntimeProviderAdapter {
    fn request(
        request: RuntimeProviderRequest,
        published_tools: &BTreeSet<String>,
    ) -> GenerationRequest {
        let mut instructions = Vec::new();
        let mut transcript = Vec::new();
        for message in request.messages {
            match message {
                PromptMessage::System { text } => instructions.push(text),
                PromptMessage::User { text } => transcript.push(text),
                PromptMessage::Assistant { text, .. } => {
                    transcript.push(format!("assistant: {text}"));
                }
                PromptMessage::ToolResult {
                    call_id,
                    output,
                    failed,
                } => transcript.push(format!(
                    "tool {} {}: {output}",
                    call_id,
                    if failed { "failed" } else { "completed" }
                )),
            }
        }
        GenerationRequest {
            model: request.model.unwrap_or_else(|| "openclaw".to_owned()),
            prompt: transcript.join("\n"),
            instructions: (!instructions.is_empty()).then(|| instructions.join("\n")),
            media: Vec::new(),
            tools: request
                .tool_names
                .into_iter()
                .filter(|name| !published_tools.contains(name))
                .map(|name| ClientTool {
                    description: (name == claw_runtime::GOAL_TOOL_NAME).then(|| {
                        "Create, update, close, or supersede the durable session goal".to_owned()
                    }),
                    parameters: Some(if name == claw_runtime::GOAL_TOOL_NAME {
                        json!({
                            "type":"object",
                            "required":["action"],
                            "properties":{
                                "action":{"type":"string"},
                                "objective":{"type":"string"},
                                "note":{"type":"string"},
                                "status":{"type":"string"}
                            }
                        })
                    } else {
                        json!({"type":"object"})
                    }),
                    name,
                })
                .collect(),
            tool_choice: ToolChoice::Auto,
            max_tokens: None,
            max_tool_calls: None,
            temperature: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            stop: None,
            response_format: None,
            request_id: format!("runtime_{}_{}", request.turn.ordinal(), request.round),
            session_id: format!(
                "runtime:{}:{}:{}",
                request.session_id,
                request.turn.ordinal(),
                request.round
            ),
        }
    }
}

impl RuntimeProviderPort for RuntimeProviderAdapter {
    fn start_round(
        &self,
        request: RuntimeProviderRequest,
    ) -> RuntimeFuture<'_, Result<Box<dyn RuntimeProviderStream>, RuntimePortError>> {
        Box::pin(async move {
            let cancellation = CancellationToken::new();
            let mut cancel_on_drop = RequestCancellation(Some(cancellation.clone()));
            let published_tools = self.provider.model_tool_names();
            let output = ToolPortBridge::map_http(
                claw_http_api::ProviderPort::generate(
                    self.provider.as_ref(),
                    Self::request(request, &published_tools),
                    cancellation,
                )
                .await,
            )?;
            cancel_on_drop.disarm();
            let mut chunks = VecDeque::new();
            if !output.text.is_empty() {
                chunks.push_back(ProviderChunk::TextDelta { text: output.text });
            }
            for call in output.tool_calls {
                let call_id = ToolCallId::new(call.id)
                    .map_err(|error| RuntimePortError::Invalid(error.to_string()))?;
                chunks.push_back(ProviderChunk::ToolCallBegin {
                    call_id: call_id.clone(),
                    name: call.name,
                });
                chunks.push_back(ProviderChunk::ToolCallArgumentsDelta {
                    call_id: call_id.clone(),
                    fragment: call.arguments,
                });
                chunks.push_back(ProviderChunk::ToolCallEnd { call_id });
            }
            chunks.push_back(ProviderChunk::MessageEnd);
            Ok(Box::new(BufferedProviderStream { chunks }) as Box<dyn RuntimeProviderStream>)
        })
    }
}

struct ActiveToolGuard<'a> {
    id: String,
    active: &'a Mutex<BTreeMap<String, CancellationToken>>,
}

impl Drop for ActiveToolGuard<'_> {
    fn drop(&mut self) {
        self.active
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.id);
    }
}

struct ToolPortBridge {
    tools: Arc<PluginToolSurface>,
    active: Mutex<BTreeMap<String, CancellationToken>>,
}

impl ToolPortBridge {
    fn map_http<T>(result: Result<T, PortError>) -> Result<T, RuntimePortError> {
        result.map_err(|error| match error.kind {
            PortErrorKind::InvalidRequest => RuntimePortError::Invalid(error.message),
            PortErrorKind::NotFound => RuntimePortError::NotFound(error.message),
            PortErrorKind::Unavailable | PortErrorKind::Timeout => {
                RuntimePortError::Unavailable(error.message)
            }
            PortErrorKind::Internal => RuntimePortError::Unavailable(error.message),
        })
    }
}

impl RuntimeToolPort for ToolPortBridge {
    fn describe(&self) -> Vec<ToolDescriptor> {
        ModelToolCatalog::definitions(self.tools.as_ref())
            .into_iter()
            .map(|tool| ToolDescriptor {
                name: tool.name,
                summary: tool.description.unwrap_or_default(),
                requires_approval: false,
                mutates_workspace: false,
            })
            .collect()
    }

    fn invoke(
        &self,
        invocation: RuntimeToolInvocation,
    ) -> RuntimeFuture<'_, Result<RuntimeToolOutcome, RuntimePortError>> {
        Box::pin(async move {
            let id = invocation.call.call_id.as_str().to_owned();
            let cancellation = CancellationToken::new();
            self.active
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id.clone(), cancellation.clone());
            let _guard = ActiveToolGuard {
                id,
                active: &self.active,
            };
            let arguments = serde_json::from_str(&invocation.call.arguments)
                .map_err(|error| RuntimePortError::Invalid(error.to_string()))?;
            let outcome = Self::map_http(
                ToolPort::invoke(
                    self.tools.as_ref(),
                    ToolInvocation {
                        name: invocation.call.name,
                        arguments,
                        action: None,
                        context: ToolInvocationContext {
                            session_key: Some(invocation.session_id.to_string()),
                            agent_id: None,
                            idempotency_key: Some(invocation.call.call_id.to_string()),
                            message_channel: None,
                            account_id: None,
                            agent_to: None,
                            agent_thread_id: None,
                            sender_is_owner: true,
                            dry_run: false,
                        },
                    },
                    cancellation,
                )
                .await,
            )?;
            let output = serde_json::to_string(&outcome.result.unwrap_or(Value::Null))
                .map_err(|error| RuntimePortError::Invalid(error.to_string()))?;
            Ok(RuntimeToolOutcome {
                call_id: invocation.call.call_id,
                status: if outcome.ok {
                    ToolStatus::Ok
                } else {
                    ToolStatus::Failed
                },
                output,
                changed_workspace: false,
            })
        })
    }

    fn cancel(&self, call_id: &ToolCallId) -> RuntimeFuture<'_, Result<(), RuntimePortError>> {
        let cancellation = self
            .active
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(call_id.as_str())
            .cloned();
        Box::pin(async move {
            if let Some(cancellation) = cancellation {
                cancellation.cancel();
            }
            Ok(())
        })
    }
}

/// HTTP/MCP tool surface combining signed plugins and durable goals.
pub struct AgentHttpTools {
    plugins: Arc<PluginToolSurface>,
    runtime: Arc<Runtime>,
}

impl ToolPort for AgentHttpTools {
    fn list(&self) -> PortFuture<'_, Result<Vec<HttpToolDefinition>, PortError>> {
        Box::pin(async move {
            let mut tools = ToolPort::list(self.plugins.as_ref()).await?;
            tools.push(goal_http_definition());
            Ok(tools)
        })
    }

    fn invoke(
        &self,
        invocation: ToolInvocation,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<HttpToolOutcome, PortError>> {
        if invocation.name != claw_runtime::GOAL_TOOL_NAME {
            return ToolPort::invoke(self.plugins.as_ref(), invocation, cancellation);
        }
        Box::pin(async move {
            let session = invocation.context.session_key.ok_or_else(|| {
                PortError::new(
                    PortErrorKind::InvalidRequest,
                    "update_goal requires a session key",
                )
            })?;
            let session = SessionId::new(session).map_err(|error| {
                PortError::new(PortErrorKind::InvalidRequest, error.to_string())
            })?;
            let arguments = serde_json::to_string(&invocation.arguments).map_err(|error| {
                PortError::new(PortErrorKind::InvalidRequest, error.to_string())
            })?;
            let result = tokio::select! {
                result = claw_goals::invoke_goal_tool(self.runtime.goals(), &session, &arguments) => result,
                () = cancellation.cancelled() => {
                    return Err(PortError::new(PortErrorKind::Unavailable, "request cancelled"));
                }
            };
            Ok(match result {
                Ok(outcome) => HttpToolOutcome {
                    status: 200,
                    ok: true,
                    result: Some(json!({
                        "summary": outcome.summary(),
                        "goalId": outcome.record.goal_id.to_string(),
                        "status": outcome.record.status.to_string(),
                        "revision": outcome.record.revision,
                    })),
                    error_type: None,
                    error_message: None,
                    requires_approval: None,
                },
                Err(error) => HttpToolOutcome {
                    status: 400,
                    ok: false,
                    result: None,
                    error_type: Some("goal_refused".to_owned()),
                    error_message: Some(error.to_string()),
                    requires_approval: None,
                },
            })
        })
    }
}

/// One composed agent runtime shared by HTTP and every channel.
pub struct AgentRuntime {
    runtime: Arc<Runtime>,
    provider: Arc<SwappableProvider>,
    memory: Arc<MemoryContextEngine>,
    goals: Arc<FileGoalStore>,
    model: String,
    skill_count: usize,
    diagnostics: Arc<Diagnostics>,
}

impl AgentRuntime {
    /// Builds the runtime over provider, plugin, memory, state, and durable goals.
    ///
    /// # Errors
    ///
    /// Returns a safe startup error when memory or goal state cannot be opened.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: Arc<SwappableProvider>,
        plugin_tools: Arc<PluginToolSurface>,
        state_dir: &std::path::Path,
        model: String,
        skill_count: usize,
        max_sessions: usize,
        idle_timeout: Duration,
        diagnostics: Arc<Diagnostics>,
    ) -> Result<Arc<Self>, String> {
        let memory = MemoryContextEngine::new(
            max_sessions.saturating_mul(256).max(1),
            Arc::clone(&diagnostics),
        )?;
        let goals = Arc::new(
            FileGoalStore::open(state_dir.join("goals")).map_err(|error| error.to_string())?,
        );
        let state = Arc::new(RuntimeStateStore::default());
        let runtime = Arc::new(Runtime::new(
            RuntimePorts {
                clock: Arc::new(RuntimeClock),
                provider: Arc::new(RuntimeProviderAdapter {
                    provider: Arc::clone(&provider),
                }),
                state,
                tools: Arc::new(ToolPortBridge {
                    tools: plugin_tools,
                    active: Mutex::new(BTreeMap::new()),
                }),
                approvals: Arc::new(SilentApprovalPort),
                goals: Arc::clone(&goals) as Arc<dyn GoalStorePort>,
                context: Arc::clone(&memory) as Arc<dyn ContextEnginePort>,
            },
            RuntimeConfig {
                session_capacity: max_sessions.max(1),
                session_idle_ttl: idle_timeout,
                ..RuntimeConfig::default()
            },
        ));
        diagnostics.record(format!(
            "goal store recovery: {:?}; write_lock_attempts={}",
            goals.recovery(),
            goals.operation_semantics().write_lock_attempts
        ));
        Ok(Arc::new(Self {
            runtime,
            provider,
            memory,
            goals,
            model,
            skill_count,
            diagnostics,
        }))
    }

    /// Returns the shared runtime.
    #[must_use]
    pub fn runtime(&self) -> Arc<Runtime> {
        Arc::clone(&self.runtime)
    }

    /// Returns the combined HTTP/MCP tool surface.
    #[must_use]
    pub fn http_tools(self: &Arc<Self>, plugins: Arc<PluginToolSurface>) -> Arc<AgentHttpTools> {
        Arc::new(AgentHttpTools {
            plugins,
            runtime: Arc::clone(&self.runtime),
        })
    }

    /// Returns a synchronous channel conversation adapter.
    #[must_use]
    pub fn conversation(self: &Arc<Self>) -> RuntimeConversation {
        RuntimeConversation {
            runtime: Arc::clone(self),
        }
    }

    /// Reports whether an activated provider can serve channel conversations.
    #[must_use]
    pub fn authenticated(&self) -> bool {
        self.provider.is_active()
    }

    /// Executes the channel-owned `/status` and `/reset` commands.
    ///
    /// # Errors
    ///
    /// Returns an invalid-request error for unknown commands or session IDs.
    pub async fn channel_command(
        &self,
        conversation_id: &str,
        command: &str,
    ) -> Result<String, PortError> {
        match command {
            "status" => Ok(format!(
                "model={} authenticated={} sessions={} provider_generation={}",
                self.model,
                self.authenticated(),
                self.runtime.managed_session_ids().len(),
                self.provider.provider_generation(),
            )),
            "reset" => {
                let session_id = SessionId::new(conversation_id).map_err(|error| {
                    PortError::new(PortErrorKind::InvalidRequest, error.to_string())
                })?;
                let existed = self.runtime.destroy_session(&session_id).await;
                Ok(if existed {
                    "Conversation reset.".to_owned()
                } else {
                    "Conversation had no retained state.".to_owned()
                })
            }
            _ => Err(PortError::new(
                PortErrorKind::InvalidRequest,
                "unsupported channel command",
            )),
        }
    }

    /// Reload-fences and terminally removes every owned conversation.
    pub async fn reload_sessions(&self) -> claw_runtime::SessionReloadReport {
        let report = self.runtime.reload_sessions().await;
        self.memory.clear();
        report
    }

    /// Stops every runtime turn and approval.
    ///
    /// # Errors
    ///
    /// Returns the runtime's typed shutdown failure after all tasks are joined.
    pub async fn shutdown(&self) -> Result<(), RuntimeError> {
        self.runtime.shutdown().await
    }

    /// Runtime, memory, and goal health for operator status.
    #[must_use]
    pub fn operator_status(&self) -> Value {
        json!({
            "sessions": {
                "managed": self.runtime.managed_session_ids().len(),
                "generation": self.runtime.session_generation(),
                "trackedTurns": self.runtime.tracked_tasks(),
            },
            "memory": self.memory.report(),
            "goals": {
                "acceptedWrites": self.goals.accepted_writes(),
                "syncedPublications": self.goals.synced_publications(),
                "unsyncedPublications": self.goals.unsynced_publications(),
                "unlockFailures": self.goals.unlock_failures(),
                "recovery": format!("{:?}", self.goals.recovery()),
            },
        })
    }

    async fn chat(
        &self,
        conversation_id: &str,
        message: &str,
        cancellation: CancellationToken,
    ) -> Result<String, PortError> {
        let session_id = SessionId::new(conversation_id)
            .map_err(|error| PortError::new(PortErrorKind::InvalidRequest, error.to_string()))?;
        let mut turn = self
            .runtime
            .submit(&session_id, message)
            .await
            .map_err(|error| runtime_http_error(&error))?;
        let mut cancelled = false;
        loop {
            tokio::select! {
                event = turn.next_event() => {
                    let Some(event) = event else {
                        break;
                    };
                    if let claw_runtime::RuntimeEventKind::Failed { reason } = event.kind {
                        self.diagnostics.record(format!(
                            "runtime turn failed session={}: {reason}",
                            event.session_id
                        ));
                    }
                }
                () = cancellation.cancelled(), if !cancelled => {
                    cancelled = true;
                    turn.cancel();
                }
            }
        }
        let outcome = turn
            .join()
            .await
            .map_err(|error| runtime_http_error(&error))?;
        if cancelled {
            return Err(PortError::new(
                PortErrorKind::Unavailable,
                "request cancelled",
            ));
        }
        outcome
            .message
            .map(|message| message.text)
            .or_else(|| outcome.partial.map(|partial| partial.text))
            .ok_or_else(|| PortError::new(PortErrorKind::Internal, "runtime produced no message"))
    }
}

impl LegacyRuntimePort for AgentRuntime {
    fn snapshot(&self) -> Result<LegacyRuntimeSnapshot, PortError> {
        Ok(LegacyRuntimeSnapshot {
            skill_count: self.skill_count,
            active_model: self.model.clone(),
            session_count: self.runtime.managed_session_ids().len(),
            authenticated: self.provider.is_active(),
        })
    }

    fn chat(
        &self,
        conversation_id: String,
        message: String,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<String, PortError>> {
        Box::pin(async move {
            if !self.provider.is_active() {
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "provider is not authenticated",
                ));
            }
            self.chat(&conversation_id, &message, cancellation).await
        })
    }
}

impl OperatorRuntimeStatus for AgentRuntime {
    fn status(&self) -> Value {
        self.operator_status()
    }

    fn dispatch<'a>(
        &'a self,
        method: &'a str,
        params: Option<&'a Value>,
        cancellation: CancellationToken,
    ) -> PortFuture<'a, Result<Option<Value>, PortError>> {
        Box::pin(async move {
            let admin_session = SessionId::new("daemon-admin")
                .map_err(|error| PortError::new(PortErrorKind::Internal, error.to_string()))?;
            let effect = match method {
                "commands.list" => {
                    return Ok(Some(json!({
                        "commands": self
                            .runtime
                            .commands()
                            .specs()
                            .iter()
                            .filter(|command| command.advertised)
                            .map(|command| json!({
                                "name": command.name,
                                "aliases": command.aliases,
                                "summary": command.summary,
                                "scope": command.scope.label(),
                            }))
                            .collect::<Vec<_>>()
                    })));
                }
                "doctor.memory.status" => {
                    return Ok(Some(self.memory.report()));
                }
                "gateway.suspend.status" => CommandEffect::SuspendStatus,
                "gateway.suspend.prepare" => CommandEffect::SuspendPrepare {
                    drain_seconds: params
                        .and_then(|value| value.get("drainSeconds"))
                        .and_then(Value::as_u64)
                        .unwrap_or(30),
                },
                "gateway.suspend.resume" => {
                    let lease_id = params
                        .and_then(|value| value.get("leaseId"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            PortError::new(
                                PortErrorKind::InvalidRequest,
                                "gateway.suspend.resume requires params.leaseId",
                            )
                        })?;
                    CommandEffect::SuspendResume {
                        lease_id: lease_id.to_owned(),
                    }
                }
                _ => return Ok(None),
            };
            let outcome = tokio::select! {
                outcome = self.runtime.execute_effect(&admin_session, effect) => {
                    outcome.map_err(|error| runtime_http_error(&error))?
                }
                () = cancellation.cancelled() => {
                    return Err(PortError::new(
                        PortErrorKind::Unavailable,
                        "request cancelled",
                    ));
                }
            };
            Ok(Some(command_outcome_json(outcome)))
        })
    }
}

impl LegacyChannelMessagePort for AgentRuntime {
    fn process(
        &self,
        message: LegacyChannelMessage,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<String, PortError>> {
        Box::pin(async move {
            self.chat(&message.conversation_id, &message.text, cancellation)
                .await
        })
    }
}

/// Synchronous channel dispatch over the shared asynchronous runtime.
pub struct RuntimeConversation {
    runtime: Arc<AgentRuntime>,
}

impl ConversationService for RuntimeConversation {
    type Error = PortError;

    fn chat(&mut self, conversation_id: &str, text: &str) -> Result<String, Self::Error> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.runtime.chat(
                conversation_id,
                text,
                CancellationToken::new(),
            ))
        })
    }
}

fn runtime_http_error(error: &RuntimeError) -> PortError {
    let kind = match error.failure_class() {
        claw_runtime::RuntimeFailureClass::NotFound => PortErrorKind::NotFound,
        claw_runtime::RuntimeFailureClass::InvalidRequest => PortErrorKind::InvalidRequest,
        claw_runtime::RuntimeFailureClass::Busy
        | claw_runtime::RuntimeFailureClass::Unavailable
        | claw_runtime::RuntimeFailureClass::Cancelled => PortErrorKind::Unavailable,
        claw_runtime::RuntimeFailureClass::Internal => PortErrorKind::Internal,
    };
    PortError::new(kind, format!("{} ({})", error.user_message(), error))
}

fn command_outcome_json(outcome: CommandOutcome) -> Value {
    match outcome {
        CommandOutcome::Suspension(status) => json!({"status":format!("{status:?}")}),
        CommandOutcome::SuspensionPrepared(outcome) => {
            json!({"outcome":format!("{outcome:?}")})
        }
        other => json!({"outcome":format!("{other:?}")}),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use claw_application::model::ids::TurnId;
    use claw_application::model::session::SessionState;
    use claw_application::model::time::Timestamp;
    use claw_application::ports::context::{
        BootstrapReason, ContextAssembly, ContextBootstrap, ContextEnginePort, ContextIngest,
        ContextItem,
    };
    use claw_application::ports::state::{SessionSnapshot, StatePort};
    use claw_domain::SessionId;

    use super::{MemoryContextEngine, RuntimeStateStore};

    #[tokio::test]
    async fn runtime_state_rejects_stale_revisions() {
        let state = Arc::new(RuntimeStateStore::default());
        let session_id = SessionId::new("state-test").expect("session id");
        let snapshot = SessionSnapshot {
            session_id,
            turn: TurnId::FIRST,
            state: SessionState::Draft,
            pre_pause_state: None,
            updated_at: Timestamp::from_millis(1),
            revision: 0,
        };
        assert_eq!(state.save_session(snapshot.clone()).await, Ok(1));
        assert!(state.save_session(snapshot).await.is_err());
    }

    #[tokio::test]
    async fn memory_capacity_refusal_is_reported_without_eviction() {
        let diagnostics = Arc::new(crate::adapters::http_api::Diagnostics::new(8));
        let memory = MemoryContextEngine::new(1, diagnostics).expect("memory engine");
        let session_id = SessionId::new("memory-test").expect("session id");
        memory
            .bootstrap(ContextBootstrap {
                session_id: session_id.clone(),
                reason: BootstrapReason::NewSession,
                token_budget: 128,
                at: Timestamp::from_millis(1),
            })
            .await
            .expect("bootstrap");
        memory
            .ingest(ContextIngest {
                session_id: session_id.clone(),
                turn: TurnId::FIRST,
                item: ContextItem::UserInput {
                    text: "first retained memory".to_owned(),
                },
                at: Timestamp::from_millis(2),
            })
            .await
            .expect("first record");
        let refused = memory
            .ingest(ContextIngest {
                session_id,
                turn: TurnId::FIRST,
                item: ContextItem::AssistantMessage {
                    text: "second record exceeds the explicit index bound".to_owned(),
                },
                at: Timestamp::from_millis(3),
            })
            .await;
        assert!(matches!(
            refused,
            Err(claw_application::ports::PortError::Unavailable(_))
        ));
        assert_eq!(memory.report()["insertRefusals"], 1);
        let assembled = memory
            .assemble(ContextAssembly {
                session_id: SessionId::new("memory-test").expect("session id"),
                turn: TurnId::FIRST,
                round: 0,
            })
            .await
            .expect("context remains usable");
        assert_eq!(assembled.messages.len(), 1);
    }
}

//! Bounded asynchronous state-port adapter and strict on-disk DTOs.

use std::path::Path;
use std::sync::{Arc, Mutex};

use claw_application::model::ids::{ToolCallId, TurnId};
use claw_application::model::message::{
    AssistantMessage, PartialAssistantMessage, PendingToolCall, ToolCall,
};
use claw_application::model::session::SessionState;
use claw_application::model::time::Timestamp;
use claw_application::ports::provider::{
    ProviderResponseFinish, ProviderResponseReport, ProviderRoundRecord, UsageReporting,
};
use claw_application::ports::state::{
    ProviderRoundJournal, SessionSnapshot, StatePort, TurnRecord,
};
use claw_application::ports::{PortError, PortFuture};
use claw_domain::SessionId;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;

use crate::{Mutation, Record, StateDatabase, StateError};

const MAX_SESSIONS: usize = 4096;
const MAX_REVOKED_TOOL_PUBLICATIONS: usize = 256;
const TOOL_REVOCATION_PREFIX: &str = "tool-publication-revoked/v1/";

fn provider_journal_key(session: &SessionId, turn: TurnId) -> String {
    format!("provider-rounds/v1/{}", turn_key(session, turn))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RevokedToolPublication {
    schema_version: u32,
    publication: String,
}

fn tool_revocation_key(publication: &str) -> Result<String, StateError> {
    if publication.len() != 64
        || !publication
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StateError::InvalidRecord);
    }
    Ok(format!("{TOOL_REVOCATION_PREFIX}{publication}"))
}

fn validate_tool_revocation(record: &Record, publication: &str) -> Result<(), StateError> {
    let revoked: RevokedToolPublication = record.decode()?;
    if revoked.schema_version != 1 || revoked.publication != publication {
        return Err(StateError::InvalidRecord);
    }
    Ok(())
}

/// A durable state port with bounded, tracked blocking work.
pub struct DurableStateStore {
    database: Arc<StateDatabase>,
    accepting: Mutex<bool>,
    permits: Arc<Semaphore>,
    tasks: TaskTracker,
}

impl DurableStateStore {
    /// Opens validated state in an existing private directory.
    ///
    /// # Errors
    ///
    /// Rejects unavailable or incompatible databases without falling back to memory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StateError> {
        let database = Arc::new(StateDatabase::open(path)?);
        crate::runs::recover_interrupted(&database)?;
        crate::runs::recover_deliveries(&database)?;
        Ok(Self {
            database,
            accepting: Mutex::new(true),
            permits: Arc::new(Semaphore::new(32)),
            tasks: TaskTracker::new(),
        })
    }

    pub(crate) fn operation<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&StateDatabase) -> Result<T, PortError> + Send + 'static,
    ) -> PortFuture<'_, Result<T, PortError>> {
        Box::pin(async move {
            let task = {
                let accepting = self.accepting.lock().map_err(|_| unavailable())?;
                if !*accepting {
                    return Err(unavailable());
                }
                let permit = Arc::clone(&self.permits)
                    .try_acquire_owned()
                    .map_err(|_| unavailable())?;
                let database = Arc::clone(&self.database);
                let task = self.tasks.spawn_blocking(move || {
                    let _permit = permit;
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        operation(&database)
                    }))
                    .unwrap_or_else(|_| {
                        Err(PortError::OutcomeUnknown(
                            "state worker failed; inspect the original operation before retry"
                                .to_owned(),
                        ))
                    });
                    if matches!(&result, Err(PortError::OutcomeUnknown(_))) {
                        database.require_recovery();
                    }
                    result
                });
                drop(accepting);
                task
            };
            task.await.map_err(|_| {
                self.database.require_recovery();
                PortError::OutcomeUnknown(
                    "state task failed; commit outcome must be checked before retry".to_owned(),
                )
            })?
        })
    }

    /// Stops admission and waits for already issued storage operations to actually finish.
    pub async fn shutdown(&self) {
        {
            let mut accepting = self
                .accepting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *accepting = false;
            self.tasks.close();
            drop(accepting);
        }
        self.tasks.wait().await;
    }

    /// Reports a sticky storage uncertainty; reads remain available until shutdown.
    #[must_use]
    pub fn recovery_required(&self) -> bool {
        self.database.recovery_required()
    }

    /// Reads an immutable revocation for an exact reviewed tool publication digest.
    ///
    /// # Errors
    /// Rejects malformed digests, corrupt bindings and unavailable storage.
    pub async fn tool_publication_revoked(&self, publication: &str) -> Result<bool, PortError> {
        let key = tool_revocation_key(publication).map_err(port_error)?;
        let publication = publication.to_owned();
        self.operation(move |database| {
            let Some(record) = database.get(&key).map_err(port_error)? else {
                return Ok(false);
            };
            validate_tool_revocation(&record, &publication).map_err(port_error)?;
            Ok(true)
        })
        .await
    }

    /// Permanently revokes a reviewed publication without removing any execution history.
    ///
    /// # Errors
    /// Refuses invalid records, exhausted persistent capacity and uncertain writes.
    pub async fn revoke_tool_publication(&self, publication: &str) -> Result<(), PortError> {
        let key = tool_revocation_key(publication).map_err(port_error)?;
        let publication = publication.to_owned();
        self.operation(move |database| {
            for _attempt in 0..2 {
                if let Some(record) = database.get(&key).map_err(port_error)? {
                    return validate_tool_revocation(&record, &publication).map_err(port_error);
                }
                let revoked = RevokedToolPublication {
                    schema_version: 1,
                    publication: publication.clone(),
                };
                let mutation = Mutation::put(key.clone(), &revoked)
                    .map_err(port_error)?
                    .if_absent();
                match database.insert_with_prefix_limit(
                    mutation,
                    TOOL_REVOCATION_PREFIX,
                    MAX_REVOKED_TOOL_PUBLICATIONS,
                    || true,
                ) {
                    Ok(()) => return Ok(()),
                    Err(StateError::Conflict) => {}
                    Err(error) => return Err(port_error(error)),
                }
            }
            Err(PortError::Conflict(
                "tool publication revocation changed concurrently".to_owned(),
            ))
        })
        .await
    }

    /// Removes the current session pointer while preserving its historical turn records.
    ///
    /// # Errors
    ///
    /// Reports admission, storage and concurrent-update failures.
    pub async fn remove_session(&self, session: &SessionId) -> Result<bool, PortError> {
        let key = session_key(session);
        let context_key = context_key(session);
        self.operation(move |database| {
            let previous = database.get(&key).map_err(port_error)?;
            let context = database.get(&context_key).map_err(port_error)?;
            let mut changes = Vec::new();
            if let Some(previous) = previous {
                changes.push(
                    Mutation::delete(key)
                        .map_err(port_error)?
                        .if_unchanged(&previous),
                );
            }
            if let Some(previous) = context {
                changes.push(
                    Mutation::delete(context_key)
                        .map_err(port_error)?
                        .if_unchanged(&previous),
                );
            }
            if changes.is_empty() {
                return Ok(false);
            }
            database.commit(changes).map_err(port_error)?;
            Ok(true)
        })
        .await
    }

    /// Loads a bounded, typed context checkpoint without interpreting its policy.
    ///
    /// # Errors
    ///
    /// Reports admission, storage or checkpoint-schema failures.
    pub async fn load_context<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        session: &SessionId,
    ) -> Result<Option<T>, PortError> {
        let key = context_key(session);
        self.operation(move |database| {
            database
                .get(&key)
                .map_err(port_error)?
                .map(|record| record.decode().map_err(port_error))
                .transpose()
        })
        .await
    }

    /// Publishes a bounded checkpoint on the owned storage worker.
    ///
    /// The context owner must serialize its mutations and reset operations.
    ///
    /// # Errors
    ///
    /// Reports admission, size, encoding or commit failures.
    pub async fn save_context<T: Serialize + Send + 'static>(
        &self,
        session: &SessionId,
        checkpoint: T,
    ) -> Result<(), PortError> {
        let key = context_key(session);
        self.operation(move |database| {
            database
                .commit(vec![Mutation::put(key, &checkpoint).map_err(port_error)?])
                .map_err(port_error)
        })
        .await
    }
}

fn unavailable() -> PortError {
    PortError::Unavailable(
        "state store is closed or its bounded operation capacity is exhausted".to_owned(),
    )
}

pub(crate) fn port_error(error: StateError) -> PortError {
    match error {
        StateError::Conflict => PortError::Conflict("state changed since it was read".to_owned()),
        StateError::InvalidRecord | StateError::Schema => PortError::Invalid(error.to_string()),
        StateError::Storage(detail) => PortError::Unavailable(format!(
            "state storage failed: {detail}; do not infer that an interrupted commit can be replayed"
        )),
        StateError::CommitUnknown(detail) => PortError::OutcomeUnknown(format!(
            "state commit must be reconciled before retry: {detail}"
        )),
    }
}

fn session_key(session: &SessionId) -> String {
    format!("session/{}", serde_json::json!(session.as_str()))
}

fn context_key(session: &SessionId) -> String {
    format!("context/{}", serde_json::json!(session.as_str()))
}

fn turn_key(session: &SessionId, turn: TurnId) -> String {
    format!(
        "turn/{}/{:020}",
        serde_json::json!(session.as_str()),
        turn.ordinal()
    )
}

impl StatePort for DurableStateStore {
    fn next_turn(&self, session: &SessionId) -> PortFuture<'_, Result<TurnId, PortError>> {
        let key = format!("turn-high-water/{}", serde_json::json!(session.as_str()));
        self.operation(move |database| {
            let Some(record) = database.get(&key).map_err(port_error)? else {
                return Ok(TurnId::FIRST);
            };
            let previous: u64 = record.decode().map_err(port_error)?;
            previous
                .checked_add(1)
                .map(TurnId::new)
                .ok_or_else(|| PortError::Conflict("session turn identity exhausted".to_owned()))
        })
    }

    fn load_session(
        &self,
        session: &SessionId,
    ) -> PortFuture<'_, Result<Option<SessionSnapshot>, PortError>> {
        let key = session_key(session);
        self.operation(move |database| {
            database
                .get(&key)
                .map_err(port_error)?
                .map(|record| {
                    let document: SessionDocument = record.decode().map_err(port_error)?;
                    let snapshot = document.into_snapshot()?;
                    if session_key(&snapshot.session_id) != key {
                        return Err(PortError::Invalid(
                            "stored session identity does not match its key".to_owned(),
                        ));
                    }
                    Ok(snapshot)
                })
                .transpose()
        })
    }

    fn save_session(
        &self,
        mut snapshot: SessionSnapshot,
    ) -> PortFuture<'_, Result<u64, PortError>> {
        self.operation(move |database| {
            let key = session_key(&snapshot.session_id);
            let high_water_key = format!(
                "turn-high-water/{}",
                serde_json::json!(snapshot.session_id.as_str())
            );
            let high_water_record = database.get(&high_water_key).map_err(port_error)?;
            let high_water = high_water_record
                .as_ref()
                .map(Record::decode::<u64>)
                .transpose()
                .map_err(port_error)?;
            let previous = database.get(&key).map_err(port_error)?;
            let current = previous
                .as_ref()
                .map(Record::decode::<SessionDocument>)
                .transpose()
                .map_err(port_error)?
                .map(SessionDocument::into_snapshot)
                .transpose()?;
            if current
                .as_ref()
                .is_some_and(|stored| session_key(&stored.session_id) != key)
            {
                return Err(PortError::Invalid(
                    "stored session identity does not match its key".to_owned(),
                ));
            }
            let revision = current.map_or(0, |stored| stored.revision);
            if revision != snapshot.revision {
                return Err(PortError::Conflict("session revision changed".to_owned()));
            }
            if high_water.is_some_and(|previous_turn| {
                snapshot.turn.ordinal() < previous_turn
                    || (previous.is_none() && snapshot.turn.ordinal() == previous_turn)
            }) {
                return Err(PortError::Conflict(
                    "session turn identity was already consumed".to_owned(),
                ));
            }
            snapshot.revision = revision
                .checked_add(1)
                .ok_or_else(|| PortError::Conflict("session revision exhausted".to_owned()))?;
            let revision = snapshot.revision;
            let high_water_change =
                Mutation::put(high_water_key, &snapshot.turn.ordinal()).map_err(port_error)?;
            let high_water_change = match high_water_record.as_ref() {
                Some(previous) => high_water_change.if_unchanged(previous),
                None => high_water_change.if_absent(),
            };
            let change =
                Mutation::put(key, &SessionDocument::from(snapshot)).map_err(port_error)?;
            let change = match previous.as_ref() {
                Some(previous) => change.if_unchanged(previous),
                None => change.if_absent(),
            };
            database
                .commit(vec![change, high_water_change])
                .map_err(port_error)?;
            Ok(revision)
        })
    }

    fn save_provider_journal(
        &self,
        mut journal: ProviderRoundJournal,
    ) -> PortFuture<'_, Result<u64, PortError>> {
        self.operation(move |database| {
            let key = provider_journal_key(&journal.session_id, journal.turn);
            if database
                .get(&turn_key(&journal.session_id, journal.turn))
                .map_err(port_error)?
                .is_some()
            {
                return Err(PortError::Conflict(
                    "provider work for this turn is already closed".to_owned(),
                ));
            }
            let previous = database.get(&key).map_err(port_error)?;
            let decoded = previous
                .as_ref()
                .map(|record| {
                    let document: ProviderJournalDocument = record.decode().map_err(port_error)?;
                    document.into_journal(&key)
                })
                .transpose()?;
            journal.validate_update(decoded.as_ref())?;
            journal.revision = journal.revision.checked_add(1).ok_or_else(|| {
                PortError::Invalid("provider journal revision exhausted".to_owned())
            })?;
            let revision = journal.revision;
            let change =
                Mutation::put(key, &ProviderJournalDocument::from(journal)).map_err(port_error)?;
            let change = match previous.as_ref() {
                Some(previous) => change.if_unchanged(previous),
                None => change.if_absent(),
            };
            database.commit(vec![change]).map_err(port_error)?;
            Ok(revision)
        })
    }

    fn load_provider_journal(
        &self,
        session_id: &SessionId,
        turn: TurnId,
    ) -> PortFuture<'_, Result<Option<ProviderRoundJournal>, PortError>> {
        let key = provider_journal_key(session_id, turn);
        self.operation(move |database| {
            database
                .get(&key)
                .map_err(port_error)?
                .map(|record| {
                    let document: ProviderJournalDocument = record.decode().map_err(port_error)?;
                    document.into_journal(&key)
                })
                .transpose()
        })
    }

    fn save_turn(&self, record: TurnRecord) -> PortFuture<'_, Result<(), PortError>> {
        self.operation(move |database| {
            ProviderRoundRecord::validate_sequence(&record.provider_rounds)?;
            let key = turn_key(&record.session_id, record.turn);
            if let Some(previous) = database.get(&key).map_err(port_error)? {
                let document: TurnDocument = previous.decode().map_err(port_error)?;
                if document.into_record()? == record {
                    return Ok(());
                }
                return Err(PortError::Conflict(
                    "a different result already owns this turn identity".to_owned(),
                ));
            }
            let journal_key = provider_journal_key(&record.session_id, record.turn);
            let previous_journal = database.get(&journal_key).map_err(port_error)?;
            let revision = if let Some(previous) = &previous_journal {
                let document: ProviderJournalDocument = previous.decode().map_err(port_error)?;
                let journal = document.into_journal(&journal_key)?;
                if journal.closed || journal.rounds != record.provider_rounds {
                    return Err(PortError::Conflict(
                        "terminal provider reports differ from the durable journal".to_owned(),
                    ));
                }
                journal.revision.checked_add(1).ok_or_else(|| {
                    PortError::Invalid("provider journal revision exhausted".to_owned())
                })?
            } else {
                1
            };
            let closed = ProviderRoundJournal {
                session_id: record.session_id.clone(),
                turn: record.turn,
                rounds: record.provider_rounds.clone(),
                revision,
                closed: true,
                updated_at: record.updated_at,
            };
            let seal = Mutation::put(journal_key, &ProviderJournalDocument::from(closed))
                .map_err(port_error)?;
            let seal = match previous_journal.as_ref() {
                Some(previous) => seal.if_unchanged(previous),
                None => seal.if_absent(),
            };
            let document = TurnDocument::from(record);
            let change = Mutation::put(key, &document)
                .map_err(port_error)?
                .if_absent();
            database.commit(vec![change, seal]).map_err(port_error)
        })
    }

    fn load_turn(
        &self,
        session: &SessionId,
        turn: TurnId,
    ) -> PortFuture<'_, Result<Option<TurnRecord>, PortError>> {
        let key = turn_key(session, turn);
        self.operation(move |database| {
            database
                .get(&key)
                .map_err(port_error)?
                .map(|record| {
                    let document: TurnDocument = record.decode().map_err(port_error)?;
                    let record = document.into_record()?;
                    if turn_key(&record.session_id, record.turn) != key {
                        return Err(PortError::Invalid(
                            "stored turn identity does not match its key".to_owned(),
                        ));
                    }
                    Ok(record)
                })
                .transpose()
        })
    }

    fn list_sessions(&self) -> PortFuture<'_, Result<Vec<SessionSnapshot>, PortError>> {
        self.operation(|database| {
            let mut snapshots = Vec::new();
            let mut cursor = None;
            loop {
                let page = database
                    .page("session/", cursor.as_deref(), 256)
                    .map_err(port_error)?;
                for (key, record) in page.records {
                    if snapshots.len() == MAX_SESSIONS {
                        return Err(PortError::Unavailable(
                            "session listing exceeds the supported bound".to_owned(),
                        ));
                    }
                    let document: SessionDocument = record.decode().map_err(port_error)?;
                    let snapshot = document.into_snapshot()?;
                    if session_key(&snapshot.session_id) != key {
                        return Err(PortError::Invalid("stored session key mismatch".to_owned()));
                    }
                    snapshots.push(snapshot);
                }
                cursor = page.next_cursor;
                if cursor.is_none() {
                    break;
                }
            }
            snapshots
                .sort_by(|left, right| left.session_id.as_str().cmp(right.session_id.as_str()));
            Ok(snapshots)
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionDocument {
    session_id: String,
    turn: u64,
    state: String,
    pre_pause_state: Option<String>,
    updated_at: i64,
    revision: u64,
}

impl From<SessionSnapshot> for SessionDocument {
    fn from(snapshot: SessionSnapshot) -> Self {
        Self {
            session_id: snapshot.session_id.to_string(),
            turn: snapshot.turn.ordinal(),
            state: snapshot.state.label().to_owned(),
            pre_pause_state: snapshot
                .pre_pause_state
                .map(|state| state.label().to_owned()),
            updated_at: snapshot.updated_at.as_millis(),
            revision: snapshot.revision,
        }
    }
}

impl SessionDocument {
    fn into_snapshot(self) -> Result<SessionSnapshot, PortError> {
        Ok(SessionSnapshot {
            session_id: SessionId::new(self.session_id)
                .map_err(|error| PortError::Invalid(error.to_string()))?,
            turn: TurnId::new(self.turn),
            state: parse_state(&self.state)?,
            pre_pause_state: self
                .pre_pause_state
                .as_deref()
                .map(parse_state)
                .transpose()?,
            updated_at: Timestamp::from_millis(self.updated_at),
            revision: self.revision,
        })
    }
}

fn parse_state(value: &str) -> Result<SessionState, PortError> {
    SessionState::ALL
        .into_iter()
        .find(|state| state.label() == value)
        .ok_or_else(|| PortError::Invalid("stored session state is unknown".to_owned()))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallDocument {
    id: String,
    name: String,
    arguments: String,
}

impl From<ToolCall> for CallDocument {
    fn from(call: ToolCall) -> Self {
        Self {
            id: call.call_id.to_string(),
            name: call.name,
            arguments: call.arguments,
        }
    }
}

impl CallDocument {
    fn into_call(self) -> Result<ToolCall, PortError> {
        Ok(ToolCall {
            call_id: ToolCallId::new(self.id)
                .map_err(|error| PortError::Invalid(error.to_string()))?,
            name: self.name,
            arguments: self.arguments,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageDocument {
    text: String,
    reasoning: String,
    calls: Vec<CallDocument>,
}

impl From<AssistantMessage> for MessageDocument {
    fn from(message: AssistantMessage) -> Self {
        Self {
            text: message.text,
            reasoning: message.reasoning,
            calls: message
                .tool_calls
                .into_iter()
                .map(CallDocument::from)
                .collect(),
        }
    }
}

impl MessageDocument {
    fn into_message(self) -> Result<AssistantMessage, PortError> {
        Ok(AssistantMessage {
            text: self.text,
            reasoning: self.reasoning,
            tool_calls: self
                .calls
                .into_iter()
                .map(CallDocument::into_call)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialDocument {
    message: MessageDocument,
    pending: Vec<CallDocument>,
    next_sequence: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseReportDocument {
    provider: String,
    model: String,
    response_id: Option<String>,
    usage_reporting: String,
    input_tokens: u64,
    output_tokens: u64,
    cached_input_tokens: u64,
    reasoning_tokens: u64,
    finish_reason: String,
}

impl From<ProviderResponseReport> for ResponseReportDocument {
    fn from(report: ProviderResponseReport) -> Self {
        Self {
            provider: report.provider,
            model: report.model,
            response_id: report.response_id,
            usage_reporting: report.usage_reporting.label().to_owned(),
            input_tokens: report.input_tokens,
            output_tokens: report.output_tokens,
            cached_input_tokens: report.cached_input_tokens,
            reasoning_tokens: report.reasoning_tokens,
            finish_reason: report.finish_reason.label().to_owned(),
        }
    }
}

impl ResponseReportDocument {
    fn into_report(self) -> Result<ProviderResponseReport, PortError> {
        let invalid =
            || PortError::Invalid("stored provider response accounting is invalid".to_owned());
        let report = ProviderResponseReport {
            provider: self.provider,
            model: self.model,
            response_id: self.response_id,
            usage_reporting: match self.usage_reporting.as_str() {
                "unreported" => UsageReporting::Unreported,
                "partial" => UsageReporting::Partial,
                "complete" => UsageReporting::Complete,
                _ => return Err(invalid()),
            },
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cached_input_tokens: self.cached_input_tokens,
            reasoning_tokens: self.reasoning_tokens,
            finish_reason: match self.finish_reason.as_str() {
                "stop" => ProviderResponseFinish::Stop,
                "tool_calls" => ProviderResponseFinish::ToolCalls,
                "length" => ProviderResponseFinish::Length,
                "content_filter" => ProviderResponseFinish::ContentFilter,
                _ => return Err(invalid()),
            },
        };
        report.validate()?;
        Ok(report)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderRoundDocument {
    round: u32,
    response: Option<ResponseReportDocument>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderJournalDocument {
    session_id: String,
    turn: u64,
    rounds: Vec<ProviderRoundDocument>,
    revision: u64,
    closed: bool,
    updated_at: i64,
}

impl From<ProviderRoundJournal> for ProviderJournalDocument {
    fn from(journal: ProviderRoundJournal) -> Self {
        Self {
            session_id: journal.session_id.to_string(),
            turn: journal.turn.ordinal(),
            rounds: journal
                .rounds
                .into_iter()
                .map(|record| ProviderRoundDocument {
                    round: record.round,
                    response: record.response.map(ResponseReportDocument::from),
                })
                .collect(),
            revision: journal.revision,
            closed: journal.closed,
            updated_at: journal.updated_at.as_millis(),
        }
    }
}

impl ProviderJournalDocument {
    fn into_journal(self, key: &str) -> Result<ProviderRoundJournal, PortError> {
        if self.rounds.len() > claw_application::ports::provider::MAX_PROVIDER_ROUND_RECORDS
            || self.revision == 0
            || (!self.closed && self.rounds.is_empty())
        {
            return Err(PortError::Invalid(
                "stored provider journal is invalid".to_owned(),
            ));
        }
        let journal = ProviderRoundJournal {
            session_id: SessionId::new(self.session_id)
                .map_err(|error| PortError::Invalid(error.to_string()))?,
            turn: TurnId::new(self.turn),
            rounds: self
                .rounds
                .into_iter()
                .map(|record| {
                    Ok(ProviderRoundRecord {
                        round: record.round,
                        response: record
                            .response
                            .map(ResponseReportDocument::into_report)
                            .transpose()?,
                    })
                })
                .collect::<Result<Vec<_>, PortError>>()?,
            revision: self.revision,
            closed: self.closed,
            updated_at: Timestamp::from_millis(self.updated_at),
        };
        ProviderRoundRecord::validate_sequence(&journal.rounds)?;
        if provider_journal_key(&journal.session_id, journal.turn) != key {
            return Err(PortError::Invalid(
                "stored provider journal identity does not match its key".to_owned(),
            ));
        }
        Ok(journal)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TurnDocument {
    session_id: String,
    turn: u64,
    state: String,
    message: Option<MessageDocument>,
    partial: Option<PartialDocument>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    provider_rounds: Vec<ProviderRoundDocument>,
    updated_at: i64,
}

impl From<TurnRecord> for TurnDocument {
    fn from(record: TurnRecord) -> Self {
        Self {
            session_id: record.session_id.to_string(),
            turn: record.turn.ordinal(),
            state: record.state.label().to_owned(),
            message: record.message.map(MessageDocument::from),
            partial: record.partial.map(|partial| PartialDocument {
                message: MessageDocument {
                    text: partial.text,
                    reasoning: partial.reasoning,
                    calls: partial
                        .tool_calls
                        .into_iter()
                        .map(CallDocument::from)
                        .collect(),
                },
                pending: partial
                    .pending_tool_calls
                    .into_iter()
                    .map(|call| CallDocument {
                        id: call.call_id.to_string(),
                        name: call.name,
                        arguments: call.partial_arguments,
                    })
                    .collect(),
                next_sequence: partial.next_sequence,
            }),
            provider_rounds: record
                .provider_rounds
                .into_iter()
                .map(|record| ProviderRoundDocument {
                    round: record.round,
                    response: record.response.map(ResponseReportDocument::from),
                })
                .collect(),
            updated_at: record.updated_at.as_millis(),
        }
    }
}

impl TurnDocument {
    fn into_record(self) -> Result<TurnRecord, PortError> {
        if self.provider_rounds.len()
            > claw_application::ports::provider::MAX_PROVIDER_ROUND_RECORDS
        {
            return Err(PortError::Invalid(
                "stored provider accounting round limit exceeded".to_owned(),
            ));
        }
        let provider_rounds = self
            .provider_rounds
            .into_iter()
            .map(|record| {
                Ok(ProviderRoundRecord {
                    round: record.round,
                    response: record
                        .response
                        .map(ResponseReportDocument::into_report)
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>, PortError>>()?;
        ProviderRoundRecord::validate_sequence(&provider_rounds)?;
        let partial = self
            .partial
            .map(|partial| {
                let message = partial.message.into_message()?;
                let pending_tool_calls = partial
                    .pending
                    .into_iter()
                    .map(|call| {
                        let call = call.into_call()?;
                        Ok(PendingToolCall {
                            call_id: call.call_id,
                            name: call.name,
                            partial_arguments: call.arguments,
                        })
                    })
                    .collect::<Result<_, PortError>>()?;
                Ok::<_, PortError>(PartialAssistantMessage {
                    text: message.text,
                    reasoning: message.reasoning,
                    tool_calls: message.tool_calls,
                    pending_tool_calls,
                    next_sequence: partial.next_sequence,
                })
            })
            .transpose()?;
        Ok(TurnRecord {
            session_id: SessionId::new(self.session_id)
                .map_err(|error| PortError::Invalid(error.to_string()))?,
            turn: TurnId::new(self.turn),
            state: parse_state(&self.state)?,
            message: self
                .message
                .map(MessageDocument::into_message)
                .transpose()?,
            partial,
            provider_rounds,
            updated_at: Timestamp::from_millis(self.updated_at),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn provider_journal_terminal_seal_competes_atomically_with_the_first_response() {
        let fixture = crate::tests::Fixture::new();
        let store = DurableStateStore::open(fixture.path()).expect("store");
        let session = SessionId::new("journal-terminal-race").expect("session");
        let mut journal = ProviderRoundJournal {
            session_id: session.clone(),
            turn: TurnId::FIRST,
            rounds: vec![ProviderRoundRecord {
                round: 0,
                response: None,
            }],
            revision: 0,
            closed: false,
            updated_at: Timestamp::from_millis(1),
        };
        journal.revision = store
            .save_provider_journal(journal.clone())
            .await
            .expect("intent");
        let terminal = TurnRecord {
            session_id: session.clone(),
            turn: TurnId::FIRST,
            state: SessionState::Cancelled,
            message: None,
            partial: None,
            provider_rounds: journal.rounds.clone(),
            updated_at: Timestamp::from_millis(2),
        };
        journal.rounds[0].response = Some(ProviderResponseReport {
            provider: "owned".to_owned(),
            model: "owned".to_owned(),
            response_id: None,
            usage_reporting: UsageReporting::Complete,
            input_tokens: 0,
            output_tokens: 0,
            cached_input_tokens: 0,
            reasoning_tokens: 0,
            finish_reason: ProviderResponseFinish::Stop,
        });
        let (sealed, reported) = tokio::join!(
            store.save_turn(terminal),
            store.save_provider_journal(journal.clone())
        );
        assert!(matches!(
            (&sealed, &reported),
            (Ok(()), Err(PortError::Conflict(_))) | (Err(PortError::Conflict(_)), Ok(2))
        ));
        let loaded = store
            .load_provider_journal(&session, TurnId::FIRST)
            .await
            .expect("journal")
            .expect("record");
        assert_eq!(loaded.closed, sealed.is_ok());
        if let Some(turn) = store
            .load_turn(&session, TurnId::FIRST)
            .await
            .expect("turn lookup")
        {
            assert_eq!(turn.provider_rounds, loaded.rounds);
        } else {
            assert_eq!(loaded.rounds, journal.rounds);
        }
        store.shutdown().await;
    }

    #[tokio::test]
    async fn provider_journal_is_cas_append_only_reopens_and_seals_with_the_terminal_turn() {
        let fixture = crate::tests::Fixture::new();
        let store = DurableStateStore::open(fixture.path()).expect("store");
        let session = SessionId::new("journal-owner").expect("session");
        let mut journal = ProviderRoundJournal {
            session_id: session.clone(),
            turn: TurnId::FIRST,
            rounds: vec![ProviderRoundRecord {
                round: 0,
                response: None,
            }],
            revision: 0,
            closed: false,
            updated_at: Timestamp::from_millis(1),
        };
        let (first, competing) = tokio::join!(
            store.save_provider_journal(journal.clone()),
            store.save_provider_journal(journal.clone())
        );
        assert!(matches!(
            (&first, &competing),
            (Ok(1), Err(PortError::Conflict(_))) | (Err(PortError::Conflict(_)), Ok(1))
        ));
        assert!(matches!(
            store.save_provider_journal(journal.clone()).await,
            Err(PortError::Conflict(_))
        ));
        journal.revision = 1;
        assert!(matches!(
            store.save_provider_journal(journal.clone()).await,
            Err(PortError::Conflict(_))
        ));
        journal.rounds[0].response = Some(ProviderResponseReport {
            provider: "owned-provider".to_owned(),
            model: "owned-model".to_owned(),
            response_id: Some("owned-response".to_owned()),
            usage_reporting: UsageReporting::Complete,
            input_tokens: 0,
            output_tokens: 0,
            cached_input_tokens: 0,
            reasoning_tokens: 0,
            finish_reason: ProviderResponseFinish::Stop,
        });
        journal.revision = store
            .save_provider_journal(journal.clone())
            .await
            .expect("first response");
        let mut changed = journal.clone();
        changed.rounds[0]
            .response
            .as_mut()
            .expect("response")
            .input_tokens = 1;
        assert!(matches!(
            store.save_provider_journal(changed).await,
            Err(PortError::Conflict(_))
        ));
        journal.rounds.push(ProviderRoundRecord {
            round: 1,
            response: None,
        });
        journal.revision = store
            .save_provider_journal(journal.clone())
            .await
            .expect("second intent");
        assert_eq!(journal.revision, 3);
        store.shutdown().await;
        drop(store);
        let store = DurableStateStore::open(fixture.path()).expect("reopen");
        assert_eq!(
            store
                .load_provider_journal(&session, TurnId::FIRST)
                .await
                .expect("journal"),
            Some(journal.clone())
        );
        assert!(
            store
                .load_turn(&session, TurnId::FIRST)
                .await
                .expect("no fabricated turn")
                .is_none()
        );
        let terminal = TurnRecord {
            session_id: session.clone(),
            turn: TurnId::FIRST,
            state: SessionState::Failed,
            message: None,
            partial: None,
            provider_rounds: journal.rounds.clone(),
            updated_at: Timestamp::from_millis(3),
        };
        let mut inconsistent = terminal.clone();
        inconsistent.provider_rounds.pop();
        assert!(matches!(
            store.save_turn(inconsistent).await,
            Err(PortError::Conflict(_))
        ));
        store
            .save_turn(terminal.clone())
            .await
            .expect("atomic terminal and seal");
        store
            .save_turn(terminal)
            .await
            .expect("immutable identical terminal is idempotent");
        let mut sealed = store
            .load_provider_journal(&session, TurnId::FIRST)
            .await
            .expect("journal")
            .expect("sealed");
        assert!(sealed.closed);
        assert_eq!(sealed.revision, 4);
        sealed.closed = false;
        sealed.rounds.push(ProviderRoundRecord {
            round: 2,
            response: None,
        });
        assert!(matches!(
            store.save_provider_journal(sealed).await,
            Err(PortError::Conflict(_))
        ));
        store.shutdown().await;
    }

    #[test]
    fn provider_round_documents_keep_legacy_unknown_and_reject_invalid_metadata() {
        let old = serde_json::json!({"session_id":"owned","turn":0,"state":"failed","message":null,"partial":null,"updated_at":1});
        let record = serde_json::from_value::<TurnDocument>(old.clone())
            .expect("legacy schema")
            .into_record()
            .expect("legacy record");
        assert!(record.provider_rounds.is_empty());
        let mut current = old;
        current["provider_rounds"] = serde_json::json!([{"round":0,"response":{
            "provider":"owned-provider","model":"actual-model","response_id":"owned-response","usage_reporting":"complete",
            "input_tokens":0,"output_tokens":0,"cached_input_tokens":0,"reasoning_tokens":0,"finish_reason":"length"
        }},{"round":1,"response":null}]);
        let record = serde_json::from_value::<TurnDocument>(current.clone())
            .expect("current schema")
            .into_record()
            .expect("current record");
        assert_eq!(
            record.provider_rounds[0]
                .response
                .as_ref()
                .expect("reported zero")
                .usage_reporting,
            UsageReporting::Complete
        );
        assert!(record.provider_rounds[1].response.is_none());
        for (pointer, value) in [
            ("/provider_rounds/1/round", serde_json::json!(0)),
            (
                "/provider_rounds/0/response/usage_reporting",
                serde_json::json!("free"),
            ),
            (
                "/provider_rounds/0/response/cached_input_tokens",
                serde_json::json!(1),
            ),
            (
                "/provider_rounds/0/response/finish_reason",
                serde_json::json!("billed"),
            ),
            (
                "/provider_rounds/0/response/provider",
                serde_json::json!("invalid identity"),
            ),
        ] {
            let mut changed = current.clone();
            *changed.pointer_mut(pointer).expect("field") = value;
            assert!(
                serde_json::from_value::<TurnDocument>(changed)
                    .expect("syntactic document")
                    .into_record()
                    .is_err()
            );
        }
        current["provider_rounds"][0]["response"]["input_tokens"] = serde_json::json!(1);
        current["provider_rounds"][0]["response"]["usage_reporting"] =
            serde_json::json!("unreported");
        assert!(
            serde_json::from_value::<TurnDocument>(current)
                .expect("syntactic document")
                .into_record()
                .is_err()
        );
        let excessive: Vec<_> = (0..=claw_application::ports::provider::MAX_PROVIDER_ROUND_RECORDS)
            .map(|round| ProviderRoundRecord {
                round: u32::try_from(round).expect("small bound"),
                response: None,
            })
            .collect();
        assert!(ProviderRoundRecord::validate_sequence(&excessive).is_err());
    }

    #[tokio::test]
    async fn tool_publication_revocations_are_immutable_bounded_and_survive_restart() {
        let fixture = crate::tests::Fixture::new();
        let store = DurableStateStore::open(fixture.path()).expect("state");
        let publication = format!("{:064x}", 1);
        assert!(
            !store
                .tool_publication_revoked(&publication)
                .await
                .expect("unknown publication")
        );
        let (first, duplicate) = tokio::join!(
            store.revoke_tool_publication(&publication),
            store.revoke_tool_publication(&publication)
        );
        first.expect("first revocation");
        duplicate.expect("duplicate revocation");
        for index in 2..=MAX_REVOKED_TOOL_PUBLICATIONS {
            store
                .revoke_tool_publication(&format!("{index:064x}"))
                .await
                .expect("within persistent quota");
        }
        let beyond = format!("{:064x}", MAX_REVOKED_TOOL_PUBLICATIONS + 1);
        assert!(store.revoke_tool_publication(&beyond).await.is_err());
        assert!(
            !store
                .tool_publication_revoked(&beyond)
                .await
                .expect("no partial insert")
        );
        store
            .revoke_tool_publication(&publication)
            .await
            .expect("idempotent write at capacity");
        for invalid in ["short", &"A".repeat(64), &"g".repeat(64)] {
            assert!(store.tool_publication_revoked(invalid).await.is_err());
            assert!(store.revoke_tool_publication(invalid).await.is_err());
        }
        store.shutdown().await;
        drop(store);
        let reopened = DurableStateStore::open(fixture.path()).expect("reopened state");
        assert!(
            reopened
                .tool_publication_revoked(&publication)
                .await
                .expect("retained revocation")
        );
        assert!(
            !reopened
                .tool_publication_revoked(&beyond)
                .await
                .expect("different publication")
        );
        reopened.shutdown().await;
        assert!(
            reopened
                .tool_publication_revoked(&publication)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn unknown_commit_and_lost_worker_result_are_never_retryable() {
        let mapped = port_error(StateError::CommitUnknown(
            "injected commit uncertainty".to_owned(),
        ));
        assert!(matches!(mapped, PortError::OutcomeUnknown(_)));
        assert!(!mapped.is_retryable());
        assert!(port_error(StateError::Storage("before commit".to_owned())).is_retryable());

        let fixture = crate::tests::Fixture::new();
        let store = DurableStateStore::open(fixture.path()).expect("store");
        let session = SessionId::new("commit-result-lost").expect("session");
        let key = context_key(&session);
        let result = store
            .operation(move |database| -> Result<(), PortError> {
                database
                    .commit(vec![
                        Mutation::put(key, &serde_json::json!({"committed":true}))
                            .map_err(port_error)?,
                    ])
                    .map_err(port_error)?;
                panic!("injected result loss after an actual committed mutation");
            })
            .await;
        let error = result.expect_err("worker result is unknown");
        assert!(matches!(error, PortError::OutcomeUnknown(_)));
        assert!(!error.is_retryable());
        assert_eq!(
            store
                .load_context::<serde_json::Value>(&session)
                .await
                .expect("read original committed state"),
            Some(serde_json::json!({"committed":true}))
        );
        assert!(store.recovery_required());
        assert!(matches!(
            store
                .save_context(&session, serde_json::json!({"overwritten":true}))
                .await,
            Err(PortError::OutcomeUnknown(_))
        ));
        assert_eq!(
            store
                .load_context::<serde_json::Value>(&session)
                .await
                .expect("fenced writes preserve readback"),
            Some(serde_json::json!({"committed":true}))
        );
        store.shutdown().await;
        assert!(store.recovery_required());
        drop(store);
        let reopened = DurableStateStore::open(fixture.path()).expect("explicit reopen");
        assert!(!reopened.recovery_required());
        assert_eq!(
            reopened
                .load_context::<serde_json::Value>(&session)
                .await
                .expect("reconcile original operation"),
            Some(serde_json::json!({"committed":true}))
        );
        reopened.shutdown().await;
    }

    #[tokio::test]
    async fn dropped_waiter_cannot_hide_storage_worker_failure_or_clear_write_fence() {
        let fixture = crate::tests::Fixture::new();
        let store = Arc::new(DurableStateStore::open(fixture.path()).expect("store"));
        let session = SessionId::new("lost-state-waiter").expect("session");
        let key = context_key(&session);
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let running = Arc::clone(&store);
        let task = tokio::spawn(async move {
            running
                .operation(move |database| -> Result<(), PortError> {
                    database
                        .commit(vec![Mutation::put(key, &true).map_err(port_error)?])
                        .map_err(port_error)?;
                    started.send(()).expect("observer still waiting");
                    released
                        .recv_timeout(std::time::Duration::from_secs(3))
                        .expect("owned fixture release");
                    panic!("injected failure after caller stopped observing");
                })
                .await
        });
        ready.await.expect("write committed");
        task.abort();
        assert!(
            task.await
                .expect_err("only observer task cancelled")
                .is_cancelled()
        );
        release.send(()).expect("release owned state worker");
        store.shutdown().await;
        assert!(store.recovery_required());
        assert!(
            store
                .database
                .get(&context_key(&session))
                .expect("original record")
                .expect("retained value")
                .decode::<bool>()
                .expect("typed value")
        );
    }

    #[tokio::test]
    async fn runtime_state_roundtrips_snapshots_and_partial_turns_across_reopen() {
        let fixture = crate::tests::Fixture::new();
        let store = DurableStateStore::open(fixture.path()).expect("store");
        let session_id = SessionId::new("state/session\"name").expect("session");
        let mut snapshot = SessionSnapshot {
            session_id: session_id.clone(),
            turn: TurnId::FIRST,
            state: SessionState::Running,
            pre_pause_state: None,
            updated_at: Timestamp::from_millis(10),
            revision: 0,
        };
        snapshot.revision = store
            .save_session(snapshot.clone())
            .await
            .expect("first revision");
        assert_eq!(snapshot.revision, 1);
        snapshot.state = SessionState::Failed;
        snapshot.revision = store
            .save_session(snapshot.clone())
            .await
            .expect("second revision");
        assert_eq!(snapshot.revision, 2);
        let record = TurnRecord {
            provider_rounds: vec![
                ProviderRoundRecord {
                    round: 0,
                    response: Some(ProviderResponseReport {
                        provider: "owned-provider".to_owned(),
                        model: "actual-model".to_owned(),
                        response_id: Some("owned-zero".to_owned()),
                        usage_reporting: UsageReporting::Complete,
                        input_tokens: 0,
                        output_tokens: 0,
                        cached_input_tokens: 0,
                        reasoning_tokens: 0,
                        finish_reason: ProviderResponseFinish::Stop,
                    }),
                },
                ProviderRoundRecord {
                    round: 1,
                    response: Some(ProviderResponseReport {
                        provider: "owned-provider".to_owned(),
                        model: "actual-model".to_owned(),
                        response_id: Some("owned-partial".to_owned()),
                        usage_reporting: UsageReporting::Partial,
                        input_tokens: 4,
                        output_tokens: 0,
                        cached_input_tokens: 1,
                        reasoning_tokens: 0,
                        finish_reason: ProviderResponseFinish::Length,
                    }),
                },
                ProviderRoundRecord {
                    round: 2,
                    response: None,
                },
            ],
            session_id: session_id.clone(),
            turn: TurnId::FIRST,
            state: SessionState::Failed,
            message: None,
            partial: Some(PartialAssistantMessage {
                text: "partial result".to_owned(),
                pending_tool_calls: vec![PendingToolCall {
                    call_id: ToolCallId::new("call-one").expect("call"),
                    name: "write_file".to_owned(),
                    partial_arguments: "{\"path\":".to_owned(),
                }],
                ..PartialAssistantMessage::default()
            }),
            updated_at: Timestamp::from_millis(20),
        };
        store.save_turn(record.clone()).await.expect("save turn");
        let mut invalid = record.clone();
        invalid.turn = TurnId::new(1);
        invalid.provider_rounds[0].round = 1;
        assert!(matches!(
            store.save_turn(invalid).await,
            Err(PortError::Invalid(_))
        ));
        assert!(
            store
                .load_turn(&session_id, TurnId::new(1))
                .await
                .expect("no invalid write")
                .is_none()
        );
        store
            .save_context(
                &session_id,
                serde_json::json!({"messages": ["retained input"]}),
            )
            .await
            .expect("checkpoint");
        store
            .save_turn(record.clone())
            .await
            .expect("idempotent same record");
        let mut conflicting = record.clone();
        conflicting.updated_at = Timestamp::from_millis(21);
        assert!(matches!(
            store.save_turn(conflicting).await,
            Err(PortError::Conflict(_))
        ));
        store.shutdown().await;
        assert!(store.load_session(&session_id).await.is_err());
        drop(store);
        let reopened = DurableStateStore::open(fixture.path()).expect("reopen");
        assert_eq!(
            reopened.load_session(&session_id).await.expect("snapshot"),
            Some(snapshot)
        );
        assert_eq!(
            reopened
                .load_context::<serde_json::Value>(&session_id)
                .await
                .expect("checkpoint")
                .expect("retained")["messages"][0],
            "retained input"
        );
        assert_eq!(
            reopened
                .load_turn(&session_id, TurnId::FIRST)
                .await
                .expect("turn"),
            Some(record)
        );
        assert_eq!(reopened.list_sessions().await.expect("list").len(), 1);
        assert!(
            reopened
                .remove_session(&session_id)
                .await
                .expect("remove pointer")
        );
        assert!(
            reopened
                .load_session(&session_id)
                .await
                .expect("snapshot absent")
                .is_none()
        );
        assert!(
            reopened
                .load_context::<serde_json::Value>(&session_id)
                .await
                .expect("checkpoint removed")
                .is_none()
        );
        assert!(
            reopened
                .load_turn(&session_id, TurnId::FIRST)
                .await
                .expect("history retained")
                .is_some()
        );
        assert_eq!(
            reopened
                .next_turn(&session_id)
                .await
                .expect("unused turn")
                .ordinal(),
            1
        );
        let reset = SessionSnapshot {
            session_id: session_id.clone(),
            turn: TurnId::FIRST,
            state: SessionState::Draft,
            pre_pause_state: None,
            updated_at: Timestamp::EPOCH,
            revision: 0,
        };
        assert!(matches!(
            reopened.save_session(reset.clone()).await,
            Err(PortError::Conflict(_))
        ));
        assert_eq!(
            reopened
                .save_session(SessionSnapshot {
                    turn: TurnId::new(1),
                    ..reset
                })
                .await,
            Ok(1)
        );
        reopened.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_state_rejects_stale_snapshot_revisions() {
        let fixture = crate::tests::Fixture::new();
        let store = DurableStateStore::open(fixture.path()).expect("store");
        let snapshot = SessionSnapshot {
            session_id: SessionId::new("revision").expect("session"),
            turn: TurnId::FIRST,
            state: SessionState::Draft,
            pre_pause_state: None,
            updated_at: Timestamp::EPOCH,
            revision: 0,
        };
        assert_eq!(store.save_session(snapshot.clone()).await, Ok(1));
        assert!(matches!(
            store.save_session(snapshot).await,
            Err(PortError::Conflict(_))
        ));
        store.shutdown().await;
    }
}

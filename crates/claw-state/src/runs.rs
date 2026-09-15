//! Durable ingress, once-only execution claims and acknowledged result delivery.

use claw_application::model::ids::TurnId;
use claw_application::model::time::Timestamp;
use claw_application::ports::PortError;
use claw_domain::SessionId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtime::port_error;
use crate::{DurableStateStore, Mutation, Record, StateDatabase, StateError};

const MAX_RETAINED_RUNS: u64 = 16_384;
const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;
const COUNT_KEY: &str = "run-metadata/retained-count";

/// Bounded Discord session metadata; the host must revalidate its origin before connecting.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DiscordResume {
    session_id: String,
    sequence: i64,
    resume_gateway_url: Option<String>,
}

impl std::fmt::Debug for DiscordResume {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiscordResume")
            .field("sequence", &self.sequence)
            .field("session", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl DiscordResume {
    /// Builds bounded metadata without granting trust to the stored session or URL.
    ///
    /// # Errors
    /// Rejects blank/control-containing session IDs, negative sequences and oversized URLs.
    pub fn new(
        session_id: &str,
        sequence: i64,
        resume_gateway_url: Option<&str>,
    ) -> Result<Self, StateError> {
        let resume = Self {
            session_id: session_id.to_owned(),
            sequence,
            resume_gateway_url: resume_gateway_url.map(str::to_owned),
        };
        resume.validate()?;
        Ok(resume)
    }

    fn validate(&self) -> Result<(), StateError> {
        if self.session_id.trim().is_empty()
            || self.session_id.len() > 256
            || self.session_id.trim() != self.session_id
            || self.session_id.chars().any(char::is_control)
            || self.sequence < 0
            || self.resume_gateway_url.as_ref().is_some_and(|url| {
                url.len() > 2_048
                    || !url.starts_with("wss://")
                    || url
                        .chars()
                        .any(|character| character.is_control() || character.is_whitespace())
            })
        {
            return Err(StateError::InvalidRecord);
        }
        Ok(())
    }

    /// Returns the retained session identifier, which is not an authorization grant.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the last host-settled dispatch sequence.
    #[must_use]
    pub const fn sequence(&self) -> i64 {
        self.sequence
    }

    /// Returns the saved address for current host-policy revalidation.
    #[must_use]
    pub fn resume_gateway_url(&self) -> Option<&str> {
        self.resume_gateway_url.as_deref()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StoredDiscordResume {
    schema_version: u64,
    binding: String,
    revision: u64,
    saved_at_ms: i64,
    resume: Option<DiscordResume>,
}

fn discord_resume_key(binding: &str) -> Result<String, StateError> {
    telegram_cursor_key(binding)?;
    Ok(format!("discord-resume/v1/{binding}"))
}

fn read_discord_resume(
    database: &StateDatabase,
    binding: &str,
) -> Result<(Option<Record>, StoredDiscordResume), StateError> {
    let previous = database.get(&discord_resume_key(binding)?)?;
    let stored = if let Some(record) = &previous {
        let stored: StoredDiscordResume = record.decode()?;
        if stored.schema_version != 1
            || stored.binding != binding
            || stored.revision == 0
            || stored.saved_at_ms < 0
        {
            return Err(StateError::InvalidRecord);
        }
        if let Some(resume) = &stored.resume {
            resume.validate()?;
        }
        stored
    } else {
        StoredDiscordResume {
            schema_version: 1,
            binding: binding.to_owned(),
            revision: 0,
            saved_at_ms: 0,
            resume: None,
        }
    };
    Ok((previous, stored))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TelegramPollCursor {
    schema_version: u64,
    binding: String,
    offset: i64,
    advanced_at_ms: i64,
}

fn telegram_cursor_key(binding: &str) -> Result<String, StateError> {
    if binding.len() != 64
        || !binding
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StateError::InvalidRecord);
    }
    Ok(format!("telegram-poll/v1/{binding}"))
}

fn read_telegram_cursor(
    database: &StateDatabase,
    binding: &str,
) -> Result<(Option<Record>, TelegramPollCursor), StateError> {
    let previous = database.get(&telegram_cursor_key(binding)?)?;
    let cursor = if let Some(record) = &previous {
        let cursor: TelegramPollCursor = record.decode()?;
        if cursor.schema_version != 1
            || cursor.binding != binding
            || cursor.offset < 0
            || cursor.advanced_at_ms < 0
        {
            return Err(StateError::InvalidRecord);
        }
        cursor
    } else {
        TelegramPollCursor {
            schema_version: 1,
            binding: binding.to_owned(),
            offset: 0,
            advanced_at_ms: 0,
        }
    };
    Ok((previous, cursor))
}

/// Authenticated ingress identity and exact input, never a replayable permission grant.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunSubmission {
    source: String,
    principal: String,
    idempotency_key: String,
    session_id: String,
    input: String,
}

impl RunSubmission {
    /// Builds a bounded ingress identity supplied by the authenticated host.
    ///
    /// # Errors
    /// Rejects invalid identity components and empty or oversized messages.
    pub fn new(
        source: &str,
        principal: &str,
        key: &str,
        session: &SessionId,
        input: &str,
    ) -> Result<Self, StateError> {
        let value = Self {
            source: source.to_owned(),
            principal: principal.to_owned(),
            idempotency_key: key.to_owned(),
            session_id: session.to_string(),
            input: input.to_owned(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), StateError> {
        for component in [
            &self.source,
            &self.principal,
            &self.idempotency_key,
            &self.session_id,
        ] {
            if component.is_empty()
                || component.len() > 128
                || component.chars().any(char::is_control)
            {
                return Err(StateError::InvalidRecord);
            }
        }
        if SessionId::new(&self.session_id).is_err()
            || self.input.trim().is_empty()
            || self.input.len() > MAX_INPUT_BYTES
        {
            return Err(StateError::InvalidRecord);
        }
        Ok(())
    }

    fn run_id(&self) -> Result<String, StateError> {
        identity_digest(&(&self.source, &self.principal, &self.idempotency_key))
    }
}

fn identity_digest(value: &impl Serialize) -> Result<String, StateError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let identity = serde_json::to_vec(value).map_err(|_| StateError::InvalidRecord)?;
    Ok(Sha256::digest(identity)
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
        .map(char::from)
        .collect())
}

fn result_prefix(source: &str, principal: &str) -> Result<String, StateError> {
    if [source, principal]
        .into_iter()
        .any(|value| value.is_empty() || value.len() > 128 || value.chars().any(char::is_control))
    {
        return Err(StateError::InvalidRecord);
    }
    Ok(format!(
        "run-outbox/{}/",
        identity_digest(&(source, principal))?
    ))
}

fn result_key(run: &DurableRun) -> Result<String, StateError> {
    Ok(format!(
        "{}{}",
        result_prefix(&run.submission.source, &run.submission.principal)?,
        run.id()
    ))
}

fn inbox_prefix(source: &str, principal: &str) -> Result<String, StateError> {
    Ok(format!(
        "run-inbox/{}/",
        identity_digest(&(source, principal))?
    ))
}

fn inbox_key(run: &DurableRun) -> Result<String, StateError> {
    Ok(format!(
        "{}{}",
        inbox_prefix(&run.submission.source, &run.submission.principal)?,
        run.id()
    ))
}

fn session_owner_key(session: &str) -> Result<String, StateError> {
    Ok(format!("run-session-owner/{}", identity_digest(&session)?))
}

fn read_session_owner(
    database: &StateDatabase,
    session: &str,
) -> Result<Option<(Record, String)>, StateError> {
    let Some(record) = database.get(&session_owner_key(session)?)? else {
        return Ok(None);
    };
    let owner: String = record.decode()?;
    if owner.len() != 64
        || !owner
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StateError::InvalidRecord);
    }
    Ok(Some((record, owner)))
}

/// Recovery-safe execution phase for one durable ingress item.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunPhase {
    /// Accepted on disk; execution has not been claimed.
    Queued,
    /// Claimed on disk; the host may have started external work.
    Executing,
    /// The terminal result was atomically published with an outbox record.
    Finished,
    /// Execution or commit was interrupted and may have produced external effects.
    OutcomeUnknown,
}

impl RunPhase {
    /// Stable native phase label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Executing => "executing",
            Self::Finished => "finished",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }
}

/// A bounded terminal answer, separate from whether a client acknowledged it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunResult {
    status: String,
    text: String,
}

impl RunResult {
    /// Captures a terminal status and complete bounded answer.
    ///
    /// # Errors
    /// Refuses unknown status labels or output exceeding the storage bound; never truncates.
    pub fn new(status: &str, text: String) -> Result<Self, StateError> {
        let result = Self {
            status: status.to_owned(),
            text,
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<(), StateError> {
        if !matches!(
            self.status.as_str(),
            "completed" | "completed_with_changes" | "cancelled" | "failed" | "outcome_unknown"
        ) || self.text.len() > MAX_RESULT_BYTES
        {
            return Err(StateError::InvalidRecord);
        }
        Ok(())
    }

    /// Terminal execution status, not transport delivery status.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }

    /// The retained, untruncated terminal answer.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// A durable run whose request can be replayed only as a lookup, not another execution.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DurableRun {
    schema: u32,
    run_id: String,
    submission: RunSubmission,
    phase: RunPhase,
    #[serde(default)]
    cancel_requested: bool,
    turn: Option<u64>,
    result: Option<RunResult>,
    revision: u64,
    accepted_at_ms: i64,
    updated_at_ms: i64,
}

impl DurableRun {
    fn validate(&self, id: &str) -> Result<(), StateError> {
        self.submission.validate()?;
        if self.schema != 1
            || self.run_id != id
            || self.submission.run_id()? != id
            || self.revision == 0
            || matches!(self.phase, RunPhase::Queued)
                && (self.turn.is_some() || self.result.is_some())
            || matches!(self.phase, RunPhase::Executing) && self.result.is_some()
            || matches!(self.phase, RunPhase::Finished | RunPhase::OutcomeUnknown)
                && self.result.is_none()
        {
            return Err(StateError::InvalidRecord);
        }
        if let Some(result) = &self.result {
            result.validate()?;
        }
        Ok(())
    }

    /// Stable identifier bound to source, authenticated principal and idempotency key.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.run_id
    }

    /// Owning session identity.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.submission.session_id
    }

    /// Execution phase persisted before any external execution starts.
    #[must_use]
    pub const fn phase(&self) -> RunPhase {
        self.phase
    }

    /// Whether cancellation was durably requested before this execution settled.
    #[must_use]
    pub const fn cancellation_requested(&self) -> bool {
        self.cancel_requested
    }

    /// Complete input retained for an explicitly reauthorized queued retry.
    #[must_use]
    pub fn input(&self) -> &str {
        &self.submission.input
    }

    /// Runtime turn identity, absent when execution could not be bound.
    #[must_use]
    pub const fn turn(&self) -> Option<u64> {
        self.turn
    }

    /// Persisted terminal result, including outcome-unknown recovery.
    #[must_use]
    pub const fn result(&self) -> Option<&RunResult> {
        self.result.as_ref()
    }

    /// Revision used to acknowledge exactly the observed terminal result.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// The result of durable admission; duplicates retain the original execution identity.
pub struct RunAdmission {
    /// Durable run after this operation committed or read the original record.
    pub run: DurableRun,
    /// Whether the exact scoped input had already been accepted.
    pub replayed: bool,
}

/// A bounded page of runs within an authenticated ingress partition.
pub struct RunResultPage {
    /// At most 32 matching runs; the query determines active versus unacknowledged terminal state.
    pub runs: Vec<DurableRun>,
    /// Exclusive pagination cursor, not a chronological incremental-delivery cursor.
    pub next_cursor: Option<String>,
}

/// Durable transport status for one complete reply, separate from model execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryPhase {
    /// Claimed before the first network send; never eligible for automatic replay.
    Sending,
    /// Every segment was acknowledged by its transport and the local receipt committed.
    Delivered,
    /// Sending or acknowledgement was interrupted; reconcile before any explicit resend.
    OutcomeUnknown,
}

/// Bound delivery claim for an immutable terminal run result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunDelivery {
    schema: u32,
    run_id: String,
    result_revision: u64,
    content_digest: String,
    phase: DeliveryPhase,
}

impl RunDelivery {
    /// Stable durable run identity whose reply was claimed.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Last committed transport status; a sending record is not permission to retry.
    #[must_use]
    pub const fn phase(&self) -> DeliveryPhase {
        self.phase
    }

    fn validate(&self) -> Result<(), StateError> {
        run_key(&self.run_id)?;
        if self.schema != 1
            || self.result_revision == 0
            || self.content_digest.len() != 64
            || !self
                .content_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StateError::InvalidRecord);
        }
        Ok(())
    }
}

fn delivery_key(run_id: &str) -> Result<String, StateError> {
    run_key(run_id)?;
    Ok(format!("run-delivery/{run_id}"))
}

/// Immutable evidence of one acknowledged native reply segment, without its content.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunDeliveryReceipt {
    schema_version: u64,
    run_id: String,
    result_revision: u64,
    segment: u32,
    content_bytes: usize,
    content_sha256: String,
    remote_message_id: String,
}

impl std::fmt::Debug for RunDeliveryReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunDeliveryReceipt")
            .field("segment", &self.segment)
            .field("content_bytes", &self.content_bytes)
            .finish_non_exhaustive()
    }
}

impl RunDeliveryReceipt {
    fn validate(&self) -> Result<(), StateError> {
        run_key(&self.run_id)?;
        if self.schema_version != 1
            || self.result_revision == 0
            || self.segment >= 1_024
            || self.content_bytes == 0
            || self.content_bytes > 16 * 1024
            || self.content_sha256.len() != 64
            || !self
                .content_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !valid_remote_receipt_id(&self.remote_message_id)
        {
            return Err(StateError::InvalidRecord);
        }
        Ok(())
    }
}

fn valid_remote_receipt_id(id: &str) -> bool {
    if let Some(resource) = id.strip_prefix("msteams:") {
        return !resource.is_empty()
            && resource.len() <= 256
            && resource.bytes().all(|byte| {
                byte.is_ascii() && !byte.is_ascii_whitespace() && !byte.is_ascii_control()
            });
    }
    if id.starts_with("wamid.") {
        id.len() > 6
            && id.len() <= 256
            && id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'+' | b'/' | b'_' | b'-' | b'=')
            })
    } else {
        !id.is_empty()
            && id.len() <= 20
            && id.bytes().all(|byte| byte.is_ascii_digit())
            && id.parse::<u64>().is_ok_and(|id| id > 0)
    }
}

/// Provider-reported facts for one known receipt, separate from the local delivery claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunDeliveryStatus {
    schema_version: u64,
    run_id: String,
    result_revision: u64,
    segment: u32,
    sent_at_ms: Option<i64>,
    delivered_at_ms: Option<i64>,
    read_at_ms: Option<i64>,
    failed_at_ms: Option<i64>,
    failure_code: Option<u32>,
}

impl RunDeliveryStatus {
    /// Returns the furthest delivery progress, retaining failure facts separately.
    #[must_use]
    pub const fn reported_state(&self) -> &'static str {
        if self.read_at_ms.is_some() {
            "read"
        } else if self.delivered_at_ms.is_some() {
            "delivered"
        } else if self.failed_at_ms.is_some() {
            "failed"
        } else {
            "sent"
        }
    }

    /// Indicates that both a failure and recipient delivery/read were reported.
    #[must_use]
    pub const fn conflicting_reports(&self) -> bool {
        self.failed_at_ms.is_some() && (self.delivered_at_ms.is_some() || self.read_at_ms.is_some())
    }

    fn validate(&self) -> Result<(), StateError> {
        run_key(&self.run_id)?;
        let times = [
            self.sent_at_ms,
            self.delivered_at_ms,
            self.read_at_ms,
            self.failed_at_ms,
        ];
        if self.schema_version != 1
            || self.result_revision == 0
            || self.segment >= 1_024
            || times.iter().all(Option::is_none)
            || times.iter().flatten().any(|time| *time < 0)
            || self.failure_code.is_some() && self.failed_at_ms.is_none()
        {
            return Err(StateError::InvalidRecord);
        }
        Ok(())
    }

    fn observe(
        &mut self,
        status: &str,
        at: i64,
        failure_code: Option<u32>,
    ) -> Result<bool, StateError> {
        let time = match status {
            "sent" => &mut self.sent_at_ms,
            "delivered" => &mut self.delivered_at_ms,
            "read" => &mut self.read_at_ms,
            "failed" => &mut self.failed_at_ms,
            _ => return Err(StateError::InvalidRecord),
        };
        if time.is_some_and(|previous| previous > at) {
            return Ok(false);
        }
        if *time == Some(at) {
            if status == "failed" && self.failure_code != failure_code {
                return Err(StateError::Conflict);
            }
            return Ok(false);
        }
        *time = Some(at);
        if status == "failed" {
            self.failure_code = failure_code;
        }
        Ok(true)
    }
}

fn receipt_lookup_key(
    source: &str,
    principal: &str,
    remote_id: &str,
) -> Result<String, StateError> {
    if [source, principal]
        .into_iter()
        .any(|value| value.is_empty() || value.len() > 128 || value.chars().any(char::is_control))
        || !remote_id.starts_with("wamid.")
        || !valid_remote_receipt_id(remote_id)
    {
        return Err(StateError::InvalidRecord);
    }
    Ok(format!(
        "run-cloud-receipt/{}",
        identity_digest(&(source, principal, remote_id))?
    ))
}

fn delivery_status_key(id: &str, segment: u32) -> Result<String, StateError> {
    receipt_key(id, segment)?;
    Ok(format!("run-delivery-status/{id}/{segment:04}"))
}

/// A bounded page of confirmed remote segment identifiers, not replay permission.
pub struct RunDeliveryReceiptPage {
    /// At most 32 immutable receipt records in segment order.
    pub receipts: Vec<RunDeliveryReceipt>,
    /// Provider facts associated only with receipts on this page.
    pub statuses: Vec<RunDeliveryStatus>,
    /// Exclusive segment cursor for the next page.
    pub next_after: Option<u32>,
}

fn receipt_key(id: &str, segment: u32) -> Result<String, StateError> {
    run_key(id)?;
    if segment >= 1_024 {
        return Err(StateError::InvalidRecord);
    }
    Ok(format!("run-delivery-receipt/{id}/{segment:04}"))
}

pub(crate) fn recover_deliveries(database: &StateDatabase) -> Result<(), StateError> {
    let mut cursor = None;
    let mut inspected = 0_usize;
    loop {
        let page = database.page("run-delivery/", cursor.as_deref(), 32)?;
        for (key, record) in page.records {
            inspected += 1;
            if inspected
                > usize::try_from(MAX_RETAINED_RUNS).map_err(|_| StateError::InvalidRecord)?
            {
                return Err(StateError::InvalidRecord);
            }
            let mut delivery: RunDelivery = record.decode()?;
            delivery.validate()?;
            if key != delivery_key(&delivery.run_id)? {
                return Err(StateError::InvalidRecord);
            }
            let (_, run) =
                read_run(database, &delivery.run_id)?.ok_or(StateError::InvalidRecord)?;
            if run.phase != RunPhase::Finished || run.revision != delivery.result_revision {
                return Err(StateError::InvalidRecord);
            }
            if delivery.phase == DeliveryPhase::Sending {
                delivery.phase = DeliveryPhase::OutcomeUnknown;
                database.commit(vec![Mutation::put(key, &delivery)?.if_unchanged(&record)])?;
            }
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(());
        }
    }
}

fn run_key(id: &str) -> Result<String, StateError> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StateError::InvalidRecord);
    }
    Ok(format!("run/{id}"))
}

fn read_run(
    database: &StateDatabase,
    id: &str,
) -> Result<Option<(Record, DurableRun)>, StateError> {
    database
        .get(&run_key(id)?)?
        .map(|record| {
            let run: DurableRun = record.decode()?;
            run.validate(id)?;
            Ok((record, run))
        })
        .transpose()
}

fn finish_changes(
    id: &str,
    previous: &Record,
    run: &DurableRun,
) -> Result<Vec<Mutation>, StateError> {
    Ok(vec![
        Mutation::put(run_key(id)?, run)?.if_unchanged(previous),
        Mutation::put(result_key(run)?, run)?.if_absent(),
        Mutation::delete(format!("run-active/{id}"))?,
        Mutation::delete(inbox_key(run)?)?,
    ])
}

pub(crate) fn recover_interrupted(database: &StateDatabase) -> Result<(), StateError> {
    let mut cursor = None;
    loop {
        let page = database.page("run-active/", cursor.as_deref(), 128)?;
        for (key, marker) in page.records {
            if !marker.decode::<bool>()? {
                return Err(StateError::InvalidRecord);
            }
            let id = key
                .strip_prefix("run-active/")
                .ok_or(StateError::InvalidRecord)?;
            let (previous, mut run) = read_run(database, id)?.ok_or(StateError::InvalidRecord)?;
            match run.phase {
                RunPhase::Queued => {
                    let index = inbox_key(&run)?;
                    if database.get(&index)?.is_none() {
                        database.commit(vec![Mutation::put(index, &true)?.if_absent()])?;
                    }
                }
                RunPhase::Executing => {
                    run.phase = RunPhase::OutcomeUnknown;
                    run.revision = run
                        .revision
                        .checked_add(1)
                        .ok_or(StateError::InvalidRecord)?;
                    run.result = Some(RunResult::new("outcome_unknown", "The process stopped before a terminal result committed. Do not repeat external effects automatically.".to_owned())?);
                    database.commit(finish_changes(id, &previous, &run)?)?;
                }
                _ => return Err(StateError::InvalidRecord),
            }
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(());
        }
    }
}

impl DurableStateStore {
    /// Loads a host-owned Discord resume checkpoint, expiring it after five minutes or clock rollback.
    ///
    /// Expiration clears only resume metadata and retains its revision plus all execution claims.
    ///
    /// # Errors
    /// Refuses invalid/corrupt metadata, stale concurrent expiration and unconfirmed storage writes.
    pub async fn discord_resume(
        &self,
        binding: &str,
        at: Timestamp,
    ) -> Result<(u64, Option<DiscordResume>), PortError> {
        let binding = binding.to_owned();
        self.operation(move |database| {
            if at.as_millis() < 0 {
                return Err(port_error(StateError::InvalidRecord));
            }
            let (previous, mut stored) =
                read_discord_resume(database, &binding).map_err(port_error)?;
            if let Some(previous) = previous
                && stored.resume.is_some()
                && (at.as_millis() < stored.saved_at_ms
                    || at.as_millis().saturating_sub(stored.saved_at_ms) >= 300_000)
            {
                stored.resume = None;
                stored.revision = stored
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| port_error(StateError::InvalidRecord))?;
                stored.saved_at_ms = at.as_millis();
                database
                    .commit(vec![
                        Mutation::put(discord_resume_key(&binding).map_err(port_error)?, &stored)
                            .map_err(port_error)?
                            .if_unchanged(&previous),
                    ])
                    .map_err(port_error)?;
            }
            Ok((stored.revision, stored.resume))
        })
        .await
    }

    /// Replaces a settled Discord checkpoint using its exact observed revision.
    ///
    /// The configured host owns admission and processing checks; this record never authorizes replay.
    ///
    /// # Errors
    /// Refuses stale/reversed sequence, invalid metadata, exhausted 256-binding quota or unknown commit.
    pub async fn save_discord_resume(
        &self,
        binding: &str,
        expected_revision: u64,
        resume: Option<DiscordResume>,
        at: Timestamp,
    ) -> Result<u64, PortError> {
        let binding = binding.to_owned();
        self.operation(move |database| {
            if at.as_millis() < 0 {
                return Err(port_error(StateError::InvalidRecord));
            }
            if let Some(resume) = &resume {
                resume.validate().map_err(port_error)?;
            }
            let (previous, mut stored) =
                read_discord_resume(database, &binding).map_err(port_error)?;
            if stored.revision != expected_revision
                || at.as_millis() < stored.saved_at_ms
                || stored
                    .resume
                    .as_ref()
                    .zip(resume.as_ref())
                    .is_some_and(|(before, after)| {
                        before.session_id == after.session_id && after.sequence < before.sequence
                    })
            {
                return Err(port_error(StateError::Conflict));
            }
            if stored.resume == resume {
                return Ok(stored.revision);
            }
            stored.revision = stored
                .revision
                .checked_add(1)
                .ok_or_else(|| port_error(StateError::InvalidRecord))?;
            stored.resume = resume;
            stored.saved_at_ms = at.as_millis();
            let mutation =
                Mutation::put(discord_resume_key(&binding).map_err(port_error)?, &stored)
                    .map_err(port_error)?;
            match previous {
                Some(previous) => database.commit(vec![mutation.if_unchanged(&previous)]),
                None => database.insert_with_prefix_limit(
                    mutation.if_absent(),
                    "discord-resume/v1/",
                    256,
                    || true,
                ),
            }
            .map_err(port_error)?;
            Ok(stored.revision)
        })
        .await
    }

    /// Loads a host-owned Telegram cursor, conservatively expiring one day without advancement.
    ///
    /// Expiry or clock regression resets only the provider offset, never durable execution claims.
    /// This avoids carrying stale offsets into Telegram's random update-ID reset after long inactivity.
    ///
    /// # Errors
    /// Refuses invalid bindings, corrupted cursor records and storage failures.
    pub async fn telegram_poll_cursor(
        &self,
        binding: &str,
        at: Timestamp,
    ) -> Result<i64, PortError> {
        let binding = binding.to_owned();
        self.operation(move |database| {
            if at.as_millis() < 0 {
                return Err(port_error(StateError::InvalidRecord));
            }
            let (previous, mut cursor) =
                read_telegram_cursor(database, &binding).map_err(port_error)?;
            if let Some(previous) = previous
                && (at.as_millis() < cursor.advanced_at_ms
                    || cursor.offset > 0
                        && at.as_millis().saturating_sub(cursor.advanced_at_ms) >= 86_400_000)
            {
                cursor.offset = 0;
                cursor.advanced_at_ms = at.as_millis();
                database
                    .commit(vec![
                        Mutation::put(telegram_cursor_key(&binding).map_err(port_error)?, &cursor)
                            .map_err(port_error)?
                            .if_unchanged(&previous),
                    ])
                    .map_err(port_error)?;
            }
            Ok(cursor.offset)
        })
        .await
    }

    /// Advances a drained Telegram batch cursor with an exact prior-offset comparison.
    ///
    /// The configured host must settle its durable message processing before calling this method.
    /// This record never authorizes replay and new credential bindings do not inherit old offsets.
    ///
    /// # Errors
    /// Refuses stale/negative/regressing offsets, more than 256 retained bindings, and unknown writes.
    pub async fn advance_telegram_poll_cursor(
        &self,
        binding: &str,
        expected: i64,
        next: i64,
        at: Timestamp,
    ) -> Result<(), PortError> {
        let binding = binding.to_owned();
        self.operation(move |database| {
            if expected < 0 || next < expected || at.as_millis() < 0 {
                return Err(port_error(StateError::InvalidRecord));
            }
            let (previous, current) =
                read_telegram_cursor(database, &binding).map_err(port_error)?;
            if current.offset != expected || at.as_millis() < current.advanced_at_ms {
                return Err(port_error(StateError::Conflict));
            }
            if next == expected {
                return Ok(());
            }
            let cursor = TelegramPollCursor {
                schema_version: 1,
                binding: binding.clone(),
                offset: next,
                advanced_at_ms: at.as_millis(),
            };
            let mutation =
                Mutation::put(telegram_cursor_key(&binding).map_err(port_error)?, &cursor)
                    .map_err(port_error)?;
            match previous {
                Some(previous) => database.commit(vec![mutation.if_unchanged(&previous)]),
                None => database.insert_with_prefix_limit(
                    mutation.if_absent(),
                    "telegram-poll/v1/",
                    256,
                    || true,
                ),
            }
            .map_err(port_error)
        })
        .await
    }

    /// Claims a terminal result for one transport attempt before any outbound bytes are sent.
    ///
    /// # Errors
    /// Refuses unowned/nonterminal results, changed reply content and unconfirmed commits.
    /// An existing claim returns `None`; no delivery phase is automatically sent again.
    pub async fn claim_run_delivery(
        &self,
        id: &str,
        source: &str,
        principal: &str,
        revision: u64,
        content: &str,
    ) -> Result<Option<RunDelivery>, PortError> {
        let id = id.to_owned();
        let source = source.to_owned();
        let principal = principal.to_owned();
        if content.len() > MAX_RESULT_BYTES {
            return Err(PortError::Invalid(
                "delivery content exceeds its bound".to_owned(),
            ));
        }
        let content_digest = identity_digest(&content).map_err(port_error)?;
        self.operation(move |database| {
            let (_, run) = read_run(database, &id)
                .map_err(port_error)?
                .filter(|(_, run)| {
                    run.submission.source == source && run.submission.principal == principal
                })
                .ok_or_else(|| PortError::NotFound("delivery run is not available".to_owned()))?;
            if run.phase != RunPhase::Finished || run.revision != revision {
                return Err(PortError::Conflict(
                    "delivery requires the exact terminal result revision".to_owned(),
                ));
            }
            let key = delivery_key(&id).map_err(port_error)?;
            if let Some(record) = database.get(&key).map_err(port_error)? {
                let delivery: RunDelivery = record.decode().map_err(port_error)?;
                delivery.validate().map_err(port_error)?;
                if delivery.run_id != id
                    || delivery.result_revision != revision
                    || delivery.content_digest != content_digest
                {
                    return Err(PortError::Conflict(
                        "delivery binding changed; reconciliation is required".to_owned(),
                    ));
                }
                return Ok(None);
            }
            let delivery = RunDelivery {
                schema: 1,
                run_id: id,
                result_revision: revision,
                content_digest,
                phase: DeliveryPhase::Sending,
            };
            match database.commit(vec![
                Mutation::put(key, &delivery)
                    .map_err(port_error)?
                    .if_absent(),
            ]) {
                Ok(()) => Ok(Some(delivery)),
                Err(StateError::Conflict) => Ok(None),
                Err(error) => Err(port_error(error)),
            }
        })
        .await
    }

    /// Persists one remote acknowledgement before the next outbound segment is sent.
    ///
    /// # Errors
    /// Refuses changed claims, foreign owners, noncontiguous/altered receipts and unknown commits.
    pub async fn record_run_delivery_receipt(
        &self,
        claim: &RunDelivery,
        source: &str,
        principal: &str,
        segment: u32,
        content: &str,
        remote_id: &str,
    ) -> Result<(), PortError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        if content.is_empty() || content.len() > 16 * 1024 {
            return Err(port_error(StateError::InvalidRecord));
        }
        let content_sha256 = Sha256::digest(content.as_bytes())
            .into_iter()
            .flat_map(|byte| {
                [
                    char::from(HEX[usize::from(byte >> 4)]),
                    char::from(HEX[usize::from(byte & 15)]),
                ]
            })
            .collect();
        let receipt = RunDeliveryReceipt {
            schema_version: 1,
            run_id: claim.run_id.clone(),
            result_revision: claim.result_revision,
            segment,
            content_bytes: content.len(),
            content_sha256,
            remote_message_id: remote_id.to_owned(),
        };
        receipt.validate().map_err(port_error)?;
        let claim = claim.clone();
        let source = source.to_owned();
        let principal = principal.to_owned();
        self.operation(move |database| {
            claim.validate().map_err(port_error)?;
            let (_, run) = read_run(database, &claim.run_id)
                .map_err(port_error)?
                .filter(|(_, run)| {
                    run.submission.source == source && run.submission.principal == principal
                })
                .ok_or_else(|| PortError::NotFound("delivery run is not available".to_owned()))?;
            let key = delivery_key(&claim.run_id).map_err(port_error)?;
            let previous = database
                .get(&key)
                .map_err(port_error)?
                .ok_or_else(|| PortError::NotFound("delivery was not claimed".to_owned()))?;
            let current: RunDelivery = previous.decode().map_err(port_error)?;
            if current != claim
                || current.phase != DeliveryPhase::Sending
                || run.revision != claim.result_revision
            {
                return Err(PortError::Conflict(
                    "delivery claim is no longer accepting receipts".to_owned(),
                ));
            }
            let receipt_key = receipt_key(&claim.run_id, segment).map_err(port_error)?;
            if let Some(existing) = database.get(&receipt_key).map_err(port_error)? {
                let existing: RunDeliveryReceipt = existing.decode().map_err(port_error)?;
                existing.validate().map_err(port_error)?;
                return if existing == receipt {
                    Ok(())
                } else {
                    Err(PortError::Conflict(
                        "remote receipt changed for the same segment".to_owned(),
                    ))
                };
            }
            if segment > 0 {
                let previous = database
                    .get(&self::receipt_key(&claim.run_id, segment - 1).map_err(port_error)?)
                    .map_err(port_error)?
                    .ok_or_else(|| {
                        PortError::Conflict(
                            "remote receipts must be recorded in segment order".to_owned(),
                        )
                    })?;
                let previous: RunDeliveryReceipt = previous.decode().map_err(port_error)?;
                previous.validate().map_err(port_error)?;
                if previous.run_id != claim.run_id
                    || previous.result_revision != claim.result_revision
                    || previous.segment != segment - 1
                {
                    return Err(port_error(StateError::InvalidRecord));
                }
            }
            let mut changes = vec![
                Mutation::put(key, &current)
                    .map_err(port_error)?
                    .if_unchanged(&previous),
                Mutation::put(receipt_key, &receipt)
                    .map_err(port_error)?
                    .if_absent(),
            ];
            if receipt.remote_message_id.starts_with("wamid.") {
                let index_key = receipt_lookup_key(&source, &principal, &receipt.remote_message_id)
                    .map_err(port_error)?;
                if database.get(&index_key).map_err(port_error)?.is_some() {
                    return Err(PortError::Conflict(
                        "Cloud message identity is already bound to a receipt".to_owned(),
                    ));
                }
                changes.push(
                    Mutation::put(index_key, &receipt)
                        .map_err(port_error)?
                        .if_absent(),
                );
            }
            database.commit(changes).map_err(port_error)
        })
        .await
    }

    /// Applies a provider status only to an existing receipt in the exact authenticated partition.
    ///
    /// Unknown remote IDs return false without creating records. This never settles or retries a claim.
    ///
    /// # Errors
    /// Refuses invalid status/timestamps, corrupt bindings, conflicting same-time failures or unknown writes.
    pub async fn record_run_delivery_status(
        &self,
        source: &str,
        principal: &str,
        remote_id: &str,
        status: &str,
        at: Timestamp,
        failure_code: Option<u32>,
    ) -> Result<bool, PortError> {
        if at.as_millis() < 0
            || !matches!(status, "sent" | "delivered" | "read" | "failed")
            || status != "failed" && failure_code.is_some()
        {
            return Err(port_error(StateError::InvalidRecord));
        }
        let index_key = receipt_lookup_key(source, principal, remote_id).map_err(port_error)?;
        let (source, principal, remote_id, status) = (
            source.to_owned(),
            principal.to_owned(),
            remote_id.to_owned(),
            status.to_owned(),
        );
        self.operation(move |database| {
            let Some(index) = database.get(&index_key).map_err(port_error)? else {
                return Ok(false);
            };
            let receipt: RunDeliveryReceipt = index.decode().map_err(port_error)?;
            receipt.validate().map_err(port_error)?;
            let (_, run) = read_run(database, &receipt.run_id)
                .map_err(port_error)?
                .filter(|(_, run)| {
                    run.submission.source == source && run.submission.principal == principal
                })
                .ok_or_else(|| PortError::NotFound("status receipt is unavailable".to_owned()))?;
            let stored_receipt = database
                .get(&receipt_key(&receipt.run_id, receipt.segment).map_err(port_error)?)
                .map_err(port_error)?
                .ok_or_else(|| port_error(StateError::InvalidRecord))?;
            if receipt.remote_message_id != remote_id
                || run.revision != receipt.result_revision
                || stored_receipt
                    .decode::<RunDeliveryReceipt>()
                    .map_err(port_error)?
                    != receipt
            {
                return Err(port_error(StateError::InvalidRecord));
            }
            let key = delivery_status_key(&receipt.run_id, receipt.segment).map_err(port_error)?;
            for _attempt in 0..32 {
                let previous = database.get(&key).map_err(port_error)?;
                let mut facts = if let Some(previous) = &previous {
                    let facts: RunDeliveryStatus = previous.decode().map_err(port_error)?;
                    facts.validate().map_err(port_error)?;
                    if facts.run_id != receipt.run_id
                        || facts.result_revision != receipt.result_revision
                        || facts.segment != receipt.segment
                    {
                        return Err(port_error(StateError::InvalidRecord));
                    }
                    facts
                } else {
                    RunDeliveryStatus {
                        schema_version: 1,
                        run_id: receipt.run_id.clone(),
                        result_revision: receipt.result_revision,
                        segment: receipt.segment,
                        sent_at_ms: None,
                        delivered_at_ms: None,
                        read_at_ms: None,
                        failed_at_ms: None,
                        failure_code: None,
                    }
                };
                if !facts
                    .observe(&status, at.as_millis(), failure_code)
                    .map_err(port_error)?
                {
                    return Ok(true);
                }
                facts.validate().map_err(port_error)?;
                let mutation = Mutation::put(key.clone(), &facts).map_err(port_error)?;
                let mutation = match previous {
                    Some(previous) => mutation.if_unchanged(&previous),
                    None => mutation.if_absent(),
                };
                match database.commit(vec![mutation]) {
                    Ok(()) => return Ok(true),
                    Err(StateError::Conflict) => {}
                    Err(error) => return Err(port_error(error)),
                }
            }
            Err(PortError::Conflict(
                "delivery status changed concurrently".to_owned(),
            ))
        })
        .await
    }

    /// Reads bounded remote receipt metadata for the authenticated run owner.
    ///
    /// # Errors
    /// Refuses foreign owners, invalid cursors and inconsistent stored claim/receipt bindings.
    pub async fn run_delivery_receipts(
        &self,
        id: &str,
        source: &str,
        principal: &str,
        after: Option<u32>,
    ) -> Result<RunDeliveryReceiptPage, PortError> {
        let id = id.to_owned();
        let source = source.to_owned();
        let principal = principal.to_owned();
        self.operation(move |database| {
            let (_, run) = read_run(database, &id)
                .map_err(port_error)?
                .filter(|(_, run)| {
                    run.submission.source == source && run.submission.principal == principal
                })
                .ok_or_else(|| PortError::NotFound("delivery run is not available".to_owned()))?;
            let cursor = after
                .map(|segment| receipt_key(&id, segment))
                .transpose()
                .map_err(port_error)?;
            let prefix = format!("run-delivery-receipt/{id}/");
            let page = database
                .page(&prefix, cursor.as_deref(), 32)
                .map_err(port_error)?;
            let claim = database
                .get(&delivery_key(&id).map_err(port_error)?)
                .map_err(port_error)?
                .map(|record| record.decode::<RunDelivery>())
                .transpose()
                .map_err(port_error)?;
            if let Some(claim) = &claim {
                claim.validate().map_err(port_error)?;
            }
            let mut receipts = Vec::with_capacity(page.records.len());
            let mut statuses = Vec::new();
            for (key, record) in page.records {
                let receipt: RunDeliveryReceipt = record.decode().map_err(port_error)?;
                receipt.validate().map_err(port_error)?;
                if key != receipt_key(&id, receipt.segment).map_err(port_error)?
                    || receipt.run_id != id
                    || receipt.result_revision != run.revision
                    || claim.as_ref().is_none_or(|claim| {
                        claim.run_id != id || claim.result_revision != receipt.result_revision
                    })
                {
                    return Err(port_error(StateError::InvalidRecord));
                }
                if let Some(record) = database
                    .get(&delivery_status_key(&id, receipt.segment).map_err(port_error)?)
                    .map_err(port_error)?
                {
                    let status: RunDeliveryStatus = record.decode().map_err(port_error)?;
                    status.validate().map_err(port_error)?;
                    if status.run_id != id
                        || status.segment != receipt.segment
                        || status.result_revision != receipt.result_revision
                    {
                        return Err(port_error(StateError::InvalidRecord));
                    }
                    statuses.push(status);
                }
                receipts.push(receipt);
            }
            Ok(RunDeliveryReceiptPage {
                next_after: page
                    .next_cursor
                    .and_then(|_| receipts.last().map(|receipt| receipt.segment)),
                receipts,
                statuses,
            })
        })
        .await
    }

    /// Records a transport outcome and atomically removes a confirmed result notification.
    ///
    /// Confirmed segment receipts remain when the overall delivery settles or is acknowledged.
    ///
    /// # Errors
    /// Refuses mismatched owners/claims, already settled delivery and uncertain commits.
    pub async fn finish_run_delivery(
        &self,
        claim: RunDelivery,
        source: &str,
        principal: &str,
        confirmed: bool,
    ) -> Result<RunDelivery, PortError> {
        let source = source.to_owned();
        let principal = principal.to_owned();
        self.operation(move |database| {
            claim.validate().map_err(port_error)?;
            let (_, run) = read_run(database, &claim.run_id)
                .map_err(port_error)?
                .filter(|(_, run)| {
                    run.submission.source == source && run.submission.principal == principal
                })
                .ok_or_else(|| PortError::NotFound("delivery run is not available".to_owned()))?;
            if run.revision != claim.result_revision {
                return Err(PortError::Conflict("delivery result changed".to_owned()));
            }
            let key = delivery_key(&claim.run_id).map_err(port_error)?;
            let previous = database
                .get(&key)
                .map_err(port_error)?
                .ok_or_else(|| PortError::NotFound("delivery was not claimed".to_owned()))?;
            let mut current: RunDelivery = previous.decode().map_err(port_error)?;
            if current != claim || current.phase != DeliveryPhase::Sending {
                return Err(PortError::Conflict(
                    "delivery was already settled or changed".to_owned(),
                ));
            }
            current.phase = if confirmed {
                DeliveryPhase::Delivered
            } else {
                DeliveryPhase::OutcomeUnknown
            };
            let mut changes = vec![
                Mutation::put(key, &current)
                    .map_err(port_error)?
                    .if_unchanged(&previous),
            ];
            if confirmed {
                let notification = result_key(&run).map_err(port_error)?;
                if let Some(record) = database.get(&notification).map_err(port_error)? {
                    changes.push(
                        Mutation::delete(notification)
                            .map_err(port_error)?
                            .if_unchanged(&record),
                    );
                }
            }
            database.commit(changes).map_err(port_error)?;
            Ok(current)
        })
        .await
    }

    /// Reads one delivery status only within the run's authenticated ingress namespace.
    ///
    /// # Errors
    /// Refuses malformed identities, corrupt delivery records and unavailable storage.
    pub async fn load_run_delivery(
        &self,
        id: &str,
        source: &str,
        principal: &str,
    ) -> Result<Option<RunDelivery>, PortError> {
        let id = id.to_owned();
        let source = source.to_owned();
        let principal = principal.to_owned();
        self.operation(move |database| {
            if read_run(database, &id)
                .map_err(port_error)?
                .is_none_or(|(_, run)| {
                    run.submission.source != source || run.submission.principal != principal
                })
            {
                return Ok(None);
            }
            let Some(record) = database
                .get(&delivery_key(&id).map_err(port_error)?)
                .map_err(port_error)?
            else {
                return Ok(None);
            };
            let delivery: RunDelivery = record.decode().map_err(port_error)?;
            delivery.validate().map_err(port_error)?;
            if delivery.run_id != id {
                return Err(PortError::Invalid(
                    "delivery identity differs from its key".to_owned(),
                ));
            }
            Ok(Some(delivery))
        })
        .await
    }

    /// Durably accepts one scoped input, or returns its exact prior record.
    ///
    /// # Errors
    /// Rejects conflicting reuse, exhausted retention quota, invalid input and unconfirmed commits.
    pub async fn admit_run(
        &self,
        submission: RunSubmission,
        at: Timestamp,
    ) -> Result<RunAdmission, PortError> {
        self.operation(move |database| {
            submission.validate().map_err(port_error)?;
            let id = submission.run_id().map_err(port_error)?;
            let owner = identity_digest(&(&submission.source, &submission.principal))
                .map_err(port_error)?;
            for _attempt in 0..32 {
                let previous_owner =
                    read_session_owner(database, &submission.session_id).map_err(port_error)?;
                if previous_owner
                    .as_ref()
                    .is_some_and(|(_, previous)| previous != &owner)
                {
                    return Err(PortError::Conflict(
                        "session is not available to this authenticated principal".to_owned(),
                    ));
                }
                if let Some((_, run)) = read_run(database, &id).map_err(port_error)? {
                    if run.submission != submission {
                        return Err(PortError::Conflict(
                            "idempotency key belongs to different input or session".to_owned(),
                        ));
                    }
                    if previous_owner.is_none() {
                        if read_session_owner(database, &submission.session_id)
                            .map_err(port_error)?
                            .is_some()
                        {
                            continue;
                        }
                        return Err(PortError::Conflict(
                            "historical session ownership requires explicit migration".to_owned(),
                        ));
                    }
                    return Ok(RunAdmission {
                        run,
                        replayed: true,
                    });
                }
                if previous_owner.is_none() {
                    for namespace in ["session", "context", "turn-high-water"] {
                        if database
                            .get(&format!(
                                "{namespace}/{}",
                                serde_json::json!(submission.session_id)
                            ))
                            .map_err(port_error)?
                            .is_some()
                        {
                            return Err(PortError::Conflict(
                                "existing unowned session requires explicit migration".to_owned(),
                            ));
                        }
                    }
                }
                let counter = database.get(COUNT_KEY).map_err(port_error)?;
                let count = counter
                    .as_ref()
                    .map(Record::decode::<u64>)
                    .transpose()
                    .map_err(port_error)?
                    .unwrap_or(0);
                if count >= MAX_RETAINED_RUNS {
                    return Err(PortError::Unavailable(
                        "durable run retention quota reached; existing requests remain queryable"
                            .to_owned(),
                    ));
                }
                let run = DurableRun {
                    schema: 1,
                    run_id: id.clone(),
                    submission: submission.clone(),
                    phase: RunPhase::Queued,
                    cancel_requested: false,
                    turn: None,
                    result: None,
                    revision: 1,
                    accepted_at_ms: at.as_millis(),
                    updated_at_ms: at.as_millis(),
                };
                let count_change = Mutation::put(COUNT_KEY, &(count + 1)).map_err(port_error)?;
                let count_change = match counter.as_ref() {
                    Some(previous) => count_change.if_unchanged(previous),
                    None => count_change.if_absent(),
                };
                let ownership = Mutation::put(
                    session_owner_key(&submission.session_id).map_err(port_error)?,
                    &owner,
                )
                .map_err(port_error)?;
                let ownership = match &previous_owner {
                    Some((record, _)) => ownership.if_unchanged(record),
                    None => ownership.if_absent(),
                };
                let result = database.commit(vec![
                    Mutation::put(run_key(&id).map_err(port_error)?, &run)
                        .map_err(port_error)?
                        .if_absent(),
                    Mutation::put(format!("run-active/{id}"), &true)
                        .map_err(port_error)?
                        .if_absent(),
                    Mutation::put(inbox_key(&run).map_err(port_error)?, &true)
                        .map_err(port_error)?
                        .if_absent(),
                    count_change,
                    ownership,
                ]);
                match result {
                    Ok(()) => {
                        return Ok(RunAdmission {
                            run,
                            replayed: false,
                        });
                    }
                    Err(StateError::Conflict) => {}
                    Err(error) => return Err(port_error(error)),
                }
            }
            Err(PortError::Conflict(
                "run admission contention exceeded its bounded retry budget".to_owned(),
            ))
        })
        .await
    }

    /// Checks durable session ownership without disclosing another principal's identity.
    ///
    /// # Errors
    /// Rejects invalid principals, corrupt ownership and unavailable storage.
    pub async fn owns_run_session(
        &self,
        source: &str,
        principal: &str,
        session: &SessionId,
    ) -> Result<bool, PortError> {
        result_prefix(source, principal).map_err(port_error)?;
        let owner = identity_digest(&(source, principal)).map_err(port_error)?;
        let session = session.to_string();
        self.operation(move |database| {
            Ok(read_session_owner(database, &session)
                .map_err(port_error)?
                .is_some_and(|(_, stored)| stored == owner))
        })
        .await
    }

    /// Reserves a legacy session namespace without granting any authenticated tool authority.
    ///
    /// # Errors
    /// Refuses a Gateway-owned session and failed or contended ownership commits.
    pub async fn reserve_legacy_session(&self, session: &SessionId) -> Result<(), PortError> {
        self.reserve_session_owner("legacy", "unverified-routing", session, true)
            .await
    }

    /// Reserves a session for an authenticated ingress without claiming historical unowned data.
    ///
    /// # Errors
    /// Refuses conflicting owners, unowned historical state and unconfirmed storage operations.
    pub async fn reserve_authenticated_session(
        &self,
        source: &str,
        principal: &str,
        session: &SessionId,
    ) -> Result<(), PortError> {
        self.reserve_session_owner(source, principal, session, false)
            .await
    }

    async fn reserve_session_owner(
        &self,
        source: &str,
        principal: &str,
        session: &SessionId,
        permit_historical: bool,
    ) -> Result<(), PortError> {
        result_prefix(source, principal).map_err(port_error)?;
        let session = session.to_string();
        let owner = identity_digest(&(source, principal)).map_err(port_error)?;
        self.operation(move |database| {
            for _attempt in 0..32 {
                if let Some((_, previous)) =
                    read_session_owner(database, &session).map_err(port_error)?
                {
                    return if previous == owner {
                        Ok(())
                    } else {
                        Err(PortError::Conflict(
                            "session is not available to this ingress identity".to_owned(),
                        ))
                    };
                }
                if !permit_historical {
                    for namespace in ["session", "context", "turn-high-water"] {
                        if database
                            .get(&format!("{namespace}/{}", serde_json::json!(session)))
                            .map_err(port_error)?
                            .is_some()
                        {
                            return Err(PortError::Conflict(
                                "unowned historical session requires explicit migration".to_owned(),
                            ));
                        }
                    }
                }
                match database.commit(vec![
                    Mutation::put(session_owner_key(&session).map_err(port_error)?, &owner)
                        .map_err(port_error)?
                        .if_absent(),
                ]) {
                    Ok(()) => return Ok(()),
                    Err(StateError::Conflict) => {}
                    Err(error) => return Err(port_error(error)),
                }
            }
            Err(PortError::Conflict(
                "session ownership contention exceeded its budget".to_owned(),
            ))
        })
        .await
    }

    /// Claims a queued input once, before the host may start external work.
    ///
    /// # Errors
    /// Rejects an already claimed, completed or interrupted run and failed commits.
    pub async fn claim_run(&self, id: &str, at: Timestamp) -> Result<DurableRun, PortError> {
        let id = id.to_owned();
        self.operation(move |database| {
            let (previous, mut run) = read_run(database, &id)
                .map_err(port_error)?
                .ok_or_else(|| PortError::NotFound("run does not exist".to_owned()))?;
            if run.phase != RunPhase::Queued {
                return Err(PortError::Conflict(
                    "run is not queued; execution must not be repeated".to_owned(),
                ));
            }
            run.phase = RunPhase::Executing;
            run.revision = run
                .revision
                .checked_add(1)
                .ok_or_else(|| PortError::Conflict("run revision exhausted".to_owned()))?;
            run.updated_at_ms = at.as_millis();
            database
                .commit(vec![
                    Mutation::put(run_key(&id).map_err(port_error)?, &run)
                        .map_err(port_error)?
                        .if_unchanged(&previous),
                ])
                .map_err(port_error)?;
            Ok(run)
        })
        .await
    }

    /// Binds the once-claimed execution to its runtime turn without authorizing another execution.
    ///
    /// # Errors
    /// Rejects rebinding, non-executing runs and unconfirmed commits.
    pub async fn bind_run_turn(&self, id: &str, turn: TurnId) -> Result<DurableRun, PortError> {
        let id = id.to_owned();
        self.operation(move |database| {
            for _attempt in 0..32 {
                let (previous, mut run) = read_run(database, &id)
                    .map_err(port_error)?
                    .ok_or_else(|| PortError::NotFound("run does not exist".to_owned()))?;
                if run.phase != RunPhase::Executing || run.turn.is_some() {
                    return Err(PortError::Conflict(
                        "run execution was already bound or retired".to_owned(),
                    ));
                }
                run.turn = Some(turn.ordinal());
                run.revision = run
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| PortError::Conflict("run revision exhausted".to_owned()))?;
                match database.commit(vec![
                    Mutation::put(run_key(&id).map_err(port_error)?, &run)
                        .map_err(port_error)?
                        .if_unchanged(&previous),
                ]) {
                    Ok(()) => return Ok(run),
                    Err(StateError::Conflict) => {}
                    Err(error) => return Err(port_error(error)),
                }
            }
            Err(PortError::Conflict(
                "run binding contention exceeded its budget".to_owned(),
            ))
        })
        .await
    }

    /// Persists cancellation for the authenticated run; queued work terminates without execution.
    ///
    /// # Errors
    /// Rejects foreign identities, invalid records and failed commits; never cancels a replacement run.
    pub async fn cancel_run(
        &self,
        id: &str,
        source: &str,
        principal: &str,
        at: Timestamp,
    ) -> Result<DurableRun, PortError> {
        let (id, source, principal) = (id.to_owned(), source.to_owned(), principal.to_owned());
        self.operation(move |database| {
            for _attempt in 0..32 {
                let (previous, mut run) = read_run(database, &id)
                    .map_err(port_error)?
                    .ok_or_else(|| PortError::NotFound("run does not exist".to_owned()))?;
                if run.submission.source != source || run.submission.principal != principal {
                    return Err(PortError::NotFound("run does not exist".to_owned()));
                }
                if run.result.is_some() || run.cancel_requested {
                    return Ok(run);
                }
                run.cancel_requested = true;
                run.revision = run
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| PortError::Conflict("run revision exhausted".to_owned()))?;
                run.updated_at_ms = at.as_millis();
                let changes = if run.phase == RunPhase::Queued {
                    run.phase = RunPhase::Finished;
                    run.result =
                        Some(RunResult::new("cancelled", String::new()).map_err(port_error)?);
                    finish_changes(&id, &previous, &run).map_err(port_error)?
                } else {
                    vec![
                        Mutation::put(run_key(&id).map_err(port_error)?, &run)
                            .map_err(port_error)?
                            .if_unchanged(&previous),
                    ]
                };
                match database.commit(changes) {
                    Ok(()) => return Ok(run),
                    Err(StateError::Conflict) => {}
                    Err(error) => return Err(port_error(error)),
                }
            }
            Err(PortError::Conflict(
                "run cancellation contention exceeded its budget".to_owned(),
            ))
        })
        .await
    }

    /// Atomically publishes a terminal run and a durable, not-yet-acknowledged result.
    ///
    /// # Errors
    /// Rejects non-executing runs, conflicting terminal results and failed commits.
    pub async fn finish_run(
        &self,
        id: &str,
        result: RunResult,
        at: Timestamp,
    ) -> Result<DurableRun, PortError> {
        let id = id.to_owned();
        self.operation(move |database| {
            result.validate().map_err(port_error)?;
            for _attempt in 0..32 {
                let (previous, mut run) = read_run(database, &id)
                    .map_err(port_error)?
                    .ok_or_else(|| PortError::NotFound("run does not exist".to_owned()))?;
                if matches!(run.phase, RunPhase::Finished | RunPhase::OutcomeUnknown)
                    && run.result.as_ref() == Some(&result)
                {
                    return Ok(run);
                }
                if run.phase != RunPhase::Executing {
                    return Err(PortError::Conflict(
                        "run is not executing or its terminal result differs".to_owned(),
                    ));
                }
                run.phase = if result.status() == "outcome_unknown" {
                    RunPhase::OutcomeUnknown
                } else {
                    RunPhase::Finished
                };
                run.result = Some(result.clone());
                run.updated_at_ms = at.as_millis();
                run.revision = run
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| PortError::Conflict("run revision exhausted".to_owned()))?;
                match database.commit(finish_changes(&id, &previous, &run).map_err(port_error)?) {
                    Ok(()) => return Ok(run),
                    Err(StateError::Conflict) => {}
                    Err(error) => return Err(port_error(error)),
                }
            }
            Err(PortError::Conflict(
                "run finalization contention exceeded its budget".to_owned(),
            ))
        })
        .await
    }

    /// Looks up one run only within its authenticated ingress identity.
    ///
    /// # Errors
    /// Rejects invalid identifiers, corrupt records and storage failures.
    pub async fn load_run(
        &self,
        id: &str,
        source: &str,
        principal: &str,
    ) -> Result<Option<DurableRun>, PortError> {
        let (id, source, principal) = (id.to_owned(), source.to_owned(), principal.to_owned());
        self.operation(move |database| {
            Ok(read_run(database, &id)
                .map_err(port_error)?
                .map(|(_, run)| run)
                .filter(|run| {
                    run.submission.source == source && run.submission.principal == principal
                }))
        })
        .await
    }

    /// Lists unacknowledged results within one authenticated source/principal partition.
    ///
    /// # Errors
    /// Rejects malformed cursors, corrupt index entries and storage failures.
    pub async fn pending_run_results(
        &self,
        source: &str,
        principal: &str,
        session: Option<&SessionId>,
        after: Option<&str>,
    ) -> Result<RunResultPage, PortError> {
        let prefix = result_prefix(source, principal).map_err(port_error)?;
        if let Some(after) = after {
            run_key(after).map_err(port_error)?;
        }
        let cursor = after.map(|id| format!("{prefix}{id}"));
        let session = session.map(ToString::to_string);
        self.operation(move |database| {
            let page = database
                .page(&prefix, cursor.as_deref(), 32)
                .map_err(port_error)?;
            let mut runs = Vec::new();
            for (key, record) in page.records {
                let run: DurableRun = record.decode().map_err(port_error)?;
                let id = key
                    .strip_prefix(&prefix)
                    .ok_or_else(|| PortError::Invalid("result partition mismatch".to_owned()))?;
                run.validate(id).map_err(port_error)?;
                if result_key(&run).map_err(port_error)? != key
                    || !matches!(run.phase, RunPhase::Finished | RunPhase::OutcomeUnknown)
                {
                    return Err(PortError::Invalid(
                        "result index identity or phase mismatch".to_owned(),
                    ));
                }
                if session
                    .as_ref()
                    .is_none_or(|session| run.session_id() == session)
                {
                    runs.push(run);
                }
            }
            Ok(RunResultPage {
                runs,
                next_cursor: page.next_cursor.map(|key| key[prefix.len()..].to_owned()),
            })
        })
        .await
    }

    /// Lists accepted or executing inputs so a reconnected client can recover its active run.
    ///
    /// # Errors
    /// Rejects malformed cursors, identity/index mismatches and storage failures.
    pub async fn active_runs(
        &self,
        source: &str,
        principal: &str,
        session: &SessionId,
        after: Option<&str>,
    ) -> Result<RunResultPage, PortError> {
        result_prefix(source, principal).map_err(port_error)?;
        let prefix = inbox_prefix(source, principal).map_err(port_error)?;
        if let Some(after) = after {
            run_key(after).map_err(port_error)?;
        }
        let cursor = after.map(|id| format!("{prefix}{id}"));
        let session = session.to_string();
        self.operation(move |database| {
            let page = database
                .page(&prefix, cursor.as_deref(), 32)
                .map_err(port_error)?;
            let mut runs = Vec::new();
            for (key, record) in page.records {
                if !record.decode::<bool>().map_err(port_error)? {
                    return Err(PortError::Invalid("invalid inbox marker".to_owned()));
                }
                let id = key
                    .strip_prefix(&prefix)
                    .ok_or_else(|| PortError::Invalid("inbox partition mismatch".to_owned()))?;
                let (_, run) = read_run(database, id)
                    .map_err(port_error)?
                    .ok_or_else(|| PortError::Invalid("missing inbox run".to_owned()))?;
                if inbox_key(&run).map_err(port_error)? != key {
                    return Err(PortError::Invalid("inbox identity mismatch".to_owned()));
                }
                if run.session_id() == session && run.result.is_none() {
                    runs.push(run);
                }
            }
            Ok(RunResultPage {
                runs,
                next_cursor: page.next_cursor.map(|key| key[prefix.len()..].to_owned()),
            })
        })
        .await
    }

    /// Acknowledges exactly one terminal result, never merely an event-bus publish.
    ///
    /// # Errors
    /// Refuses cross-principal acknowledgements, stale revisions and nonterminal runs.
    pub async fn acknowledge_run(
        &self,
        id: &str,
        source: &str,
        principal: &str,
        revision: u64,
    ) -> Result<(), PortError> {
        let (id, source, principal) = (id.to_owned(), source.to_owned(), principal.to_owned());
        self.operation(move |database| {
            let (_, run) = read_run(database, &id)
                .map_err(port_error)?
                .ok_or_else(|| PortError::NotFound("run does not exist".to_owned()))?;
            if run.submission.source != source || run.submission.principal != principal {
                return Err(PortError::NotFound("run does not exist".to_owned()));
            }
            if !matches!(run.phase, RunPhase::Finished | RunPhase::OutcomeUnknown)
                || run.revision != revision
            {
                return Err(PortError::Conflict(
                    "acknowledgement must match the observed terminal revision".to_owned(),
                ));
            }
            let key = result_key(&run).map_err(port_error)?;
            if let Some(previous) = database.get(&key).map_err(port_error)? {
                let result: DurableRun = previous.decode().map_err(port_error)?;
                if result != run {
                    return Err(PortError::Invalid(
                        "outbox result differs from terminal run".to_owned(),
                    ));
                }
                database
                    .commit(vec![
                        Mutation::delete(key)
                            .map_err(port_error)?
                            .if_unchanged(&previous),
                    ])
                    .map_err(port_error)?;
            }
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Root(std::path::PathBuf);
    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "claw-run-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("temporary root");
            Self(path)
        }
        fn open(&self) -> DurableStateStore {
            DurableStateStore::open(self.0.join("state.redb")).expect("state opens")
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn submission(principal: &str, key: &str, input: &str) -> RunSubmission {
        RunSubmission::new(
            "gateway",
            principal,
            key,
            &SessionId::new("session-one").expect("session"),
            input,
        )
        .expect("submission")
    }

    #[tokio::test]
    async fn cloud_delivery_statuses_are_receipt_bound_monotonic_and_never_resolve_unknown_claims()
    {
        let root = Root::new();
        let state = root.open();
        let run = state
            .admit_run(submission("status-owner", "one", "input"), Timestamp::EPOCH)
            .await
            .expect("input")
            .run;
        state
            .claim_run(run.id(), Timestamp::EPOCH)
            .await
            .expect("claim");
        let run = state
            .finish_run(
                run.id(),
                RunResult::new("completed", "reply".to_owned()).expect("reply"),
                Timestamp::EPOCH,
            )
            .await
            .expect("completed");
        let claim = state
            .claim_run_delivery(run.id(), "gateway", "status-owner", run.revision(), "reply")
            .await
            .expect("delivery")
            .expect("first claim");
        assert!(
            !state
                .record_run_delivery_status(
                    "gateway",
                    "status-owner",
                    "wamid.one",
                    "read",
                    Timestamp::from_millis(3),
                    None
                )
                .await
                .expect("unmatched callback ignored")
        );
        state
            .record_run_delivery_receipt(&claim, "gateway", "status-owner", 0, "reply", "wamid.one")
            .await
            .expect("known receipt");
        state
            .record_run_delivery_receipt(&claim, "gateway", "status-owner", 0, "reply", "wamid.one")
            .await
            .expect("identical receipt is idempotent");
        assert!(
            state
                .record_run_delivery_receipt(
                    &claim,
                    "gateway",
                    "status-owner",
                    1,
                    "reply",
                    "wamid.one"
                )
                .await
                .is_err(),
            "one Cloud ID cannot identify two segments"
        );
        state
            .finish_run_delivery(claim, "gateway", "status-owner", false)
            .await
            .expect("overall delivery unknown");
        for (label, millis, code) in [
            ("read", 30, None),
            ("sent", 10, None),
            ("delivered", 20, None),
            ("failed", 40, Some(131_000)),
            ("sent", 5, None),
        ] {
            assert!(
                state
                    .record_run_delivery_status(
                        "gateway",
                        "status-owner",
                        "wamid.one",
                        label,
                        Timestamp::from_millis(millis),
                        code
                    )
                    .await
                    .expect("provider fact")
            );
        }
        assert!(
            !state
                .record_run_delivery_status(
                    "gateway",
                    "other-owner",
                    "wamid.one",
                    "read",
                    Timestamp::from_millis(50),
                    None
                )
                .await
                .expect("other partition has no receipt")
        );
        assert!(
            state
                .record_run_delivery_status(
                    "gateway",
                    "status-owner",
                    "wamid.one",
                    "failed",
                    Timestamp::from_millis(40),
                    Some(131_001)
                )
                .await
                .is_err()
        );
        assert!(
            state
                .record_run_delivery_status(
                    "gateway",
                    "status-owner",
                    "wamid.one",
                    "delivered",
                    Timestamp::from_millis(-1),
                    None
                )
                .await
                .is_err()
        );
        let page = state
            .run_delivery_receipts(run.id(), "gateway", "status-owner", None)
            .await
            .expect("facts");
        assert_eq!(page.statuses.len(), 1);
        assert_eq!(page.statuses[0].reported_state(), "read");
        assert!(page.statuses[0].conflicting_reports());
        assert_eq!(page.statuses[0].sent_at_ms, Some(10));
        assert_eq!(page.statuses[0].failure_code, Some(131_000));
        assert_eq!(
            page.receipts.len(),
            1,
            "colliding receipt did not partially commit"
        );
        assert!(
            state
                .record_run_delivery_status(
                    "gateway",
                    "status-owner",
                    "wamid.one",
                    "failed",
                    Timestamp::from_millis(40),
                    Some(131_000)
                )
                .await
                .expect("identical failure callback")
        );
        assert_eq!(
            state
                .run_delivery_receipts(run.id(), "gateway", "status-owner", None)
                .await
                .expect("duplicate state")
                .statuses,
            page.statuses
        );
        let (sent_update, read_update) = tokio::join!(
            state.record_run_delivery_status(
                "gateway",
                "status-owner",
                "wamid.one",
                "sent",
                Timestamp::from_millis(11),
                None
            ),
            state.record_run_delivery_status(
                "gateway",
                "status-owner",
                "wamid.one",
                "read",
                Timestamp::from_millis(31),
                None
            ),
        );
        assert!(sent_update.expect("concurrent sent fact"));
        assert!(read_update.expect("concurrent read fact"));
        let page = state
            .run_delivery_receipts(run.id(), "gateway", "status-owner", None)
            .await
            .expect("merged concurrent facts");
        assert_eq!(page.statuses[0].sent_at_ms, Some(11));
        assert_eq!(page.statuses[0].read_at_ms, Some(31));
        assert_eq!(page.statuses[0].delivered_at_ms, Some(20));
        assert_eq!(page.statuses[0].failure_code, Some(131_000));
        state.shutdown().await;
        drop(state);
        let state = root.open();
        assert_eq!(
            state
                .run_delivery_receipts(run.id(), "gateway", "status-owner", None)
                .await
                .expect("reopened facts")
                .statuses,
            page.statuses
        );
        assert_eq!(
            state
                .load_run_delivery(run.id(), "gateway", "status-owner")
                .await
                .expect("claim")
                .expect("retained")
                .phase(),
            DeliveryPhase::OutcomeUnknown
        );
        assert!(
            state
                .claim_run_delivery(run.id(), "gateway", "status-owner", run.revision(), "reply")
                .await
                .expect("no replay")
                .is_none()
        );
        state.shutdown().await;
    }

    #[tokio::test]
    async fn delivery_segment_receipts_are_ordered_immutable_owned_and_survive_unknown_restart() {
        let root = Root::new();
        let state = root.open();
        let run = state
            .admit_run(
                submission("receipt-owner", "once", "input"),
                Timestamp::EPOCH,
            )
            .await
            .expect("admitted")
            .run;
        state
            .claim_run(run.id(), Timestamp::EPOCH)
            .await
            .expect("claimed execution");
        let run = state
            .finish_run(
                run.id(),
                RunResult::new("completed", "retained reply".to_owned()).expect("result"),
                Timestamp::EPOCH,
            )
            .await
            .expect("finished");
        let claim = state
            .claim_run_delivery(
                run.id(),
                "gateway",
                "receipt-owner",
                run.revision(),
                "retained reply",
            )
            .await
            .expect("delivery claim")
            .expect("first owner");
        assert!(
            state
                .record_run_delivery_receipt(&claim, "gateway", "other-owner", 0, "piece", "1")
                .await
                .is_err()
        );
        assert!(
            state
                .record_run_delivery_receipt(&claim, "gateway", "receipt-owner", 1, "piece", "2")
                .await
                .is_err()
        );
        assert!(
            state
                .record_run_delivery_receipt(
                    &claim,
                    "gateway",
                    "receipt-owner",
                    0,
                    "piece",
                    "bad-id"
                )
                .await
                .is_err()
        );
        for index in 0..34 {
            state
                .record_run_delivery_receipt(
                    &claim,
                    "gateway",
                    "receipt-owner",
                    index,
                    "private-segment-marker",
                    &(index + 1).to_string(),
                )
                .await
                .expect("remote acknowledgement");
        }
        for invalid in ["wamid.", "wamid.bad value", "wamid.\n"] {
            assert!(
                state
                    .record_run_delivery_receipt(
                        &claim,
                        "gateway",
                        "receipt-owner",
                        34,
                        "cloud segment",
                        invalid
                    )
                    .await
                    .is_err()
            );
        }
        state
            .record_run_delivery_receipt(
                &claim,
                "gateway",
                "receipt-owner",
                34,
                "cloud segment",
                "wamid.fixture-confirmed",
            )
            .await
            .expect("bounded Cloud receipt");
        state
            .record_run_delivery_receipt(
                &claim,
                "gateway",
                "receipt-owner",
                0,
                "private-segment-marker",
                "1",
            )
            .await
            .expect("same receipt is idempotent data write");
        assert!(
            state
                .record_run_delivery_receipt(
                    &claim,
                    "gateway",
                    "receipt-owner",
                    0,
                    "changed body",
                    "1"
                )
                .await
                .is_err()
        );
        assert!(
            state
                .record_run_delivery_receipt(
                    &claim,
                    "gateway",
                    "receipt-owner",
                    0,
                    "private-segment-marker",
                    "99"
                )
                .await
                .is_err()
        );
        let first = state
            .run_delivery_receipts(run.id(), "gateway", "receipt-owner", None)
            .await
            .expect("first metadata page");
        assert_eq!(first.receipts.len(), 32);
        assert_eq!(first.next_after, Some(31));
        assert!(
            !serde_json::to_string(&first.receipts)
                .expect("metadata")
                .contains("private-segment-marker")
        );
        assert!(
            state
                .run_delivery_receipts(run.id(), "gateway", "other-owner", None)
                .await
                .is_err()
        );
        state.shutdown().await;
        drop(state);
        let state = root.open();
        assert_eq!(
            state
                .load_run_delivery(run.id(), "gateway", "receipt-owner")
                .await
                .expect("retained claim")
                .expect("delivery")
                .phase(),
            DeliveryPhase::OutcomeUnknown
        );
        let second = state
            .run_delivery_receipts(run.id(), "gateway", "receipt-owner", first.next_after)
            .await
            .expect("second page after restart");
        assert_eq!(second.receipts.len(), 3);
        assert_eq!(second.next_after, None);
        assert_eq!(second.receipts[1].remote_message_id, "34");
        assert_eq!(
            second.receipts[2].remote_message_id,
            "wamid.fixture-confirmed"
        );
        assert!(
            state
                .record_run_delivery_receipt(&claim, "gateway", "receipt-owner", 34, "piece", "35")
                .await
                .is_err()
        );
        assert!(
            state
                .claim_run_delivery(
                    run.id(),
                    "gateway",
                    "receipt-owner",
                    run.revision(),
                    "retained reply"
                )
                .await
                .expect("cannot reacquire uncertain delivery")
                .is_none()
        );
        state.shutdown().await;
    }

    #[tokio::test]
    async fn discord_resume_checkpoints_are_cas_bound_and_expire_without_replaying_runs() {
        let root = Root::new();
        let state = root.open();
        let binding = "e".repeat(64);
        let other = "f".repeat(64);
        let run = state
            .admit_run(
                submission("discord-fixture", "once", "claimed input"),
                Timestamp::EPOCH,
            )
            .await
            .expect("durable input")
            .run;
        state
            .claim_run(run.id(), Timestamp::EPOCH)
            .await
            .expect("execution claim");
        let resume = DiscordResume::new(
            "private-session",
            7,
            Some("wss://gateway.discord.gg/?v=10&encoding=json"),
        )
        .expect("resume metadata");
        assert!(!format!("{resume:?}").contains("private-session"));
        assert_eq!(
            state
                .discord_resume(&binding, Timestamp::EPOCH)
                .await
                .expect("initial checkpoint"),
            (0, None)
        );
        assert_eq!(
            state
                .save_discord_resume(&binding, 0, Some(resume.clone()), Timestamp::EPOCH)
                .await
                .expect("initial save"),
            1
        );
        assert!(
            state
                .save_discord_resume(&binding, 0, None, Timestamp::EPOCH)
                .await
                .is_err()
        );
        let next = DiscordResume::new("private-session", 8, None).expect("new progress");
        let (first, second) = tokio::join!(
            state.save_discord_resume(&binding, 1, Some(next.clone()), Timestamp::EPOCH),
            state.save_discord_resume(&binding, 1, None, Timestamp::EPOCH)
        );
        assert_ne!(first.is_ok(), second.is_ok());
        let (revision, _) = state
            .discord_resume(&binding, Timestamp::EPOCH)
            .await
            .expect("winner");
        assert_eq!(
            state
                .discord_resume(&other, Timestamp::EPOCH)
                .await
                .expect("different binding"),
            (0, None)
        );
        let revision = state
            .save_discord_resume(
                &binding,
                revision,
                Some(next.clone()),
                Timestamp::from_millis(1),
            )
            .await
            .expect("settled snapshot");
        assert!(
            state
                .save_discord_resume(&binding, revision, Some(resume), Timestamp::from_millis(1))
                .await
                .is_err()
        );
        state.shutdown().await;
        drop(state);
        let state = root.open();
        assert_eq!(
            state
                .discord_resume(&binding, Timestamp::from_millis(2))
                .await
                .expect("reopened checkpoint"),
            (revision, Some(next))
        );
        let expired = state
            .discord_resume(&binding, Timestamp::from_millis(300_001))
            .await
            .expect("expired checkpoint");
        assert_eq!(expired, (revision + 1, None));
        assert!(
            state
                .claim_run(run.id(), Timestamp::from_millis(300_001))
                .await
                .is_err()
        );
        assert!(
            state
                .save_discord_resume(&binding, revision, None, Timestamp::from_millis(300_002))
                .await
                .is_err()
        );
        assert!(
            state
                .discord_resume("invalid", Timestamp::EPOCH)
                .await
                .is_err()
        );
        assert!(DiscordResume::new("session", -1, None).is_err());
        assert!(DiscordResume::new(" session ", 1, None).is_err());
        let candidate = DiscordResume::new("quota-session", 1, None).expect("candidate");
        for index in 0..255 {
            state
                .save_discord_resume(
                    &format!("{index:064x}"),
                    0,
                    Some(candidate.clone()),
                    Timestamp::from_millis(300_002),
                )
                .await
                .expect("retained binding capacity");
        }
        assert!(
            state
                .save_discord_resume(
                    &other,
                    0,
                    Some(candidate.clone()),
                    Timestamp::from_millis(300_002)
                )
                .await
                .is_err()
        );
        let revision = state
            .save_discord_resume(
                &binding,
                expired.0,
                Some(candidate),
                Timestamp::from_millis(300_002),
            )
            .await
            .expect("existing tombstone can be reused at capacity");
        assert_eq!(
            state
                .discord_resume(&binding, Timestamp::from_millis(300_001))
                .await
                .expect("clock rollback clears resume without losing revision"),
            (revision + 1, None)
        );
        state.shutdown().await;
    }

    #[tokio::test]
    async fn telegram_poll_cursors_are_bound_monotonic_atomic_and_persistent() {
        let root = Root::new();
        let state = root.open();
        let binding = "a".repeat(64);
        let other = "b".repeat(64);
        assert_eq!(
            state
                .telegram_poll_cursor(&binding, Timestamp::EPOCH)
                .await
                .expect("initial cursor"),
            0
        );
        state
            .advance_telegram_poll_cursor(&binding, 0, 11, Timestamp::EPOCH)
            .await
            .expect("settled batch");
        let (first, second) = tokio::join!(
            state.advance_telegram_poll_cursor(&binding, 11, 12, Timestamp::EPOCH),
            state.advance_telegram_poll_cursor(&binding, 11, 13, Timestamp::EPOCH)
        );
        assert_ne!(
            first.is_ok(),
            second.is_ok(),
            "only one concurrent batch can advance the observed cursor"
        );
        let offset = state
            .telegram_poll_cursor(&binding, Timestamp::EPOCH)
            .await
            .expect("winner");
        assert!(matches!(offset, 12 | 13));
        assert_eq!(
            state
                .telegram_poll_cursor(&other, Timestamp::EPOCH)
                .await
                .expect("different credential"),
            0
        );
        assert!(
            state
                .advance_telegram_poll_cursor(&binding, 0, 14, Timestamp::EPOCH)
                .await
                .is_err()
        );
        assert!(
            state
                .advance_telegram_poll_cursor(&binding, offset, offset - 1, Timestamp::EPOCH)
                .await
                .is_err()
        );
        assert!(
            state
                .advance_telegram_poll_cursor(&binding, -1, 14, Timestamp::EPOCH)
                .await
                .is_err()
        );
        assert!(
            state
                .telegram_poll_cursor("not-a-binding", Timestamp::EPOCH)
                .await
                .is_err()
        );
        state
            .advance_telegram_poll_cursor(&binding, offset, offset, Timestamp::EPOCH)
            .await
            .expect("idempotent current cursor");
        state.shutdown().await;
        drop(state);
        let reopened = root.open();
        assert_eq!(
            reopened
                .telegram_poll_cursor(&binding, Timestamp::EPOCH)
                .await
                .expect("persisted cursor"),
            offset
        );
        assert_eq!(
            reopened
                .telegram_poll_cursor(&other, Timestamp::EPOCH)
                .await
                .expect("isolated cursor"),
            0
        );
        reopened
            .advance_telegram_poll_cursor(&other, 0, 1, Timestamp::EPOCH)
            .await
            .expect("independent credential cursor");
        for index in 0..254 {
            reopened
                .advance_telegram_poll_cursor(&format!("{index:064x}"), 0, 1, Timestamp::EPOCH)
                .await
                .expect("bounded retained credential bindings");
        }
        let excess = "d".repeat(64);
        assert!(
            reopened
                .advance_telegram_poll_cursor(&excess, 0, 1, Timestamp::EPOCH)
                .await
                .is_err()
        );
        assert_eq!(
            reopened
                .telegram_poll_cursor(&excess, Timestamp::EPOCH)
                .await
                .expect("refused allocation leaves no cursor"),
            0
        );
        reopened
            .advance_telegram_poll_cursor(&other, 1, 2, Timestamp::EPOCH)
            .await
            .expect("existing binding remains writable at capacity");
        reopened.shutdown().await;
    }

    #[tokio::test]
    async fn telegram_poll_cursor_expiry_preserves_claims_and_allows_lower_new_update_ids() {
        let root = Root::new();
        let state = root.open();
        let binding = "c".repeat(64);
        let run = state
            .admit_run(
                submission("cursor-fixture", "one", "retained input"),
                Timestamp::EPOCH,
            )
            .await
            .expect("durable input")
            .run;
        state
            .claim_run(run.id(), Timestamp::EPOCH)
            .await
            .expect("durable execution claim");
        state
            .advance_telegram_poll_cursor(&binding, 0, 1_000_001, Timestamp::from_millis(10))
            .await
            .expect("initial cursor");
        assert_eq!(
            state
                .telegram_poll_cursor(&binding, Timestamp::from_millis(86_400_009))
                .await
                .expect("not expired"),
            1_000_001
        );
        assert_eq!(
            state
                .telegram_poll_cursor(&binding, Timestamp::from_millis(86_400_010))
                .await
                .expect("expired idle cursor"),
            0
        );
        assert!(
            state
                .claim_run(run.id(), Timestamp::from_millis(86_400_010))
                .await
                .is_err(),
            "cursor expiry must not authorize execution replay"
        );
        state
            .advance_telegram_poll_cursor(&binding, 0, 11, Timestamp::from_millis(86_400_011))
            .await
            .expect("new lower randomized update identity");
        assert_eq!(
            state
                .telegram_poll_cursor(&binding, Timestamp::from_millis(86_400_000))
                .await
                .expect("clock regression conservatively resets cursor"),
            0
        );
        assert!(
            state
                .telegram_poll_cursor(&binding, Timestamp::from_millis(-1))
                .await
                .is_err()
        );
        state.shutdown().await;
        drop(state);
        let reopened = root.open();
        assert_eq!(
            reopened
                .telegram_poll_cursor(&binding, Timestamp::from_millis(86_400_000))
                .await
                .expect("persisted cursor reset"),
            0
        );
        assert!(
            reopened
                .claim_run(run.id(), Timestamp::from_millis(86_400_000))
                .await
                .is_err()
        );
        reopened.shutdown().await;
    }

    #[test]
    fn run_process_exit_helper() {
        let Some(path) = std::env::var_os("GTA_CLAW_RUN_TEST_PATH") else {
            return;
        };
        let phase = std::env::var("GTA_CLAW_RUN_TEST_PHASE").expect("phase");
        let executor = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        executor.block_on(async move {
            let state = DurableStateStore::open(path).expect("child state");
            let run = state
                .admit_run(
                    submission("device", "interruption", "one external operation"),
                    Timestamp::from_millis(1),
                )
                .await
                .expect("admission")
                .run;
            if phase == "accepted" {
                std::process::exit(0);
            }
            state
                .claim_run(run.id(), Timestamp::from_millis(2))
                .await
                .expect("claim");
            if phase == "claimed" {
                std::process::exit(0);
            }
            let finished = state
                .finish_run(
                    run.id(),
                    RunResult::new("completed", "retained answer".to_owned()).expect("answer"),
                    Timestamp::from_millis(3),
                )
                .await
                .expect("finish");
            if phase == "finished" {
                std::process::exit(0);
            }
            if matches!(
                phase.as_str(),
                "delivery_claimed" | "delivery_receipt" | "delivery_confirmed" | "delivery_unknown"
            ) {
                let claim = state
                    .claim_run_delivery(
                        run.id(),
                        "gateway",
                        "device",
                        finished.revision(),
                        "retained answer",
                    )
                    .await
                    .expect("delivery committed before send")
                    .expect("only sender");
                if phase == "delivery_claimed" {
                    std::process::exit(0);
                }
                state
                    .record_run_delivery_receipt(
                        &claim,
                        "gateway",
                        "device",
                        0,
                        "retained answer",
                        "42",
                    )
                    .await
                    .expect("remote segment receipt persisted");
                if phase == "delivery_receipt" {
                    std::process::exit(0);
                }
                state
                    .finish_run_delivery(claim, "gateway", "device", phase == "delivery_confirmed")
                    .await
                    .expect("delivery receipt committed");
                std::process::exit(0);
            }
            assert_eq!(phase, "acknowledged");
            state
                .acknowledge_run(run.id(), "gateway", "device", finished.revision())
                .await
                .expect("ACK");
            std::process::exit(0);
        });
    }

    #[test]
    fn process_exit_at_each_run_boundary_never_replays_claimed_work_or_loses_unacked_results() {
        for phase in [
            "accepted",
            "claimed",
            "finished",
            "acknowledged",
            "delivery_claimed",
            "delivery_receipt",
            "delivery_confirmed",
            "delivery_unknown",
        ] {
            let root = Root::new();
            let mut child =
                std::process::Command::new(std::env::current_exe().expect("test executable"));
            child.env_clear();
            #[cfg(windows)]
            for name in ["SystemRoot", "SystemDrive", "WINDIR"] {
                if let Some(value) = std::env::var_os(name) {
                    child.env(name, value);
                }
            }
            let output = child
                .args([
                    "--exact",
                    "runs::tests::run_process_exit_helper",
                    "--nocapture",
                ])
                .env("GTA_CLAW_RUN_TEST_PATH", root.0.join("state.redb"))
                .env("GTA_CLAW_RUN_TEST_PHASE", phase)
                .output()
                .expect("isolated crash child");
            assert!(
                output.status.success(),
                "{phase}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let executor = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("recovery runtime");
            executor.block_on(async {
                let state = root.open();
                let replay = state
                    .admit_run(
                        submission("device", "interruption", "one external operation"),
                        Timestamp::from_millis(4),
                    )
                    .await
                    .expect("durable retry");
                assert!(replay.replayed);
                let expected = match phase {
                    "accepted" => RunPhase::Queued,
                    "claimed" => RunPhase::OutcomeUnknown,
                    _ => RunPhase::Finished,
                };
                assert_eq!(replay.run.phase(), expected, "{phase}");
                if phase != "accepted" {
                    assert!(
                        state
                            .claim_run(replay.run.id(), Timestamp::from_millis(5))
                            .await
                            .is_err()
                    );
                }
                let results = state
                    .pending_run_results("gateway", "device", None, None)
                    .await
                    .expect("result recovery");
                assert_eq!(
                    results.runs.len(),
                    usize::from(matches!(
                        phase,
                        "claimed"
                            | "finished"
                            | "delivery_claimed"
                            | "delivery_receipt"
                            | "delivery_unknown"
                    ))
                );
                if expected == RunPhase::Finished {
                    assert_eq!(
                        replay.run.result().expect("retained answer").text(),
                        "retained answer"
                    );
                }
                if phase.starts_with("delivery_") {
                    let receipts = state
                        .run_delivery_receipts(replay.run.id(), "gateway", "device", None)
                        .await
                        .expect("remote receipt survives direct process exit");
                    assert_eq!(
                        receipts.receipts.len(),
                        usize::from(phase != "delivery_claimed")
                    );
                    if let Some(receipt) = receipts.receipts.first() {
                        assert_eq!(receipt.remote_message_id, "42");
                        assert_eq!(receipt.content_bytes, "retained answer".len());
                        assert_eq!(receipt.segment, 0);
                    }
                    let delivery = state
                        .load_run_delivery(replay.run.id(), "gateway", "device")
                        .await
                        .expect("delivery recovery")
                        .expect("retained delivery");
                    assert_eq!(
                        delivery.phase(),
                        if phase == "delivery_confirmed" {
                            DeliveryPhase::Delivered
                        } else {
                            DeliveryPhase::OutcomeUnknown
                        }
                    );
                    assert!(
                        state
                            .claim_run_delivery(
                                replay.run.id(),
                                "gateway",
                                "device",
                                replay.run.revision(),
                                "retained answer"
                            )
                            .await
                            .expect("no repeated send")
                            .is_none()
                    );
                }
                state.shutdown().await;
            });
        }
    }

    #[tokio::test]
    async fn delivery_claims_are_once_only_and_confirmed_notifications_are_atomic() {
        let root = Root::new();
        let state = root.open();
        let run = state
            .admit_run(
                submission("device", "delivery", "hello"),
                Timestamp::from_millis(1),
            )
            .await
            .expect("durable input")
            .run;
        assert!(
            state
                .claim_run_delivery(run.id(), "gateway", "device", run.revision(), "reply")
                .await
                .is_err()
        );
        state
            .claim_run(run.id(), Timestamp::from_millis(2))
            .await
            .expect("execution claimed");
        let run = state
            .finish_run(
                run.id(),
                RunResult::new("completed", "reply".to_owned()).expect("result"),
                Timestamp::from_millis(3),
            )
            .await
            .expect("terminal result");
        assert!(
            state
                .claim_run_delivery(run.id(), "gateway", "other", run.revision(), "reply")
                .await
                .is_err()
        );
        assert!(
            state
                .claim_run_delivery(run.id(), "gateway", "device", run.revision() + 1, "reply")
                .await
                .is_err()
        );
        let (first, other) = tokio::join!(
            state.claim_run_delivery(run.id(), "gateway", "device", run.revision(), "reply"),
            state.claim_run_delivery(run.id(), "gateway", "device", run.revision(), "reply")
        );
        let first = first.expect("first contender");
        let other = other.expect("second contender");
        assert_ne!(first.is_some(), other.is_some());
        let claim = first.or(other).expect("one winning sender");
        assert_eq!(claim.phase(), DeliveryPhase::Sending);
        assert!(
            state
                .finish_run_delivery(claim.clone(), "gateway", "other", true)
                .await
                .is_err()
        );
        let completed = state
            .finish_run_delivery(claim.clone(), "gateway", "device", true)
            .await
            .expect("confirmed transport receipt");
        assert_eq!(completed.phase(), DeliveryPhase::Delivered);
        assert!(
            state
                .pending_run_results("gateway", "device", None, None)
                .await
                .expect("outbox")
                .runs
                .is_empty()
        );
        assert!(
            state
                .load_run(run.id(), "gateway", "device")
                .await
                .expect("dedupe history")
                .is_some()
        );
        assert!(
            state
                .finish_run_delivery(claim, "gateway", "device", false)
                .await
                .is_err()
        );
        state.shutdown().await;
        drop(state);
        let state = root.open();
        assert_eq!(
            state
                .load_run_delivery(run.id(), "gateway", "device")
                .await
                .expect("delivery after restart")
                .expect("record")
                .phase(),
            DeliveryPhase::Delivered
        );
        assert!(
            state
                .claim_run_delivery(run.id(), "gateway", "device", run.revision(), "reply")
                .await
                .expect("duplicate only lookup")
                .is_none()
        );
        assert!(
            state
                .load_run_delivery(run.id(), "gateway", "other")
                .await
                .expect("other owner cannot read")
                .is_none()
        );
        state.shutdown().await;
    }

    #[tokio::test]
    async fn interrupted_or_failed_delivery_retains_result_without_resending_after_reopen() {
        for settle_failure in [false, true] {
            let root = Root::new();
            let state = root.open();
            let run = state
                .admit_run(
                    submission("device", "delivery-unknown", "hello"),
                    Timestamp::from_millis(1),
                )
                .await
                .expect("durable input")
                .run;
            state
                .claim_run(run.id(), Timestamp::from_millis(2))
                .await
                .expect("claimed");
            let run = state
                .finish_run(
                    run.id(),
                    RunResult::new("completed", "complete reply".to_owned()).expect("reply"),
                    Timestamp::from_millis(3),
                )
                .await
                .expect("finished");
            let claim = state
                .claim_run_delivery(
                    run.id(),
                    "gateway",
                    "device",
                    run.revision(),
                    "complete reply",
                )
                .await
                .expect("delivery claim commit")
                .expect("only sender");
            if settle_failure {
                state
                    .finish_run_delivery(claim, "gateway", "device", false)
                    .await
                    .expect("record unconfirmed send");
            }
            state.shutdown().await;
            drop(state);
            let state = root.open();
            let delivery = state
                .load_run_delivery(run.id(), "gateway", "device")
                .await
                .expect("recovered delivery")
                .expect("retained claim");
            assert_eq!(delivery.phase(), DeliveryPhase::OutcomeUnknown);
            assert!(
                state
                    .claim_run_delivery(
                        run.id(),
                        "gateway",
                        "device",
                        run.revision(),
                        "complete reply"
                    )
                    .await
                    .expect("no automatic send")
                    .is_none()
            );
            assert!(
                state
                    .claim_run_delivery(
                        run.id(),
                        "gateway",
                        "device",
                        run.revision(),
                        "changed reply"
                    )
                    .await
                    .is_err()
            );
            assert_eq!(
                state
                    .pending_run_results("gateway", "device", None, None)
                    .await
                    .expect("retained result notification")
                    .runs
                    .len(),
                1
            );
            assert!(
                state
                    .claim_run(run.id(), Timestamp::from_millis(4))
                    .await
                    .is_err()
            );
            state.shutdown().await;
        }
    }

    #[tokio::test]
    async fn authenticated_channel_reservation_is_atomic_and_never_adopts_legacy_history() {
        let root = Root::new();
        let state = root.open();
        let session = SessionId::new("channel-owner-fixture").expect("session");
        let (first, other) = tokio::join!(
            state.reserve_authenticated_session("channel", "actor-one", &session),
            state.reserve_authenticated_session("channel", "actor-two", &session)
        );
        assert_ne!(first.is_ok(), other.is_ok());
        let owner = if first.is_ok() {
            "actor-one"
        } else {
            "actor-two"
        };
        assert!(
            state
                .owns_run_session("channel", owner, &session)
                .await
                .expect("stored owner")
        );
        assert!(state.reserve_legacy_session(&session).await.is_err());
        let historical = SessionId::new("unowned-historical-channel").expect("legacy session");
        state
            .save_context(&historical, serde_json::json!({"retain":true}))
            .await
            .expect("existing unowned checkpoint");
        assert!(
            state
                .reserve_authenticated_session("channel", owner, &historical)
                .await
                .is_err()
        );
        assert_eq!(
            state
                .load_context::<serde_json::Value>(&historical)
                .await
                .expect("untouched historical record"),
            Some(serde_json::json!({"retain":true}))
        );
        state
            .remove_session(&session)
            .await
            .expect("reset current pointer");
        state.shutdown().await;
        drop(state);
        let state = root.open();
        assert!(
            state
                .owns_run_session("channel", owner, &session)
                .await
                .expect("owner survives reset and reopen")
        );
        assert!(
            state
                .reserve_authenticated_session("gateway", owner, &session)
                .await
                .is_err()
        );
        state.shutdown().await;
    }

    #[tokio::test]
    async fn session_ownership_is_atomic_with_admission_and_survives_reset_and_restart() {
        let root = Root::new();
        let state = root.open();
        let session = SessionId::new("session-one").expect("session");
        let (first, second) = tokio::join!(
            state.admit_run(
                submission("device-one", "first", "one"),
                Timestamp::from_millis(1)
            ),
            state.admit_run(
                submission("device-two", "second", "two"),
                Timestamp::from_millis(1)
            )
        );
        assert_ne!(first.is_ok(), second.is_ok());
        let owner = if first.is_ok() {
            "device-one"
        } else {
            "device-two"
        };
        let other = if first.is_ok() {
            "device-two"
        } else {
            "device-one"
        };
        assert!(
            state
                .owns_run_session("gateway", owner, &session)
                .await
                .expect("owner")
        );
        assert!(
            !state
                .owns_run_session("gateway", other, &session)
                .await
                .expect("other principal")
        );
        assert!(
            !state
                .owns_run_session("http", owner, &session)
                .await
                .expect("other ingress")
        );
        state.remove_session(&session).await.expect("reset");
        state.shutdown().await;
        drop(state);
        let state = root.open();
        assert!(
            state
                .owns_run_session("gateway", owner, &session)
                .await
                .expect("retained owner")
        );
        assert!(
            state
                .admit_run(
                    submission(other, "new-key", "must not gain access"),
                    Timestamp::from_millis(2)
                )
                .await
                .is_err()
        );
        state.shutdown().await;
    }

    #[tokio::test]
    async fn legacy_and_authenticated_admission_cannot_race_into_the_same_session() {
        let root = Root::new();
        let state = root.open();
        let session = SessionId::new("session-one").expect("session");
        let (legacy, gateway) = tokio::join!(
            state.reserve_legacy_session(&session),
            state.admit_run(
                submission("device", "race", "verified input"),
                Timestamp::from_millis(1)
            )
        );
        assert_ne!(legacy.is_ok(), gateway.is_ok());
        assert_eq!(
            state
                .owns_run_session("gateway", "device", &session)
                .await
                .expect("ownership"),
            gateway.is_ok()
        );
        assert_eq!(
            state.reserve_legacy_session(&session).await.is_ok(),
            legacy.is_ok()
        );
        state.shutdown().await;
    }

    #[tokio::test]
    async fn unowned_historical_session_cannot_be_claimed_by_guessing_its_name() {
        let root = Root::new();
        let state = root.open();
        let session = SessionId::new("session-one").expect("session");
        state
            .save_context(
                &session,
                serde_json::json!({"existing": "private historical context"}),
            )
            .await
            .expect("historical state");
        assert!(
            state
                .admit_run(
                    submission("first-guesser", "guess", "claim"),
                    Timestamp::from_millis(1)
                )
                .await
                .is_err()
        );
        assert!(
            !state
                .owns_run_session("gateway", "first-guesser", &session)
                .await
                .expect("unowned")
        );
        let preserved: serde_json::Value = state
            .load_context(&session)
            .await
            .expect("read context")
            .expect("preserved");
        assert_eq!(preserved["existing"], "private historical context");
        state.shutdown().await;
    }

    #[tokio::test]
    async fn run_retention_quota_refuses_new_work_but_keeps_duplicates_queryable() {
        let root = Root::new();
        let state = root.open();
        let accepted = state
            .admit_run(
                submission("device", "existing", "retained input"),
                Timestamp::from_millis(1),
            )
            .await
            .expect("existing run");
        state
            .operation(|database| {
                database
                    .commit(vec![
                        Mutation::put(COUNT_KEY, &MAX_RETAINED_RUNS).map_err(port_error)?,
                    ])
                    .map_err(port_error)
            })
            .await
            .expect("quota fixture");
        assert!(
            state
                .admit_run(
                    submission("device", "new-key", "new input"),
                    Timestamp::from_millis(2)
                )
                .await
                .is_err()
        );
        let duplicate = state
            .admit_run(
                submission("device", "existing", "retained input"),
                Timestamp::from_millis(3),
            )
            .await
            .expect("retained retry");
        assert!(duplicate.replayed);
        assert_eq!(duplicate.run.id(), accepted.run.id());
        state.shutdown().await;
    }

    #[tokio::test]
    async fn durable_admission_replays_exact_input_across_reopen_without_reclaiming_execution() {
        let root = Root::new();
        let state = root.open();
        let accepted = state
            .admit_run(
                submission("device-one", "key-one", "hello"),
                Timestamp::from_millis(1),
            )
            .await
            .expect("admission");
        assert!(!accepted.replayed);
        let id = accepted.run.id().to_owned();
        state
            .claim_run(&id, Timestamp::from_millis(2))
            .await
            .expect("single claim");
        assert!(
            state
                .claim_run(&id, Timestamp::from_millis(2))
                .await
                .is_err()
        );
        state
            .bind_run_turn(&id, TurnId::FIRST)
            .await
            .expect("turn binding");
        let result = RunResult::new("completed", "answer".to_owned()).expect("result");
        let finished = state
            .finish_run(&id, result.clone(), Timestamp::from_millis(3))
            .await
            .expect("result and outbox commit");
        state
            .finish_run(&id, result, Timestamp::from_millis(4))
            .await
            .expect("same result retry");
        state.shutdown().await;
        drop(state);
        let state = root.open();
        let replayed = state
            .admit_run(
                submission("device-one", "key-one", "hello"),
                Timestamp::from_millis(5),
            )
            .await
            .expect("durable replay");
        assert!(replayed.replayed);
        assert_eq!(replayed.run.id(), id);
        assert_eq!(replayed.run.result().expect("answer").text(), "answer");
        assert!(
            state
                .claim_run(&id, Timestamp::from_millis(6))
                .await
                .is_err()
        );
        assert!(
            state
                .admit_run(
                    submission("device-one", "key-one", "different"),
                    Timestamp::from_millis(7)
                )
                .await
                .is_err()
        );
        assert!(
            state
                .load_run(&id, "gateway", "other-device")
                .await
                .expect("isolated query")
                .is_none()
        );
        assert!(
            state
                .acknowledge_run(&id, "gateway", "other-device", finished.revision())
                .await
                .is_err()
        );
        assert!(
            state
                .acknowledge_run(&id, "gateway", "device-one", finished.revision() - 1)
                .await
                .is_err()
        );
        let pending = state
            .pending_run_results("gateway", "device-one", None, None)
            .await
            .expect("durable outbox");
        assert_eq!(pending.runs.len(), 1);
        assert_eq!(pending.runs[0].id(), id);
        assert!(
            state
                .pending_run_results("gateway", "other-device", None, None)
                .await
                .expect("isolated outbox")
                .runs
                .is_empty()
        );
        state
            .acknowledge_run(&id, "gateway", "device-one", finished.revision())
            .await
            .expect("correct acknowledgement");
        state
            .acknowledge_run(&id, "gateway", "device-one", finished.revision())
            .await
            .expect("idempotent acknowledgement");
        assert!(
            state
                .load_run(&id, "gateway", "device-one")
                .await
                .expect("retained run")
                .is_some()
        );
        assert!(
            state
                .pending_run_results("gateway", "device-one", None, None)
                .await
                .expect("acknowledged outbox")
                .runs
                .is_empty()
        );
        state.shutdown().await;
    }

    #[tokio::test]
    async fn interrupted_execution_becomes_unknown_but_unclaimed_input_stays_queued() {
        let root = Root::new();
        let state = root.open();
        let started = state
            .admit_run(
                submission("device", "started", "do work"),
                Timestamp::from_millis(1),
            )
            .await
            .expect("started admission")
            .run;
        let queued = state
            .admit_run(
                submission("device", "queued", "later work"),
                Timestamp::from_millis(1),
            )
            .await
            .expect("queued admission")
            .run;
        let session = SessionId::new("session-one").expect("session");
        assert_eq!(
            state
                .active_runs("gateway", "device", &session, None)
                .await
                .expect("active inbox")
                .runs
                .len(),
            2
        );
        assert!(
            state
                .active_runs("gateway", "other", &session, None)
                .await
                .expect("foreign inbox")
                .runs
                .is_empty()
        );
        state
            .claim_run(started.id(), Timestamp::from_millis(2))
            .await
            .expect("claim");
        state.shutdown().await;
        drop(state);
        let state = root.open();
        let unknown = state
            .load_run(started.id(), "gateway", "device")
            .await
            .expect("recovered")
            .expect("run");
        assert_eq!(unknown.phase(), RunPhase::OutcomeUnknown);
        assert_eq!(
            unknown.result().expect("recovery result").status(),
            "outcome_unknown"
        );
        assert!(
            state
                .claim_run(started.id(), Timestamp::from_millis(3))
                .await
                .is_err()
        );
        assert_eq!(
            state
                .load_run(queued.id(), "gateway", "device")
                .await
                .expect("queued")
                .expect("run")
                .phase(),
            RunPhase::Queued
        );
        let active = state
            .active_runs("gateway", "device", &session, None)
            .await
            .expect("recovered active inbox");
        assert_eq!(active.runs.len(), 1);
        assert_eq!(active.runs[0].id(), queued.id());
        state.shutdown().await;
    }

    #[tokio::test]
    async fn run_cancellation_before_claim_or_binding_is_retained_without_touching_another_run() {
        let root = Root::new();
        let state = root.open();
        let queued = state
            .admit_run(
                submission("device", "queued-cancel", "queued"),
                Timestamp::from_millis(1),
            )
            .await
            .expect("queued")
            .run;
        let cancelled = state
            .cancel_run(queued.id(), "gateway", "device", Timestamp::from_millis(2))
            .await
            .expect("queued cancellation");
        assert_eq!(cancelled.result().expect("terminal").status(), "cancelled");
        assert!(
            state
                .claim_run(queued.id(), Timestamp::from_millis(3))
                .await
                .is_err()
        );
        let executing = state
            .admit_run(
                submission("device", "executing-cancel", "running"),
                Timestamp::from_millis(4),
            )
            .await
            .expect("accepted")
            .run;
        state
            .claim_run(executing.id(), Timestamp::from_millis(5))
            .await
            .expect("claim");
        state
            .cancel_run(
                executing.id(),
                "gateway",
                "device",
                Timestamp::from_millis(6),
            )
            .await
            .expect("cancel before binding");
        let bound = state
            .bind_run_turn(executing.id(), TurnId::FIRST)
            .await
            .expect("bind after cancellation");
        assert!(bound.cancellation_requested());
        assert!(
            state
                .cancel_run(
                    executing.id(),
                    "gateway",
                    "other",
                    Timestamp::from_millis(7)
                )
                .await
                .is_err()
        );
        assert_eq!(
            state
                .load_run(queued.id(), "gateway", "device")
                .await
                .expect("old run")
                .expect("present")
                .revision(),
            cancelled.revision()
        );
        state.shutdown().await;
    }

    #[tokio::test]
    async fn concurrent_cancellation_and_finalization_keep_one_terminal_result_and_outbox() {
        let root = Root::new();
        let state = root.open();
        let run = state
            .admit_run(
                submission("device", "cancel-finish", "one call"),
                Timestamp::from_millis(1),
            )
            .await
            .expect("run")
            .run;
        state
            .claim_run(run.id(), Timestamp::from_millis(2))
            .await
            .expect("claim");
        let (finished, cancelled) = tokio::join!(
            state.finish_run(
                run.id(),
                RunResult::new("completed", "complete".to_owned()).expect("result"),
                Timestamp::from_millis(3)
            ),
            state.cancel_run(run.id(), "gateway", "device", Timestamp::from_millis(3)),
        );
        let finished = finished.expect("terminal publication");
        cancelled.expect("concurrent cancellation");
        let retained = state
            .load_run(run.id(), "gateway", "device")
            .await
            .expect("load")
            .expect("retained");
        assert_eq!(retained.result(), finished.result());
        assert_eq!(
            state
                .pending_run_results("gateway", "device", None, None)
                .await
                .expect("outbox")
                .runs
                .len(),
            1
        );
        state.shutdown().await;
    }

    #[tokio::test]
    async fn concurrent_duplicate_admission_and_claim_have_one_winner() {
        let root = Root::new();
        let state = root.open();
        let input = submission("device", "key", "same input");
        let (first, second) = tokio::join!(
            state.admit_run(input.clone(), Timestamp::from_millis(1)),
            state.admit_run(input, Timestamp::from_millis(1))
        );
        let first = first.expect("first admission");
        let second = second.expect("second admission");
        assert_ne!(first.replayed, second.replayed);
        assert_eq!(first.run.id(), second.run.id());
        let (first_claim, second_claim) = tokio::join!(
            state.claim_run(first.run.id(), Timestamp::from_millis(2)),
            state.claim_run(second.run.id(), Timestamp::from_millis(2))
        );
        assert_ne!(first_claim.is_ok(), second_claim.is_ok());
        assert!(
            state
                .admit_run(
                    submission("other-device", "key", "same input"),
                    Timestamp::from_millis(3)
                )
                .await
                .is_err()
        );
        let own_session = RunSubmission::new(
            "gateway",
            "other-device",
            "key",
            &SessionId::new("other-session").expect("separate session"),
            "same input",
        )
        .expect("other principal submission");
        let another = state
            .admit_run(own_session, Timestamp::from_millis(3))
            .await
            .expect("other principal owns its session");
        assert_ne!(another.run.id(), first.run.id());
        state.shutdown().await;
    }
}

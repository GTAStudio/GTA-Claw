//! Persistence port and an in-memory adapter.
//!
//! The port is deliberately narrow: sessions and records in, sessions and
//! records out. A durable adapter lives outside this crate, so nothing here
//! depends on a database, a schema migration, or a file format.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::retrieval::{MemoryRecord, RecordError};
use crate::session::{Session, SessionId};
use crate::vector::RecordId;

/// Persistence port for sessions and memory records.
pub trait MemoryStore {
    /// Inserts or replaces one session.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SessionCapacityExceeded`] when storing a session
    /// that is not already present would take the adapter past its session
    /// bound, or [`StoreError::Backend`] when the underlying store is
    /// unavailable or rejects the write.
    fn put_session(&mut self, session: &Session) -> Result<(), StoreError>;

    /// Loads one session.
    ///
    /// A missing session is `Ok(None)`, never an error.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] when the underlying store is
    /// unavailable or the stored representation cannot be decoded.
    fn get_session(&self, id: &SessionId) -> Result<Option<Session>, StoreError>;

    /// Lists every stored session identifier in ascending order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] when the underlying store is
    /// unavailable or the listing cannot be read to completion.
    fn list_sessions(&self) -> Result<Vec<SessionId>, StoreError>;

    /// Deletes one session and every record that belongs to it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] when the underlying store is
    /// unavailable or the session and its records cannot be removed together.
    fn delete_session(&mut self, id: &SessionId) -> Result<bool, StoreError>;

    /// Inserts or replaces one memory record.
    ///
    /// # Errors
    ///
    /// Returns a record-validation error for an empty or oversized body or
    /// oversized tag set,
    /// [`StoreError::RecordCapacityExceeded`] when storing a record that is
    /// not already present would take the adapter past its record bound, or
    /// [`StoreError::Backend`] when the underlying store is unavailable.
    fn put_record(&mut self, record: MemoryRecord) -> Result<(), StoreError>;

    /// Loads one memory record.
    ///
    /// A missing record is `Ok(None)`, never an error.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] when the underlying store is
    /// unavailable or the stored representation cannot be decoded.
    fn get_record(&self, id: &RecordId) -> Result<Option<MemoryRecord>, StoreError>;

    /// Lists records, optionally restricted to one session, in identifier
    /// order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] when the underlying store is
    /// unavailable or the listing cannot be read to completion.
    fn records(&self, session: Option<&SessionId>) -> Result<Vec<MemoryRecord>, StoreError>;

    /// Deletes one record, reporting whether it existed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] when the underlying store is
    /// unavailable or the removal cannot be applied.
    fn delete_record(&mut self, id: &RecordId) -> Result<bool, StoreError>;
}

/// Bounded in-memory adapter.
///
/// The capacity bound is a safety property, not an optimization: an agent
/// that can append memory without limit is an agent that can exhaust the
/// host. Exceeding the bound is an error, never a silent eviction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryMemoryStore {
    sessions: BTreeMap<SessionId, Session>,
    records: BTreeMap<RecordId, MemoryRecord>,
    max_sessions: usize,
    max_records: usize,
}

impl Default for InMemoryMemoryStore {
    fn default() -> Self {
        Self::new(1_000, 100_000)
    }
}

impl InMemoryMemoryStore {
    /// Creates an empty store with explicit capacity bounds.
    #[must_use]
    pub const fn new(max_sessions: usize, max_records: usize) -> Self {
        Self {
            sessions: BTreeMap::new(),
            records: BTreeMap::new(),
            max_sessions,
            max_records,
        }
    }

    /// Returns the number of stored sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns the number of stored records.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

impl MemoryStore for InMemoryMemoryStore {
    fn put_session(&mut self, session: &Session) -> Result<(), StoreError> {
        if !self.sessions.contains_key(session.id()) && self.sessions.len() >= self.max_sessions {
            return Err(StoreError::SessionCapacityExceeded);
        }
        self.sessions.insert(session.id().clone(), session.clone());
        Ok(())
    }

    fn get_session(&self, id: &SessionId) -> Result<Option<Session>, StoreError> {
        Ok(self.sessions.get(id).cloned())
    }

    fn list_sessions(&self) -> Result<Vec<SessionId>, StoreError> {
        Ok(self.sessions.keys().cloned().collect())
    }

    fn delete_session(&mut self, id: &SessionId) -> Result<bool, StoreError> {
        let removed = self.sessions.remove(id).is_some();
        self.records.retain(|_, record| record.session != *id);
        Ok(removed)
    }

    fn put_record(&mut self, record: MemoryRecord) -> Result<(), StoreError> {
        record.validate().map_err(StoreError::from)?;
        if !self.records.contains_key(&record.id) && self.records.len() >= self.max_records {
            return Err(StoreError::RecordCapacityExceeded);
        }
        self.records.insert(record.id.clone(), record);
        Ok(())
    }

    fn get_record(&self, id: &RecordId) -> Result<Option<MemoryRecord>, StoreError> {
        Ok(self.records.get(id).cloned())
    }

    fn records(&self, session: Option<&SessionId>) -> Result<Vec<MemoryRecord>, StoreError> {
        Ok(self
            .records
            .values()
            .filter(|record| session.is_none_or(|wanted| record.session == *wanted))
            .cloned()
            .collect())
    }

    fn delete_record(&mut self, id: &RecordId) -> Result<bool, StoreError> {
        Ok(self.records.remove(id).is_some())
    }
}

/// A rejected persistence operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// The session capacity bound was reached.
    SessionCapacityExceeded,
    /// The record capacity bound was reached.
    RecordCapacityExceeded,
    /// A record body was empty.
    EmptyRecord,
    /// A record body exceeded the processing bound.
    RecordTooLarge,
    /// A record had too many tags.
    TooManyTags,
    /// One record tag exceeded its byte bound.
    TagTooLong,
    /// The adapter failed for an implementation-specific reason.
    Backend,
}

impl Display for StoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SessionCapacityExceeded => "session capacity exceeded",
            Self::RecordCapacityExceeded => "record capacity exceeded",
            Self::EmptyRecord => "record body must not be empty",
            Self::RecordTooLarge => "record body exceeds the maximum size",
            Self::TooManyTags => "record has too many tags",
            Self::TagTooLong => "record tag exceeds the maximum size",
            Self::Backend => "memory store backend failed",
        };
        formatter.write_str(message)
    }
}

impl Error for StoreError {}

impl From<RecordError> for StoreError {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::EmptyText => Self::EmptyRecord,
            RecordError::TextTooLong => Self::RecordTooLarge,
            RecordError::TooManyTags => Self::TooManyTags,
            RecordError::TagTooLong => Self::TagTooLong,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retrieval::RecordKind;
    use crate::session::Role;
    use std::collections::BTreeSet;

    fn session_id(value: &str) -> SessionId {
        SessionId::new(value).expect("valid session identifier")
    }

    fn record(id: &str, session: &str, text: &str) -> MemoryRecord {
        MemoryRecord {
            id: RecordId::new(id).expect("valid record identifier"),
            session: session_id(session),
            kind: RecordKind::Note,
            text: text.to_owned(),
            unix_millis: 1,
            tags: BTreeSet::new(),
        }
    }

    #[test]
    fn a_stored_session_round_trips_with_its_messages() {
        let mut store = InMemoryMemoryStore::default();
        let mut session = Session::new(session_id("alpha"));
        session.append(Role::System, "rules", 1).expect("appended");
        session.append(Role::User, "hello", 2).expect("appended");

        store.put_session(&session).expect("stored");
        let loaded = store
            .get_session(&session_id("alpha"))
            .expect("no backend failure")
            .expect("session present");
        assert_eq!(loaded, session);
        assert_eq!(loaded.messages().len(), 2);
        assert_eq!(loaded.messages()[1].content, "hello");
        assert_eq!(store.list_sessions(), Ok(vec![session_id("alpha")]));
    }

    #[test]
    fn a_missing_session_is_absent_rather_than_an_error() {
        let store = InMemoryMemoryStore::default();
        assert_eq!(store.get_session(&session_id("nope")), Ok(None));
        assert_eq!(store.list_sessions(), Ok(Vec::new()));
    }

    #[test]
    fn deleting_a_session_removes_its_records_only() {
        let mut store = InMemoryMemoryStore::default();
        store
            .put_session(&Session::new(session_id("a")))
            .expect("ok");
        store
            .put_session(&Session::new(session_id("b")))
            .expect("ok");
        store.put_record(record("r1", "a", "first")).expect("ok");
        store.put_record(record("r2", "a", "second")).expect("ok");
        store.put_record(record("r3", "b", "third")).expect("ok");

        assert!(store.delete_session(&session_id("a")).expect("ok"));
        assert!(!store.delete_session(&session_id("a")).expect("ok"));
        assert_eq!(store.session_count(), 1);
        assert_eq!(store.record_count(), 1);
        let remaining = store.records(None).expect("ok");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id.as_str(), "r3");
    }

    #[test]
    fn records_can_be_listed_per_session_in_identifier_order() {
        let mut store = InMemoryMemoryStore::default();
        store.put_record(record("z", "a", "one")).expect("ok");
        store.put_record(record("m", "a", "two")).expect("ok");
        store.put_record(record("c", "b", "three")).expect("ok");

        let scoped = store.records(Some(&session_id("a"))).expect("ok");
        assert_eq!(
            scoped
                .iter()
                .map(|record| record.id.as_str())
                .collect::<Vec<_>>(),
            vec!["m", "z"]
        );
        let all = store.records(None).expect("ok");
        assert_eq!(
            all.iter()
                .map(|record| record.id.as_str())
                .collect::<Vec<_>>(),
            vec!["c", "m", "z"]
        );
    }

    #[test]
    fn capacity_bounds_fail_loudly_and_replacement_still_works() {
        let mut store = InMemoryMemoryStore::new(1, 2);
        store
            .put_session(&Session::new(session_id("a")))
            .expect("ok");
        assert_eq!(
            store.put_session(&Session::new(session_id("b"))),
            Err(StoreError::SessionCapacityExceeded)
        );
        // Replacing an existing session is not a new allocation.
        store
            .put_session(&Session::new(session_id("a")))
            .expect("ok");

        store.put_record(record("r1", "a", "one")).expect("ok");
        store.put_record(record("r2", "a", "two")).expect("ok");
        assert_eq!(
            store.put_record(record("r3", "a", "three")),
            Err(StoreError::RecordCapacityExceeded)
        );
        store.put_record(record("r1", "a", "replaced")).expect("ok");
        assert_eq!(
            store
                .get_record(&RecordId::new("r1").expect("valid identifier"))
                .expect("ok")
                .expect("record present")
                .text,
            "replaced"
        );
    }

    #[test]
    fn empty_records_are_refused_and_deletion_reports_existence() {
        let mut store = InMemoryMemoryStore::default();
        assert_eq!(
            store.put_record(record("r1", "a", "")),
            Err(StoreError::EmptyRecord)
        );
        store.put_record(record("r1", "a", "body")).expect("ok");
        let id = RecordId::new("r1").expect("valid identifier");
        assert_eq!(store.delete_record(&id), Ok(true));
        assert_eq!(store.delete_record(&id), Ok(false));
        assert_eq!(store.get_record(&id), Ok(None));
    }
}

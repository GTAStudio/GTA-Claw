//! Durable-state stand-ins: sessions, turns and origin-bound credentials.
//!
//! Both stores are transactional in the way the real ones must be. A
//! transaction stages its work in a local buffer and only touches the shared
//! map on commit, so a turn that fails part way through leaves nothing behind.
//! `Drop` rolls back, which is why the staging buffer is dropped rather than
//! applied when a transaction is abandoned.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use claw_application::composition::CredentialRequest;
use claw_application::composition::{
    BoxFuture, CredentialLease, CredentialName, Grant, PersistencePort, PersistenceTransaction,
    ResolvedEndpoint, SecretStorePort, SecretTransaction, SessionRecord, SubsystemError,
    TurnRecord, well_known,
};
use claw_domain::SessionId;
use secrecy::{ExposeSecret, SecretString};

/// The rows one persistence store holds.
#[derive(Debug, Default)]
struct SessionTable {
    sessions: BTreeMap<String, SessionRecord>,
    turns: Vec<TurnRecord>,
}

/// Sessions and turns held in memory.
#[derive(Debug, Default)]
pub struct MemoryPersistence {
    table: Arc<Mutex<SessionTable>>,
    commits: Arc<AtomicU64>,
    rollbacks: Arc<AtomicU64>,
}

impl MemoryPersistence {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every turn recorded for `session`, in the order they were
    /// appended.
    #[must_use]
    pub fn turns_for(&self, session: &SessionId) -> Vec<TurnRecord> {
        self.table
            .lock()
            .expect("uncontended")
            .turns
            .iter()
            .filter(|turn| turn.session() == session)
            .cloned()
            .collect()
    }

    /// Returns how many transactions were committed.
    #[must_use]
    pub fn commits(&self) -> u64 {
        self.commits.load(Ordering::SeqCst)
    }

    /// Returns how many transactions were rolled back.
    #[must_use]
    pub fn rollbacks(&self) -> u64 {
        self.rollbacks.load(Ordering::SeqCst)
    }
}

/// A staged persistence edit.
#[derive(Debug)]
pub struct MemoryPersistenceTransaction {
    table: Arc<Mutex<SessionTable>>,
    commits: Arc<AtomicU64>,
    rollbacks: Arc<AtomicU64>,
    sessions: Vec<SessionRecord>,
    turns: Vec<TurnRecord>,
    settled: bool,
}

impl Drop for MemoryPersistenceTransaction {
    fn drop(&mut self) {
        if !self.settled {
            self.rollbacks.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl PersistencePort for MemoryPersistence {
    fn load_session(
        &self,
        id: &SessionId,
    ) -> BoxFuture<'_, Result<Option<SessionRecord>, SubsystemError>> {
        let key = id.as_str().to_owned();

        Box::pin(async move {
            Ok(self
                .table
                .lock()
                .expect("uncontended")
                .sessions
                .get(&key)
                .cloned())
        })
    }

    fn begin(&self) -> BoxFuture<'_, Result<Box<dyn PersistenceTransaction>, SubsystemError>> {
        Box::pin(async move {
            Ok(Box::new(MemoryPersistenceTransaction {
                table: Arc::clone(&self.table),
                commits: Arc::clone(&self.commits),
                rollbacks: Arc::clone(&self.rollbacks),
                sessions: Vec::new(),
                turns: Vec::new(),
                settled: false,
            }) as Box<dyn PersistenceTransaction>)
        })
    }
}

impl PersistenceTransaction for MemoryPersistenceTransaction {
    fn upsert_session(&mut self, record: SessionRecord) -> Result<(), SubsystemError> {
        let stored = self
            .table
            .lock()
            .expect("uncontended")
            .sessions
            .get(record.id().as_str())
            .map(SessionRecord::revision);

        if let Some(current) = stored
            && record.revision() <= current
        {
            return Err(SubsystemError::conflict(
                well_known::persistence(),
                format!(
                    "{} is at revision {current}, so revision {} is stale",
                    record.id(),
                    record.revision()
                ),
            ));
        }

        self.sessions.push(record);
        Ok(())
    }

    fn append_turn(&mut self, record: TurnRecord) -> Result<(), SubsystemError> {
        self.turns.push(record);
        Ok(())
    }

    fn commit(mut self: Box<Self>) -> BoxFuture<'static, Result<(), SubsystemError>> {
        self.settled = true;

        Box::pin(async move {
            let mut table = self.table.lock().expect("uncontended");

            for record in self.sessions.drain(..) {
                let existing = table
                    .sessions
                    .get(record.id().as_str())
                    .map(SessionRecord::turns)
                    .unwrap_or_default();
                let merged = SessionRecord::new(
                    record.id().clone(),
                    record.revision(),
                    existing + record.turns(),
                );
                table
                    .sessions
                    .insert(record.id().as_str().to_owned(), merged);
            }

            table.turns.append(&mut self.turns);
            drop(table);

            self.commits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }

    fn rollback(mut self: Box<Self>) -> BoxFuture<'static, Result<(), SubsystemError>> {
        self.settled = true;
        self.rollbacks.fetch_add(1, Ordering::SeqCst);

        Box::pin(async move {
            drop(self);
            Ok(())
        })
    }
}

/// One stored credential, together with the only origin it may be sent to.
#[derive(Clone, Debug)]
struct StoredCredential {
    origin: ResolvedEndpoint,
    secret: String,
}

/// Origin-bound credentials held in memory.
#[derive(Debug, Default)]
pub struct MemorySecrets {
    entries: Arc<Mutex<BTreeMap<String, StoredCredential>>>,
    releases: Arc<AtomicU64>,
}

impl MemorySecrets {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Files `secret` under `name`, usable only against `origin`.
    ///
    /// This bypasses the transaction, which is exactly what a fixture wants and
    /// exactly what production code must not do; it is why the method is named
    /// for its purpose rather than looking like part of the port.
    pub fn preload(&self, name: &CredentialName, origin: ResolvedEndpoint, secret: &str) {
        self.entries.lock().expect("uncontended").insert(
            name.as_str().to_owned(),
            StoredCredential {
                origin,
                secret: secret.to_owned(),
            },
        );
    }

    /// Returns how many credentials have been released.
    #[must_use]
    pub fn releases(&self) -> u64 {
        self.releases.load(Ordering::SeqCst)
    }
}

/// A staged secret-store edit.
#[derive(Debug)]
pub struct MemorySecretTransaction {
    entries: Arc<Mutex<BTreeMap<String, StoredCredential>>>,
    puts: Vec<(String, StoredCredential)>,
    removals: Vec<String>,
}

impl SecretStorePort for MemorySecrets {
    fn lease(
        &self,
        request: Grant<CredentialRequest>,
    ) -> BoxFuture<'_, Result<CredentialLease, SubsystemError>> {
        Box::pin(async move {
            let request = request
                .redeem()
                .map_err(|denial| SubsystemError::denied(well_known::secrets(), &denial))?;

            let stored = self
                .entries
                .lock()
                .expect("uncontended")
                .get(request.name().as_str())
                .cloned()
                .ok_or_else(|| {
                    SubsystemError::not_found(
                        well_known::secrets(),
                        format!("no credential named {}", request.name()),
                    )
                })?;

            // The stored origin is compared, not the requested one: a credential
            // filed for one host must never be released for another, however the
            // caller spelled the request.
            if stored.origin.authority() != request.origin().authority()
                || stored.origin.addresses() != request.origin().addresses()
            {
                return Err(SubsystemError::invalid(
                    well_known::secrets(),
                    format!(
                        "{} is filed against {} and cannot be presented to {}",
                        request.name(),
                        stored.origin.authority(),
                        request.origin().authority()
                    ),
                ));
            }

            self.releases.fetch_add(1, Ordering::SeqCst);

            Ok(CredentialLease::new(
                request.name().clone(),
                stored.origin,
                SecretString::from(stored.secret),
            ))
        })
    }

    fn begin(&self) -> BoxFuture<'_, Result<Box<dyn SecretTransaction>, SubsystemError>> {
        Box::pin(async move {
            Ok(Box::new(MemorySecretTransaction {
                entries: Arc::clone(&self.entries),
                puts: Vec::new(),
                removals: Vec::new(),
            }) as Box<dyn SecretTransaction>)
        })
    }
}

impl SecretTransaction for MemorySecretTransaction {
    fn put(
        &mut self,
        name: CredentialName,
        origin: ResolvedEndpoint,
        secret: SecretString,
    ) -> Result<(), SubsystemError> {
        self.puts.push((
            name.as_str().to_owned(),
            StoredCredential {
                origin,
                secret: secret.expose_secret().to_owned(),
            },
        ));

        Ok(())
    }

    fn remove(&mut self, name: &CredentialName) -> Result<(), SubsystemError> {
        self.removals.push(name.as_str().to_owned());
        Ok(())
    }

    fn commit(mut self: Box<Self>) -> BoxFuture<'static, Result<(), SubsystemError>> {
        Box::pin(async move {
            let mut entries = self.entries.lock().expect("uncontended");

            for name in self.removals.drain(..) {
                entries.remove(&name);
            }

            for (name, credential) in self.puts.drain(..) {
                entries.insert(name, credential);
            }

            Ok(())
        })
    }

    fn rollback(self: Box<Self>) -> BoxFuture<'static, Result<(), SubsystemError>> {
        Box::pin(async move {
            drop(self);
            Ok(())
        })
    }
}

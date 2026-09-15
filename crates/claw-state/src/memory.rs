use std::fmt;

use claw_application::ports::tool::{InvocationAuthority, InvocationSource};
use claw_application::ports::{PortError, PortFuture};
use claw_domain::SessionId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtime::port_error;
use crate::{DurableStateStore, Mutation, Record, StateDatabase};

/// Maximum retained explicit notes for one authenticated memory identity.
pub const MAX_MEMORY_ENTRIES: usize = 256;
/// Maximum persisted notebooks in one database, including empty revision tombstones.
pub const MAX_MEMORY_NOTEBOOKS: usize = 256;
/// Maximum UTF-8 bytes in one explicit memory note.
pub const MAX_MEMORY_CONTENT_BYTES: usize = 8 * 1024;
/// Maximum UTF-8 bytes in the caller-supplied source session of a note.
pub const MAX_MEMORY_SOURCE_SESSION_BYTES: usize = 256;
/// Maximum encoded bytes in a portable notebook archive.
pub const MAX_MEMORY_ARCHIVE_BYTES: usize = 4 * 1024 * 1024;

/// The purpose declared for an explicit note, never an authorization role.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryEntryKind {
    /// A caller-supplied fact, not an independently verified assertion.
    Fact,
    /// A preference that the caller may correct or remove.
    Preference,
    /// Workflow guidance stored as data, not executable instructions.
    Procedure,
}

/// One identity-scoped explicit note, with its source session and revision.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MemoryEntry {
    /// Caller-selected bounded note identity, unique within this principal.
    pub id: String,
    /// The declared kind of note.
    pub kind: MemoryEntryKind,
    /// UTF-8 caller content; consumers must treat it as untrusted data.
    pub content: String,
    /// The session that supplied the note, not proof of transcript contents.
    pub source_session: String,
    /// Notebook revision at which this note was last written.
    pub revision: u64,
}

impl fmt::Debug for MemoryEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryEntry")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("content", &"[REDACTED]")
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

/// A consistent bounded view of one authenticated principal's explicit notes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MemorySnapshot {
    /// CAS revision for the whole notebook, including deletes.
    pub revision: u64,
    /// Notes in strictly increasing identifier order.
    pub entries: Vec<MemoryEntry>,
}

/// Portable, untrusted note content without credentials or destination authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MemoryArchive {
    /// Archive schema, independent of database and product versions.
    pub schema_version: u32,
    /// Original note contents, source labels and notebook revisions.
    pub notebook: MemorySnapshot,
}

impl MemoryArchive {
    /// Validates all note and version bounds before a caller imports the archive.
    ///
    /// # Errors
    /// Refuses unsupported versions, unordered/duplicate identities, invalid contents,
    /// revisions or source labels. Callers must bound input bytes before decoding.
    pub fn validate(&self) -> Result<(), PortError> {
        let notes = &self.notebook;
        if self.schema_version != 1
            || notes.entries.len() > MAX_MEMORY_ENTRIES
            || !notes.entries.is_empty() && notes.revision == 0
            || notes
                .entries
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
            || notes.entries.iter().any(|entry| {
                !valid_id(&entry.id)
                    || !valid_content(&entry.content)
                    || !valid_source_session(&entry.source_session)
                    || entry.revision == 0
                    || entry.revision > notes.revision
            })
        {
            return Err(PortError::Invalid(
                "memory archive version, order, content or revision is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StoredMemory {
    version: u32,
    scope: String,
    revision: u64,
    entries: Vec<MemoryEntry>,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || index > 0 && matches!(byte, b'_' | b'-' | b'.')
        })
}

fn valid_content(content: &str) -> bool {
    !content.trim().is_empty()
        && content.len() <= MAX_MEMORY_CONTENT_BYTES
        && !content
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn valid_source_session(source: &str) -> bool {
    source.len() <= MAX_MEMORY_SOURCE_SESSION_BYTES && SessionId::new(source).is_ok()
}

fn memory_scope(authority: &InvocationAuthority) -> Result<String, PortError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if authority.is_revoked() {
        return Err(PortError::Invalid(
            "memory authority was revoked".to_owned(),
        ));
    }
    let source = match authority.source() {
        InvocationSource::Gateway => "gateway",
        InvocationSource::Http => "http",
        InvocationSource::Mcp => "mcp",
        InvocationSource::Channel => "channel",
    };
    let bytes = serde_json::to_vec(&(1_u32, source, authority.subject(), authority.account()))
        .map_err(|_| PortError::Invalid("memory identity could not be encoded".to_owned()))?;
    Ok(Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
        .map(char::from)
        .collect())
}

fn load_memory(
    database: &StateDatabase,
    scope: &str,
) -> Result<(Option<Record>, StoredMemory), PortError> {
    let stored = database
        .get(&format!("explicit-memory/v1/{scope}"))
        .map_err(port_error)?;
    let Some(record) = stored.as_ref() else {
        return Ok((
            None,
            StoredMemory {
                version: 1,
                scope: scope.to_owned(),
                revision: 0,
                entries: Vec::new(),
            },
        ));
    };
    let memory: StoredMemory = record.decode().map_err(port_error)?;
    if memory.version != 1
        || memory.scope != scope
        || memory.revision == 0
        || memory.entries.len() > MAX_MEMORY_ENTRIES
        || memory
            .entries
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
        || memory.entries.iter().any(|entry| {
            !valid_id(&entry.id)
                || !valid_content(&entry.content)
                || entry.revision == 0
                || entry.revision > memory.revision
                || !valid_source_session(&entry.source_session)
        })
    {
        return Err(PortError::Invalid(
            "stored explicit memory is invalid; preserve state for recovery".to_owned(),
        ));
    }
    Ok((stored, memory))
}

fn commit_memory(
    database: &StateDatabase,
    previous: Option<Record>,
    memory: &StoredMemory,
    authority: &InvocationAuthority,
) -> Result<(), PortError> {
    let mutation = Mutation::put(format!("explicit-memory/v1/{}", memory.scope), memory)
        .map_err(port_error)?;
    match previous {
        Some(previous) => database.commit_guarded(vec![mutation.if_unchanged(&previous)], || authority.can_execute()).map_err(port_error),
        None => database.insert_with_prefix_limit(mutation.if_absent(), "explicit-memory/v1/", MAX_MEMORY_NOTEBOOKS, || authority.can_execute())
            .map_err(|error| match error {
                crate::StateError::InvalidRecord => PortError::Invalid("explicit memory notebook capacity reached; existing notebooks remain readable and editable".to_owned()),
                other => port_error(other),
            }),
    }
}

impl DurableStateStore {
    /// Returns the stable, non-secret partition identifier for authenticated notes.
    ///
    /// This identifier is not a credential and confers no permission to read it.
    ///
    /// # Errors
    /// Refuses revoked authority or an identity that cannot be encoded.
    pub fn memory_partition_id(authority: &InvocationAuthority) -> Result<String, PortError> {
        memory_scope(authority)
    }

    /// Reads a consistent notebook for the authenticated source/subject/account.
    ///
    /// The session is not part of the key, so the same identity can recall notes
    /// across its sessions. Different ingress identities remain isolated.
    ///
    /// # Errors
    /// Refuses revoked identities, malformed stored records and storage failures.
    pub fn memory_snapshot(
        &self,
        authority: InvocationAuthority,
    ) -> PortFuture<'_, Result<MemorySnapshot, PortError>> {
        self.operation(move |database| {
            let scope = memory_scope(&authority)?;
            let (_, memory) = load_memory(database, &scope)?;
            if authority.is_revoked() {
                return Err(PortError::Invalid(
                    "memory authority was revoked while reading".to_owned(),
                ));
            }
            Ok(MemorySnapshot {
                revision: memory.revision,
                entries: memory.entries,
            })
        })
    }

    /// Creates or replaces an explicit note after comparing the notebook revision.
    ///
    /// The host must obtain any required approval before calling this adapter.
    /// This method preserves identity and CAS; it does not grant tool permission.
    ///
    /// # Errors
    /// Refuses non-executing authorities, invalid notes, capacity, stale revision,
    /// revoked authority and unconfirmed commits. An unknown commit is not replayable.
    pub fn put_memory_entry(
        &self,
        authority: InvocationAuthority,
        expected_revision: u64,
        mut entry: MemoryEntry,
    ) -> PortFuture<'_, Result<u64, PortError>> {
        self.operation(move |database| {
            if !authority.can_execute()
                || !valid_id(&entry.id)
                || !valid_content(&entry.content)
                || !valid_source_session(&entry.source_session)
                || entry.revision != 0
            {
                return Err(PortError::Invalid(
                    "explicit memory note or authority is invalid".to_owned(),
                ));
            }
            let scope = memory_scope(&authority)?;
            let (previous, mut memory) = load_memory(database, &scope)?;
            if memory.revision != expected_revision {
                return Err(PortError::Conflict(
                    "memory notebook changed since it was reviewed".to_owned(),
                ));
            }
            let position = memory
                .entries
                .binary_search_by(|stored| stored.id.cmp(&entry.id));
            if position.is_err() && memory.entries.len() == MAX_MEMORY_ENTRIES {
                return Err(PortError::Invalid(
                    "explicit memory notebook capacity reached".to_owned(),
                ));
            }
            memory.revision = memory
                .revision
                .checked_add(1)
                .ok_or_else(|| PortError::Conflict("memory revision exhausted".to_owned()))?;
            entry.revision = memory.revision;
            match position {
                Ok(position) => memory.entries[position] = entry,
                Err(position) => memory.entries.insert(position, entry),
            }
            if !authority.can_execute() {
                return Err(PortError::Invalid(
                    "memory authority was revoked before commit".to_owned(),
                ));
            }
            commit_memory(database, previous, &memory, &authority)?;
            Ok(memory.revision)
        })
    }

    /// Atomically merges an approved portable archive into the caller's notebook.
    ///
    /// Existing identities are refused unless `overwrite` is explicitly true. All
    /// imported notes receive one new destination revision; source labels remain
    /// untrusted data. Notes absent from the archive are never deleted.
    ///
    /// # Errors
    /// Refuses invalid archives, stale notebook revisions, conflicts, excess capacity,
    /// revoked/non-executing authority and unconfirmed commits. No partial merge occurs.
    pub fn import_memory_archive(
        &self,
        authority: InvocationAuthority,
        expected_revision: u64,
        archive: MemoryArchive,
        overwrite: bool,
    ) -> PortFuture<'_, Result<u64, PortError>> {
        self.operation(move |database| {
            archive.validate()?;
            if !authority.can_execute() {
                return Err(PortError::Invalid("memory import requires execution authority".to_owned()));
            }
            let scope = memory_scope(&authority)?;
            let (previous, mut notebook) = load_memory(database, &scope)?;
            if notebook.revision != expected_revision {
                return Err(PortError::Conflict("memory notebook changed before import".to_owned()));
            }
            if archive.notebook.entries.is_empty() { return Ok(notebook.revision); }
            let revision = notebook.revision.checked_add(1).ok_or_else(|| PortError::Conflict("memory revision exhausted".to_owned()))?;
            for mut entry in archive.notebook.entries {
                entry.revision = revision;
                match notebook.entries.binary_search_by(|existing| existing.id.cmp(&entry.id)) {
                    Ok(position) if overwrite => notebook.entries[position] = entry,
                    Ok(_) => return Err(PortError::Conflict("memory import contains an existing note; explicit overwrite approval is required".to_owned())),
                    Err(position) => {
                        if notebook.entries.len() == MAX_MEMORY_ENTRIES {
                            return Err(PortError::Invalid("memory import exceeds notebook capacity".to_owned()));
                        }
                        notebook.entries.insert(position, entry);
                    }
                }
            }
            notebook.revision = revision;
            if !authority.can_execute() {
                return Err(PortError::Invalid("memory authority was revoked before import commit".to_owned()));
            }
            commit_memory(database, previous, &notebook, &authority)?;
            Ok(revision)
        })
    }

    /// Deletes a note while retaining the notebook's monotonic revision.
    ///
    /// # Errors
    /// Refuses non-executing authority, invalid identity, stale revision and storage
    /// failures. A missing note leaves the revision unchanged.
    pub fn delete_memory_entry(
        &self,
        authority: InvocationAuthority,
        expected_revision: u64,
        id: String,
    ) -> PortFuture<'_, Result<u64, PortError>> {
        self.operation(move |database| {
            if !authority.can_execute() || !valid_id(&id) {
                return Err(PortError::Invalid(
                    "memory deletion identity or authority is invalid".to_owned(),
                ));
            }
            let scope = memory_scope(&authority)?;
            let (previous, mut memory) = load_memory(database, &scope)?;
            if memory.revision != expected_revision {
                return Err(PortError::Conflict(
                    "memory notebook changed since it was reviewed".to_owned(),
                ));
            }
            let Ok(position) = memory.entries.binary_search_by(|entry| entry.id.cmp(&id)) else {
                return Ok(memory.revision);
            };
            memory.entries.remove(position);
            memory.revision = memory
                .revision
                .checked_add(1)
                .ok_or_else(|| PortError::Conflict("memory revision exhausted".to_owned()))?;
            if !authority.can_execute() {
                return Err(PortError::Invalid(
                    "memory authority was revoked before commit".to_owned(),
                ));
            }
            commit_memory(database, previous, &memory, &authority)?;
            Ok(memory.revision)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claw_application::ports::tool::InvocationAccess;

    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    struct Root(std::path::PathBuf);

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn root() -> Root {
        let root = Root(std::env::temp_dir().join(format!(
            "claw-explicit-memory-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )));
        std::fs::create_dir_all(&root.0).expect("owned root");
        root
    }

    fn authority(account: &str, access: InvocationAccess) -> InvocationAuthority {
        InvocationAuthority::new(
            InvocationSource::Channel,
            "same-sender",
            Some(account),
            access,
            0,
        )
        .expect("authenticated scope")
    }

    fn entry(id: &str, session: &str) -> MemoryEntry {
        MemoryEntry {
            id: id.to_owned(),
            kind: MemoryEntryKind::Preference,
            content: "Use metric units in reports.".to_owned(),
            source_session: session.to_owned(),
            revision: 0,
        }
    }

    #[tokio::test]
    async fn explicit_memory_is_identity_scoped_durable_and_cas_protected() {
        let root = root();
        let path = root.0.join("state.redb");
        let store = DurableStateStore::open(&path).expect("state");
        let owner = authority("account-a", InvocationAccess::Execute);
        assert_eq!(
            store
                .memory_snapshot(owner.clone())
                .await
                .expect("empty")
                .revision,
            0
        );
        assert_eq!(
            store
                .put_memory_entry(owner.clone(), 0, entry("units", "first-session"))
                .await
                .expect("save"),
            1
        );
        assert!(
            store
                .memory_snapshot(authority("account-b", InvocationAccess::Execute))
                .await
                .expect("other account")
                .entries
                .is_empty()
        );
        assert!(matches!(
            store
                .put_memory_entry(owner.clone(), 0, entry("units", "second-session"))
                .await,
            Err(PortError::Conflict(_))
        ));
        assert_eq!(
            store
                .put_memory_entry(owner.clone(), 1, entry("units", "second-session"))
                .await
                .expect("correct"),
            2
        );
        store.shutdown().await;
        drop(store);
        let store = DurableStateStore::open(&path).expect("reopen");
        let snapshot = store
            .memory_snapshot(owner.clone())
            .await
            .expect("recalled");
        assert_eq!(snapshot.revision, 2);
        assert_eq!(snapshot.entries[0].source_session, "second-session");
        assert_eq!(snapshot.entries[0].content, "Use metric units in reports.");
        assert!(!format!("{snapshot:?}").contains("Use metric units"));
        assert_eq!(
            store
                .delete_memory_entry(owner.clone(), 2, "units".to_owned())
                .await
                .expect("forget"),
            3
        );
        store.shutdown().await;
        drop(store);
        let store = DurableStateStore::open(&path).expect("reopen forgotten");
        let snapshot = store
            .memory_snapshot(owner.clone())
            .await
            .expect("forgotten snapshot");
        assert!(snapshot.entries.is_empty());
        assert_eq!(snapshot.revision, 3);
        assert!(matches!(
            store
                .put_memory_entry(owner, 0, entry("units", "old-session"))
                .await,
            Err(PortError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn explicit_memory_concurrent_writes_have_one_revision_winner() {
        let root = root();
        let store = DurableStateStore::open(root.0.join("state.redb")).expect("state");
        let owner = authority("account-a", InvocationAccess::Execute);
        let (first, second) = tokio::join!(
            store.put_memory_entry(owner.clone(), 0, entry("first", "session-a")),
            store.put_memory_entry(owner.clone(), 0, entry("second", "session-b")),
        );
        assert!(matches!(
            (&first, &second),
            (Ok(1), Err(PortError::Conflict(_))) | (Err(PortError::Conflict(_)), Ok(1))
        ));
        let snapshot = store.memory_snapshot(owner).await.expect("one winner");
        assert_eq!(snapshot.revision, 1);
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.entries[0].revision, 1);
        store.shutdown().await;
    }

    #[tokio::test]
    async fn explicit_memory_archive_import_is_atomic_revisioned_and_destination_scoped() {
        let root = root();
        let path = root.0.join("state.redb");
        let store = DurableStateStore::open(&path).expect("state");
        let source = authority("source", InvocationAccess::Execute);
        let destination = authority("destination", InvocationAccess::Execute);
        store
            .put_memory_entry(source.clone(), 0, entry("first", "source-session"))
            .await
            .expect("source first");
        store
            .put_memory_entry(source.clone(), 1, entry("units", "source-session"))
            .await
            .expect("source second");
        let archive = MemoryArchive {
            schema_version: 1,
            notebook: store
                .memory_snapshot(source.clone())
                .await
                .expect("source archive"),
        };
        archive.validate().expect("valid archive");
        assert!(!format!("{archive:?}").contains("Use metric"));
        store
            .put_memory_entry(
                destination.clone(),
                0,
                entry("units", "original-destination"),
            )
            .await
            .expect("existing destination");
        assert!(matches!(
            store
                .import_memory_archive(destination.clone(), 1, archive.clone(), false)
                .await,
            Err(PortError::Conflict(_))
        ));
        let unchanged = store
            .memory_snapshot(destination.clone())
            .await
            .expect("no partial merge");
        assert_eq!(unchanged.revision, 1);
        assert_eq!(unchanged.entries.len(), 1);
        assert_eq!(unchanged.entries[0].source_session, "original-destination");
        assert!(matches!(
            store
                .import_memory_archive(destination.clone(), 0, archive.clone(), true)
                .await,
            Err(PortError::Conflict(_))
        ));
        assert!(
            store
                .import_memory_archive(
                    authority("destination", InvocationAccess::ReadOnly),
                    1,
                    archive.clone(),
                    true
                )
                .await
                .is_err()
        );
        assert_eq!(
            store
                .import_memory_archive(destination.clone(), 1, archive.clone(), true)
                .await
                .expect("approved overwrite"),
            2
        );
        let imported = store
            .memory_snapshot(destination.clone())
            .await
            .expect("imported");
        assert_eq!(imported.entries.len(), 2);
        assert!(
            imported
                .entries
                .iter()
                .all(|entry| entry.revision == 2 && entry.source_session == "source-session")
        );
        assert_eq!(
            store
                .memory_snapshot(source.clone())
                .await
                .expect("source preserved"),
            archive.notebook
        );
        for invalid in 0..3 {
            let mut changed = archive.clone();
            match invalid {
                0 => changed.schema_version = 2,
                1 => changed
                    .notebook
                    .entries
                    .push(changed.notebook.entries[0].clone()),
                _ => changed.notebook.entries[0].content = "x".repeat(MAX_MEMORY_CONTENT_BYTES + 1),
            }
            assert!(
                store
                    .import_memory_archive(destination.clone(), 2, changed, true)
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            store
                .memory_snapshot(destination.clone())
                .await
                .expect("invalid archive unchanged"),
            imported
        );
        store.shutdown().await;
        drop(store);
        let store = DurableStateStore::open(&path).expect("reopen imported");
        assert_eq!(
            store
                .memory_snapshot(destination)
                .await
                .expect("durable import"),
            imported
        );
        assert_eq!(
            store.memory_snapshot(source).await.expect("durable source"),
            archive.notebook
        );
        store.shutdown().await;
    }

    #[test]
    fn explicit_memory_rechecks_authority_after_waiting_for_the_state_writer() {
        struct Revoked(tokio_util::sync::CancellationToken);
        impl claw_application::ports::tool::InvocationRevocation for Revoked {
            fn is_revoked(&self) -> bool {
                self.0.is_cancelled()
            }
            fn revoked(&self) -> PortFuture<'_, ()> {
                Box::pin(self.0.cancelled())
            }
        }
        let root = root();
        let database =
            std::sync::Arc::new(StateDatabase::open(root.0.join("writer.redb")).expect("state"));
        let cancellation = tokio_util::sync::CancellationToken::new();
        let identity = authority("waiting-writer", InvocationAccess::Execute)
            .with_revocation(std::sync::Arc::new(Revoked(cancellation.clone())));
        let scope = memory_scope(&identity).expect("initial permitted scope");
        let mut note = entry("units", "source");
        note.revision = 1;
        let notebook = StoredMemory {
            version: 1,
            scope: scope.clone(),
            revision: 1,
            entries: vec![note],
        };
        let gate = database
            .recovery_required
            .lock()
            .expect("hold writer admission");
        let (started, reached) = std::sync::mpsc::sync_channel(0);
        let writer_database = std::sync::Arc::clone(&database);
        let writer = std::thread::spawn(move || {
            assert!(identity.can_execute());
            started.send(()).expect("writer is ready");
            commit_memory(&writer_database, None, &notebook, &identity)
        });
        reached.recv().expect("writer reached admission");
        cancellation.cancel();
        drop(gate);
        assert!(matches!(
            writer.join().expect("owned writer joined"),
            Err(PortError::Conflict(_))
        ));
        assert!(
            database
                .get(&format!("explicit-memory/v1/{scope}"))
                .expect("no stale-authority write")
                .is_none()
        );
        assert!(!database.recovery_required());
    }

    #[tokio::test]
    async fn explicit_memory_global_quota_is_atomic_and_survives_empty_notebooks_and_restart() {
        let root = root();
        let path = root.0.join("quota.redb");
        let store = DurableStateStore::open(&path).expect("state");
        let first = authority("quota-0", InvocationAccess::Execute);
        for index in 0..MAX_MEMORY_NOTEBOOKS - 1 {
            let identity = authority(&format!("quota-{index}"), InvocationAccess::Execute);
            assert_eq!(
                store
                    .put_memory_entry(identity, 0, entry("units", "seed"))
                    .await
                    .expect("within quota"),
                1
            );
        }
        let final_first = authority("last-first", InvocationAccess::Execute);
        let final_second = authority("last-second", InvocationAccess::Execute);
        let (first_result, second_result) = tokio::join!(
            store.put_memory_entry(final_first.clone(), 0, entry("units", "last-a")),
            store.put_memory_entry(final_second.clone(), 0, entry("units", "last-b")),
        );
        assert!(matches!(
            (&first_result, &second_result),
            (Ok(1), Err(PortError::Invalid(_))) | (Err(PortError::Invalid(_)), Ok(1))
        ));
        let total = store
            .memory_snapshot(final_first)
            .await
            .expect("first result")
            .entries
            .len()
            + store
                .memory_snapshot(final_second)
                .await
                .expect("second result")
                .entries
                .len();
        assert_eq!(total, 1);
        assert_eq!(
            store
                .put_memory_entry(first.clone(), 1, entry("units", "correction"))
                .await
                .expect("updates at full quota"),
            2
        );
        assert_eq!(
            store
                .delete_memory_entry(first.clone(), 2, "units".to_owned())
                .await
                .expect("delete at full quota"),
            3
        );
        let empty = store
            .memory_snapshot(first.clone())
            .await
            .expect("empty notebook retains revision");
        assert_eq!(empty.revision, 3);
        assert!(empty.entries.is_empty());
        let outsider = authority("outside-quota", InvocationAccess::Execute);
        let mut imported = entry("units", "archive");
        imported.revision = 1;
        let archive = MemoryArchive {
            schema_version: 1,
            notebook: MemorySnapshot {
                revision: 1,
                entries: vec![imported],
            },
        };
        assert!(matches!(
            store
                .import_memory_archive(outsider.clone(), 0, archive.clone(), false)
                .await,
            Err(PortError::Invalid(_))
        ));
        assert_eq!(
            store
                .memory_snapshot(outsider.clone())
                .await
                .expect("read-only empty lookup")
                .revision,
            0
        );
        assert!(!store.recovery_required());
        store.shutdown().await;
        drop(store);
        let store = DurableStateStore::open(&path).expect("quota after reopen");
        assert!(matches!(
            store
                .put_memory_entry(outsider, 0, entry("units", "new"))
                .await,
            Err(PortError::Invalid(_))
        ));
        assert_eq!(
            store
                .import_memory_archive(first.clone(), 3, archive, false)
                .await
                .expect("existing empty notebook import"),
            4
        );
        assert_eq!(
            store
                .memory_snapshot(first)
                .await
                .expect("existing notebook updated")
                .revision,
            4
        );
        store.shutdown().await;
    }

    #[tokio::test]
    async fn explicit_memory_rejects_invalid_and_unauthorized_writes() {
        let root = root();
        let store = DurableStateStore::open(root.0.join("state.redb")).expect("state");
        let owner = authority("account-a", InvocationAccess::Execute);
        assert!(
            store
                .put_memory_entry(
                    authority("account-a", InvocationAccess::ReadOnly),
                    0,
                    entry("units", "session")
                )
                .await
                .is_err()
        );
        for id in ["", "../foreign", "bad id"] {
            assert!(
                store
                    .put_memory_entry(owner.clone(), 0, entry(id, "session"))
                    .await
                    .is_err()
            );
        }
        let mut invalid = entry("units", "session");
        invalid.content = "x".repeat(MAX_MEMORY_CONTENT_BYTES + 1);
        assert!(
            store
                .put_memory_entry(owner.clone(), 0, invalid)
                .await
                .is_err()
        );
        let mut invalid = entry("units", "session");
        invalid.revision = 1;
        assert!(
            store
                .put_memory_entry(owner.clone(), 0, invalid)
                .await
                .is_err()
        );
        let invalid = entry("units", &"s".repeat(MAX_MEMORY_SOURCE_SESSION_BYTES + 1));
        assert!(
            store
                .put_memory_entry(owner.clone(), 0, invalid)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .memory_snapshot(owner)
                .await
                .expect("unchanged")
                .revision,
            0
        );
    }
}

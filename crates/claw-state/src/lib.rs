//! Bounded, versioned transactions over a pure Rust embedded database.
//!
//! This synchronous adapter belongs on an owned blocking worker, not a UI or
//! asynchronous I/O thread. Database commits do not imply external delivery.

mod memory;
mod runs;
mod runtime;
mod snapshot;

pub use memory::{
    MAX_MEMORY_ARCHIVE_BYTES, MAX_MEMORY_CONTENT_BYTES, MAX_MEMORY_ENTRIES, MAX_MEMORY_NOTEBOOKS,
    MAX_MEMORY_SOURCE_SESSION_BYTES, MemoryArchive, MemoryEntry, MemoryEntryKind, MemorySnapshot,
};
pub use runs::RunDeliveryStatus;
pub use runs::{
    DeliveryPhase, DiscordResume, DurableRun, RunAdmission, RunDelivery, RunDeliveryReceipt,
    RunDeliveryReceiptPage, RunPhase, RunResult, RunResultPage, RunSubmission,
};
pub use runtime::DurableStateStore;
pub use snapshot::SnapshotReceipt;

use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::Serialize;
use serde::de::DeserializeOwned;

const METADATA: TableDefinition<&str, u64> = TableDefinition::new("metadata");
const RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("records");
const SCHEMA_VERSION: u64 = 1;
const MAX_KEY_BYTES: usize = 512;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_TRANSACTION_RECORDS: usize = 256;
const MAX_TRANSACTION_BYTES: usize = 16 * 1024 * 1024;

/// A state operation that was refused or could not be confirmed.
#[derive(Debug)]
pub enum StateError {
    /// The database could not be read, written, or committed.
    Storage(String),
    /// A commit returned an error; its durable outcome must be recovered before retry.
    CommitUnknown(String),
    /// The on-disk application schema is unsupported or absent.
    Schema,
    /// A record or operation exceeded its validated bounds.
    InvalidRecord,
    /// An optimistic-concurrency condition did not match.
    Conflict,
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(detail) => write!(formatter, "state storage failed: {detail}"),
            Self::CommitUnknown(detail) => {
                write!(formatter, "state commit outcome is unknown: {detail}")
            }
            Self::Schema => formatter.write_str(
                "unsupported or missing state schema; preserve the database for recovery",
            ),
            Self::InvalidRecord => {
                formatter.write_str("state record or operation exceeds its validated bounds")
            }
            Self::Conflict => formatter.write_str("state changed since it was read"),
        }
    }
}

impl std::error::Error for StateError {}

fn storage(error: impl fmt::Display) -> StateError {
    StateError::Storage(error.to_string())
}

/// One atomic record replacement or deletion with an optional comparison.
pub struct Mutation {
    key: String,
    expected: ExpectedRecord,
    replacement: Option<Vec<u8>>,
}

enum ExpectedRecord {
    Any,
    Absent,
    Exact(Record),
}

impl Mutation {
    /// Creates a bounded JSON record replacement.
    ///
    /// # Errors
    ///
    /// Rejects invalid keys, oversized data, or a value that cannot be serialized.
    pub fn put(key: impl Into<String>, value: &impl Serialize) -> Result<Self, StateError> {
        let key = checked_key(key.into())?;
        let mut writer = BoundedRecord(Vec::new());
        serde_json::to_writer(&mut writer, value).map_err(|_| StateError::InvalidRecord)?;
        Ok(Self {
            key,
            expected: ExpectedRecord::Any,
            replacement: Some(writer.0),
        })
    }

    /// Creates a deletion; the target must still satisfy any attached comparison.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized or control-bearing keys.
    pub fn delete(key: impl Into<String>) -> Result<Self, StateError> {
        Ok(Self {
            key: checked_key(key.into())?,
            expected: ExpectedRecord::Any,
            replacement: None,
        })
    }

    /// Requires the key to be absent at commit time.
    #[must_use]
    pub fn if_absent(mut self) -> Self {
        self.expected = ExpectedRecord::Absent;
        self
    }

    /// Requires the exact previously read record at commit time.
    #[must_use]
    pub fn if_unchanged(mut self, previous: &Record) -> Self {
        self.expected = ExpectedRecord::Exact(previous.clone());
        self
    }
}

struct BoundedRecord(Vec<u8>);

impl std::io::Write for BoundedRecord {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_RECORD_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("record limit reached"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A bounded record whose bytes can be used for optimistic concurrency.
#[derive(Clone, Eq, PartialEq)]
pub struct Record(Vec<u8>);

/// One bounded page of lexically ordered state records.
pub struct RecordPage {
    /// Records from one consistent read transaction.
    pub records: Vec<(String, Record)>,
    /// Exclusive continuation key, present only when more matching records remain.
    pub next_cursor: Option<String>,
}

impl Record {
    /// Decodes one complete typed JSON document.
    ///
    /// # Errors
    ///
    /// Rejects invalid JSON or data that does not match the caller's schema.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, StateError> {
        serde_json::from_slice(&self.0).map_err(|_| StateError::InvalidRecord)
    }
}

/// A locally owned database with explicit application schema checks.
pub struct StateDatabase {
    database: Database,
    recovery_required: Mutex<bool>,
}

#[derive(Clone, Copy)]
enum OpenMode {
    OpenOrCreate,
    Existing,
    CreateNew,
}

impl StateDatabase {
    /// Opens an existing database or initializes a new database in an existing private directory.
    ///
    /// # Errors
    ///
    /// Rejects non-files, symlinks/reparse points, empty existing files, unsupported schemas,
    /// and storage errors. Never replaces an unreadable existing database with an empty one.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StateError> {
        Self::open_with_mode(path.as_ref(), OpenMode::OpenOrCreate)
    }

    /// Opens an existing database without creating one when the path is absent.
    ///
    /// Normal redb recovery may update its internal journal. This is not a forensic read-only open.
    ///
    /// # Errors
    /// Refuses missing, locked, unsafe or incompatible databases as in [`Self::open`].
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, StateError> {
        Self::open_with_mode(path.as_ref(), OpenMode::Existing)
    }

    /// Creates a new database without replacing or adopting an existing target.
    ///
    /// # Errors
    /// Refuses any existing object at the path, or initialization failures as in [`Self::open`].
    pub fn create_new(path: impl AsRef<Path>) -> Result<Self, StateError> {
        Self::open_with_mode(path.as_ref(), OpenMode::CreateNew)
    }

    /// Initializes state through an exclusively created empty file handle owned by the caller.
    ///
    /// # Errors
    /// Refuses non-regular or nonempty files and invalid initialization. Callers own path/ACL policy.
    pub fn from_new_file(file: fs::File) -> Result<Self, StateError> {
        if file.metadata().map_err(storage)?.len() != 0 {
            return Err(StateError::Conflict);
        }
        Self::from_file(file, false)
    }

    /// Opens state from a validated existing read/write file handle, including normal redb recovery.
    ///
    /// # Errors
    /// Refuses invalid, empty, locked or incompatible databases. Callers own path/ACL validation.
    pub fn from_existing_file(file: fs::File) -> Result<Self, StateError> {
        Self::from_file(file, true)
    }

    fn open_with_mode(path: &Path, mode: OpenMode) -> Result<Self, StateError> {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true);
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
            options.custom_flags(0x0020_0000);
        }
        let (file, existing) = match mode {
            OpenMode::Existing => (options.open(path).map_err(storage)?, true),
            OpenMode::CreateNew => (options.create_new(true).open(path).map_err(storage)?, false),
            OpenMode::OpenOrCreate => match options.create_new(true).open(path) {
                Ok(file) => (file, false),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    (options.create_new(false).open(path).map_err(storage)?, true)
                }
                Err(error) => return Err(storage(error)),
            },
        };
        Self::from_file(file, existing)
    }

    fn from_file(file: fs::File, existing: bool) -> Result<Self, StateError> {
        let metadata = file.metadata().map_err(storage)?;
        if !metadata.is_file() || (existing && metadata.len() == 0) {
            return Err(StateError::Schema);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(StateError::Schema);
            }
        }
        let database = Database::builder()
            .set_cache_size(32 * 1024 * 1024)
            .create_file(file)
            .map_err(storage)?;
        if existing {
            let read = database.begin_read().map_err(storage)?;
            let table = read.open_table(METADATA).map_err(|_| StateError::Schema)?;
            if table
                .get("schema")
                .map_err(storage)?
                .map(|value| value.value())
                != Some(SCHEMA_VERSION)
            {
                return Err(StateError::Schema);
            }
            read.open_table(RECORDS).map_err(|_| StateError::Schema)?;
        } else {
            let write = database.begin_write().map_err(storage)?;
            {
                let mut table = write.open_table(METADATA).map_err(storage)?;
                table.insert("schema", SCHEMA_VERSION).map_err(storage)?;
            }
            write.open_table(RECORDS).map_err(storage)?;
            write.commit().map_err(storage)?;
        }
        Ok(Self {
            database,
            recovery_required: Mutex::new(false),
        })
    }

    /// Reports whether an unconfirmed write or worker failure has fenced further mutations.
    #[must_use]
    pub fn recovery_required(&self) -> bool {
        self.recovery_required
            .lock()
            .map_or(true, |required| *required)
    }

    pub(crate) fn require_recovery(&self) {
        *self
            .recovery_required
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
    }

    /// Reads a record without interpreting its application payload.
    ///
    /// # Errors
    ///
    /// Rejects invalid keys, oversized stored values, or storage failures.
    pub fn get(&self, key: &str) -> Result<Option<Record>, StateError> {
        checked_key(key.to_owned())?;
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(RECORDS).map_err(storage)?;
        table
            .get(key)
            .map_err(storage)?
            .map(|value| {
                if value.value().len() > MAX_RECORD_BYTES {
                    return Err(StateError::InvalidRecord);
                }
                Ok(Record(value.value().to_vec()))
            })
            .transpose()
    }

    /// Reads a bounded page under one read transaction without loading the entire keyspace.
    ///
    /// # Errors
    ///
    /// Rejects invalid prefixes/cursors, limits outside 1..=256, oversized records and storage errors.
    pub fn page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<RecordPage, StateError> {
        checked_key(prefix.to_owned())?;
        if !(1..=256).contains(&limit) || after.is_some_and(|cursor| !cursor.starts_with(prefix)) {
            return Err(StateError::InvalidRecord);
        }
        if let Some(cursor) = after {
            checked_key(cursor.to_owned())?;
        }
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(RECORDS).map_err(storage)?;
        let mut records = Vec::new();
        let mut bytes = 0_usize;
        let mut more = false;
        for item in table.range(after.unwrap_or(prefix)..).map_err(storage)? {
            let (key, value) = item.map_err(storage)?;
            let key = key.value();
            if !key.starts_with(prefix) {
                break;
            }
            if after == Some(key) {
                continue;
            }
            let value = value.value();
            if value.len() > MAX_RECORD_BYTES {
                return Err(StateError::InvalidRecord);
            }
            if records.len() == limit || value.len() > MAX_TRANSACTION_BYTES.saturating_sub(bytes) {
                more = true;
                break;
            }
            bytes += value.len();
            records.push((key.to_owned(), Record(value.to_vec())));
        }
        let next_cursor = if more {
            records.last().map(|(key, _)| key.clone())
        } else {
            None
        };
        Ok(RecordPage {
            records,
            next_cursor,
        })
    }

    /// Atomically validates comparisons and publishes every mutation.
    ///
    /// # Errors
    ///
    /// Rejects duplicate keys, empty/oversized transactions, stale comparisons and storage
    /// failures. A commit error is not evidence that retrying an external effect is safe.
    pub fn commit(&self, mutations: Vec<Mutation>) -> Result<(), StateError> {
        self.commit_checked(mutations, None, || true)
    }

    pub(crate) fn commit_guarded(
        &self,
        mutations: Vec<Mutation>,
        permitted: impl Fn() -> bool,
    ) -> Result<(), StateError> {
        self.commit_checked(mutations, None, permitted)
    }

    pub(crate) fn insert_with_prefix_limit(
        &self,
        mutation: Mutation,
        prefix: &str,
        limit: usize,
        permitted: impl Fn() -> bool,
    ) -> Result<(), StateError> {
        checked_key(prefix.to_owned())?;
        if !(1..=4096).contains(&limit)
            || !mutation.key.starts_with(prefix)
            || !matches!(mutation.expected, ExpectedRecord::Absent)
            || mutation.replacement.is_none()
        {
            return Err(StateError::InvalidRecord);
        }
        self.commit_checked(vec![mutation], Some((prefix, limit)), permitted)
    }

    fn commit_checked(
        &self,
        mutations: Vec<Mutation>,
        new_record_limit: Option<(&str, usize)>,
        permitted: impl Fn() -> bool,
    ) -> Result<(), StateError> {
        let mut recovery = self.recovery_required.lock().map_err(|_| {
            StateError::CommitUnknown("state write gate failed; recovery is required".to_owned())
        })?;
        if *recovery {
            return Err(StateError::CommitUnknown(
                "state writes are fenced until explicit reopen and reconciliation".to_owned(),
            ));
        }
        if mutations.is_empty() || mutations.len() > MAX_TRANSACTION_RECORDS {
            return Err(StateError::InvalidRecord);
        }
        let total_bytes = mutations
            .iter()
            .try_fold(0_usize, |total, change| {
                total.checked_add(change.replacement.as_ref().map_or(0, Vec::len))
            })
            .ok_or(StateError::InvalidRecord)?;
        if total_bytes > MAX_TRANSACTION_BYTES {
            return Err(StateError::InvalidRecord);
        }
        let mut keys = std::collections::BTreeSet::new();
        if mutations
            .iter()
            .any(|change| !keys.insert(change.key.as_str()))
        {
            return Err(StateError::InvalidRecord);
        }
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(RECORDS).map_err(storage)?;
            for change in &mutations {
                let current = table.get(change.key.as_str()).map_err(storage)?;
                let accepted = match &change.expected {
                    ExpectedRecord::Any => true,
                    ExpectedRecord::Absent => current.is_none(),
                    ExpectedRecord::Exact(expected) => current
                        .as_ref()
                        .is_some_and(|value| value.value() == expected.0.as_slice()),
                };
                if !accepted {
                    return Err(StateError::Conflict);
                }
            }
            if let Some((prefix, limit)) = new_record_limit {
                let mut count = 0;
                for entry in table.range(prefix..).map_err(storage)?.take(limit) {
                    let (key, _) = entry.map_err(storage)?;
                    if !key.value().starts_with(prefix) {
                        break;
                    }
                    count += 1;
                }
                if count == limit {
                    return Err(StateError::InvalidRecord);
                }
            }
            if !permitted() {
                return Err(StateError::Conflict);
            }
            for change in mutations {
                if let Some(bytes) = change.replacement {
                    table
                        .insert(change.key.as_str(), bytes.as_slice())
                        .map_err(storage)?;
                } else {
                    table.remove(change.key.as_str()).map_err(storage)?;
                }
            }
        }
        let result = write
            .commit()
            .map_err(|error| StateError::CommitUnknown(error.to_string()));
        if result.is_err() {
            *recovery = true;
        }
        drop(recovery);
        result
    }
}

fn checked_key(key: String) -> Result<String, StateError> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES || key.chars().any(char::is_control) {
        Err(StateError::InvalidRecord)
    } else {
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    pub(crate) struct Fixture(PathBuf);

    impl Fixture {
        pub(crate) fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "claw-state-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("isolated fixture directory");
            Self(root)
        }

        pub(crate) fn path(&self) -> PathBuf {
            self.0.join("state.redb")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("fixture removed");
        }
    }

    #[test]
    fn committed_records_survive_reopen_and_keep_exact_json_values() {
        let fixture = Fixture::new();
        let database = StateDatabase::open(fixture.path()).expect("create database");
        database
            .commit(vec![
                Mutation::put(
                    "session/one",
                    &serde_json::json!({"revision": 1, "text": "  hello  "}),
                )
                .expect("record")
                .if_absent(),
            ])
            .expect("commit");
        drop(database);
        let reopened = StateDatabase::open(fixture.path()).expect("reopen");
        let decoded: serde_json::Value = reopened
            .get("session/one")
            .expect("read")
            .expect("retained record")
            .decode()
            .expect("decode");
        assert_eq!(decoded["text"], "  hello  ");
        assert_eq!(decoded["revision"], 1);
    }

    #[test]
    fn stale_comparison_rolls_back_every_mutation() {
        let fixture = Fixture::new();
        let database = StateDatabase::open(fixture.path()).expect("database");
        database
            .commit(vec![Mutation::put("one", &1).expect("record")])
            .expect("commit");
        let previous = database.get("one").expect("read").expect("record");
        database
            .commit(vec![
                Mutation::put("one", &2)
                    .expect("record")
                    .if_unchanged(&previous),
            ])
            .expect("replace");
        assert!(matches!(
            database.commit(vec![
                Mutation::put("two", &3).expect("record"),
                Mutation::delete("one")
                    .expect("delete")
                    .if_unchanged(&previous)
            ]),
            Err(StateError::Conflict)
        ));
        assert!(database.get("two").expect("read").is_none());
        assert_eq!(
            database
                .get("one")
                .expect("read")
                .expect("record")
                .decode::<u64>()
                .expect("number"),
            2
        );
    }

    #[test]
    fn invalid_or_future_database_is_preserved_and_never_reinitialized() {
        let fixture = Fixture::new();
        fs::write(fixture.path(), b"invalid database").expect("corrupt fixture");
        assert!(StateDatabase::open(fixture.path()).is_err());
        assert_eq!(
            fs::read(fixture.path()).expect("retained corrupt input"),
            b"invalid database"
        );
        fs::remove_file(fixture.path()).expect("remove owned corrupt fixture");
        let database = StateDatabase::open(fixture.path()).expect("create");
        let write = database.database.begin_write().expect("write");
        write
            .open_table(METADATA)
            .expect("table")
            .insert("schema", 99)
            .expect("future schema");
        write.commit().expect("commit");
        drop(database);
        assert!(matches!(
            StateDatabase::open(fixture.path()),
            Err(StateError::Schema)
        ));
        let raw = Database::open(fixture.path()).expect("database retained");
        assert_eq!(
            raw.begin_read()
                .expect("read")
                .open_table(METADATA)
                .expect("table")
                .get("schema")
                .expect("schema")
                .expect("marker")
                .value(),
            99
        );
    }

    #[test]
    fn bounds_and_duplicate_mutations_are_refused() {
        let fixture = Fixture::new();
        let database = StateDatabase::open(fixture.path()).expect("database");
        assert!(Mutation::put("", &1).is_err());
        assert!(Mutation::put("line\nkey", &1).is_err());
        assert!(Mutation::put("too-big", &"x".repeat(MAX_RECORD_BYTES + 1)).is_err());
        assert!(database.commit(Vec::new()).is_err());
        assert!(
            database
                .commit(vec![
                    Mutation::put("one", &1).expect("record"),
                    Mutation::put("one", &2).expect("record")
                ])
                .is_err()
        );
        assert!(database.get("one").expect("read").is_none());
    }

    #[test]
    fn live_database_lock_and_existing_empty_file_are_not_bypassed() {
        let fixture = Fixture::new();
        fs::write(fixture.path(), []).expect("empty input");
        assert!(matches!(
            StateDatabase::open(fixture.path()),
            Err(StateError::Schema)
        ));
        assert_eq!(
            fs::metadata(fixture.path()).expect("input preserved").len(),
            0
        );
        fs::remove_file(fixture.path()).expect("remove owned fixture");
        let database = StateDatabase::open(fixture.path()).expect("first owner");
        assert!(StateDatabase::open(fixture.path()).is_err());
        drop(database);
        assert!(StateDatabase::open(fixture.path()).is_ok());
    }

    #[test]
    fn pages_have_exclusive_cursors_and_do_not_cross_namespaces() {
        let fixture = Fixture::new();
        let database = StateDatabase::open(fixture.path()).expect("database");
        database
            .commit(
                ["session/a", "session/b", "session/c", "turn/a"]
                    .into_iter()
                    .map(|key| Mutation::put(key, &1).expect("record"))
                    .collect(),
            )
            .expect("commit");
        let first = database.page("session/", None, 2).expect("first page");
        assert_eq!(first.records.len(), 2);
        assert_eq!(first.next_cursor.as_deref(), Some("session/b"));
        let second = database
            .page("session/", first.next_cursor.as_deref(), 2)
            .expect("second page");
        assert_eq!(second.records.len(), 1);
        assert_eq!(second.records[0].0, "session/c");
        assert!(second.next_cursor.is_none());
        assert!(database.page("session/", Some("turn/a"), 2).is_err());
        assert!(database.page("session/", None, 0).is_err());
    }

    #[test]
    fn state_process_exit_helper() {
        let Some(path) = std::env::var_os("GTA_CLAW_STATE_TEST_PATH") else {
            return;
        };
        let mode = std::env::var("GTA_CLAW_STATE_TEST_MODE").expect("helper mode");
        let database = StateDatabase::open(path).expect("child database");
        if mode == "committed" {
            database
                .commit(vec![Mutation::put("value", &2).expect("record")])
                .expect("commit");
        } else {
            assert_eq!(mode, "uncommitted");
            let write = database.database.begin_write().expect("write");
            write
                .open_table(RECORDS)
                .expect("table")
                .insert("value", b"3".as_slice())
                .expect("uncommitted change");
            std::process::exit(0);
        }
        std::process::exit(0);
    }

    #[test]
    fn abrupt_process_exit_keeps_committed_and_discards_uncommitted_data() {
        let fixture = Fixture::new();
        let database = StateDatabase::open(fixture.path()).expect("database");
        database
            .commit(vec![Mutation::put("value", &1).expect("record")])
            .expect("initial commit");
        drop(database);
        for mode in ["committed", "uncommitted"] {
            let mut command =
                std::process::Command::new(std::env::current_exe().expect("test executable"));
            command.env_clear();
            #[cfg(windows)]
            for name in ["SystemRoot", "SystemDrive", "WINDIR"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            let output = command
                .args(["--exact", "tests::state_process_exit_helper", "--nocapture"])
                .env("GTA_CLAW_STATE_TEST_PATH", fixture.path())
                .env("GTA_CLAW_STATE_TEST_MODE", mode)
                .output()
                .expect("isolated child test");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let reopened = StateDatabase::open(fixture.path()).expect("recover database");
            assert_eq!(
                reopened
                    .get("value")
                    .expect("read")
                    .expect("value")
                    .decode::<u64>()
                    .expect("number"),
                2,
                "{mode}"
            );
        }
    }
}

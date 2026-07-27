//! The crash-safe, on-disk goal store.
//!
//! # Layout
//!
//! ```text
//! <root>/
//!   goals/<sha256(goal id)>.json      one encoded GoalRecord per file
//!   sessions/<sha256(session id)>.json  the session's goal ids, in creation order
//! ```
//!
//! Identifiers are hashed rather than used directly because a goal id is free text up to 128
//! bytes: it can contain `/`, `..`, a colon, a reserved Windows device name, or 128 bytes of
//! characters that a case-insensitive filesystem folds together. A fixed-width lowercase hex
//! digest is a filename on every host, and the identifier it stands for is written inside the
//! file, so nothing is lost.
//!
//! # Durability
//!
//! Every file is written to a uniquely named temporary sibling, flushed with
//! [`File::sync_all`](std::fs::File::sync_all), and then renamed over its target. `rename` over an
//! existing path is atomic on POSIX and on Windows, so a reader sees either the whole previous
//! record or the whole new one. A write is only acknowledged after the rename returns, which is
//! what lets [`FileGoalStore::open`] promise that an acknowledged goal survives the process.
//!
//! The record is written before the session index, so a crash between the two leaves a goal file
//! that no index mentions. That is the orphan case [`FileGoalStore::open`] repairs, and it is
//! deliberately the safe direction to fail in: an unindexed record can be adopted, whereas an
//! index entry pointing at a record that was never written cannot be reconstructed.
//!
//! # Blocking
//!
//! [`GoalStorePort`] is asynchronous, but local filesystem I/O is not. The futures returned here
//! are already-complete: the work happens before the future is handed back. That is honest for a
//! local disk and keeps the adapter usable from any executor; a network-backed store would want a
//! genuinely asynchronous implementation instead.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write as _};
use std::fs::{self, File};
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use claw_application::model::goal::GoalRecord;
use claw_application::model::ids::GoalId;
use claw_application::ports::goal::GoalStorePort;
use claw_application::ports::{PortError, PortFuture};
use claw_domain::SessionId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::budget::{BudgetUsage, GoalBudget};
use crate::wire::{self, WireError};

const GOALS_DIR: &str = "goals";
const SESSIONS_DIR: &str = "sessions";
const RECORD_EXTENSION: &str = "json";
const TEMP_PREFIX: &str = "pending-";

/// The persisted order of one session's goals.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SessionIndex {
    schema: u32,
    session_id: String,
    goal_ids: Vec<String>,
}

/// What [`FileGoalStore::open`] had to repair before the store was usable.
///
/// An empty report is the normal case. A non-empty one is not an error — the store recovered —
/// but it is a fact an operator is entitled to see, so it is returned rather than logged and
/// forgotten.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Temporary files left behind by a write that never reached its rename.
    pub discarded_partial_writes: usize,
    /// Goal records that existed but were missing from their session index.
    pub adopted_orphans: usize,
    /// Index entries naming a record that no longer exists.
    pub pruned_dangling: usize,
}

impl RecoveryReport {
    /// Returns whether the store opened over an untouched, fully consistent directory.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.discarded_partial_writes == 0 && self.adopted_orphans == 0 && self.pruned_dangling == 0
    }
}

/// A failure of the on-disk goal store.
#[derive(Debug)]
pub enum StoreError {
    /// The filesystem refused an operation.
    Io {
        /// The path involved, when one is known.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// A stored record could not be decoded.
    Corrupt {
        /// The file that could not be decoded.
        path: PathBuf,
        /// Why decoding failed.
        source: WireError,
    },
    /// A record could not be encoded.
    Encoding(WireError),
    /// The write conflicted with the revision already on disk.
    Conflict {
        /// The revision the caller was required to write.
        expected: u64,
        /// The revision the caller held.
        held: u64,
    },
    /// The write would exceed a session's budget.
    Budget(crate::budget::BudgetError),
}

impl Display for StoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "goal store io failed at {}: {source}",
                    path.display()
                )
            }
            Self::Corrupt { path, source } => {
                write!(
                    formatter,
                    "goal record at {} is corrupt: {source}",
                    path.display()
                )
            }
            Self::Encoding(source) => {
                write!(formatter, "goal record could not be encoded: {source}")
            }
            Self::Conflict { expected, held } => {
                write!(
                    formatter,
                    "expected revision {expected}, caller held {held}"
                )
            }
            Self::Budget(source) => Display::fmt(source, formatter),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Corrupt { source, .. } | Self::Encoding(source) => Some(source),
            Self::Budget(source) => Some(source),
            Self::Conflict { .. } => None,
        }
    }
}

impl From<StoreError> for PortError {
    /// Maps a store failure onto the port vocabulary the runtime branches on.
    ///
    /// A conflict stays a [`PortError::Conflict`] because retrying after a fresh read can
    /// succeed. Corruption and I/O become [`PortError::Unavailable`]: the goal may still exist,
    /// so claiming it is absent would let a caller silently start over and lose it. A budget
    /// refusal becomes [`PortError::Invalid`] because retrying the same write never succeeds.
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::Conflict { expected, held } => {
                Self::Conflict(format!("expected revision {expected}, caller held {held}"))
            }
            StoreError::Budget(error) => Self::Invalid(error.to_string()),
            other => Self::Unavailable(other.to_string()),
        }
    }
}

fn io_error(path: &Path, source: std::io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Returns the lowercase hex SHA-256 of an identifier, used as its filename stem.
fn digest_of(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// A durable [`GoalStorePort`] backed by a directory.
#[derive(Debug)]
pub struct FileGoalStore {
    root: PathBuf,
    budget: GoalBudget,
    recovery: RecoveryReport,
    /// Serialises the read-modify-write of a save within one process.
    ///
    /// The revision check is only meaningful if the load and the rename cannot interleave with
    /// another save of the same goal. Across processes the same protection comes from the
    /// revision itself: the loser's rename lands, but its revision no longer matches and the
    /// caller is told to re-read.
    writes: Mutex<()>,
    /// Feeds the unique suffix of temporary files so two concurrent writers never share one.
    sequence: AtomicU64,
    accepted_writes: AtomicU64,
}

impl FileGoalStore {
    /// Opens a store over `root`, creating the layout and repairing what it finds.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] when the layout cannot be created or scanned and
    /// [`StoreError::Corrupt`] when a record on disk cannot be decoded. Opening deliberately
    /// fails on corruption instead of skipping the record: a goal that cannot be read is not the
    /// same as a goal that was never set.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_budget(root, GoalBudget::default())
    }

    /// Opens a store with explicit ceilings.
    ///
    /// # Errors
    ///
    /// As [`FileGoalStore::open`].
    pub fn open_with_budget(
        root: impl AsRef<Path>,
        budget: GoalBudget,
    ) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        for directory in [root.join(GOALS_DIR), root.join(SESSIONS_DIR)] {
            fs::create_dir_all(&directory).map_err(|error| io_error(&directory, error))?;
        }

        let mut store = Self {
            root,
            budget,
            recovery: RecoveryReport::default(),
            writes: Mutex::new(()),
            sequence: AtomicU64::new(0),
            accepted_writes: AtomicU64::new(0),
        };
        store.recovery = store.recover()?;
        Ok(store)
    }

    /// Returns the directory this store owns.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the ceilings this store enforces.
    #[must_use]
    pub const fn budget(&self) -> GoalBudget {
        self.budget
    }

    /// Returns what opening the store had to repair.
    #[must_use]
    pub const fn recovery(&self) -> &RecoveryReport {
        &self.recovery
    }

    /// Returns how many writes this store instance accepted.
    ///
    /// Refused writes are not counted, which is what makes this usable as evidence that a
    /// rejected save touched nothing.
    #[must_use]
    pub fn accepted_writes(&self) -> u64 {
        self.accepted_writes.load(Ordering::SeqCst)
    }

    /// Returns what one session currently occupies.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] when the index or a record cannot be inspected.
    pub fn usage(&self, session_id: &SessionId) -> Result<BudgetUsage, StoreError> {
        let index = self.read_index(session_id)?;
        let mut usage = BudgetUsage {
            goals: index.goal_ids.len(),
            bytes: 0,
        };
        for goal_id in &index.goal_ids {
            let path = self.record_path_for(goal_id);
            match fs::metadata(&path) {
                Ok(metadata) => usage.bytes = usage.bytes.saturating_add(metadata.len()),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(&path, error)),
            }
        }
        Ok(usage)
    }

    fn goals_dir(&self) -> PathBuf {
        self.root.join(GOALS_DIR)
    }

    fn sessions_dir(&self) -> PathBuf {
        self.root.join(SESSIONS_DIR)
    }

    fn record_path_for(&self, goal_id: &str) -> PathBuf {
        self.goals_dir()
            .join(format!("{}.{RECORD_EXTENSION}", digest_of(goal_id)))
    }

    fn index_path_for(&self, session_id: &str) -> PathBuf {
        self.sessions_dir()
            .join(format!("{}.{RECORD_EXTENSION}", digest_of(session_id)))
    }

    /// Writes `contents` to `path` so that a reader sees all of it or none of it.
    fn write_atomically(&self, path: &Path, contents: &str) -> Result<(), StoreError> {
        let directory = path.parent().unwrap_or(&self.root);
        let ordinal = self.sequence.fetch_add(1, Ordering::SeqCst);
        let temporary = directory.join(format!("{TEMP_PREFIX}{}-{ordinal}", std::process::id()));

        {
            let mut file = File::create(&temporary).map_err(|error| io_error(&temporary, error))?;
            file.write_all(contents.as_bytes())
                .map_err(|error| io_error(&temporary, error))?;
            file.sync_all()
                .map_err(|error| io_error(&temporary, error))?;
        }

        match fs::rename(&temporary, path) {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                Err(io_error(path, error))
            }
        }
    }

    fn read_record_at(path: &Path) -> Result<Option<GoalRecord>, StoreError> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(path, error)),
        };
        wire::decode(&text)
            .map(Some)
            .map_err(|source| StoreError::Corrupt {
                path: path.to_path_buf(),
                source,
            })
    }

    fn read_index(&self, session_id: &SessionId) -> Result<SessionIndex, StoreError> {
        let path = self.index_path_for(session_id.as_str());
        match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).map_err(|error| StoreError::Corrupt {
                path,
                source: WireError::Malformed(error.to_string()),
            }),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(SessionIndex {
                schema: wire::SCHEMA_VERSION,
                session_id: session_id.as_str().to_owned(),
                goal_ids: Vec::new(),
            }),
            Err(error) => Err(io_error(&path, error)),
        }
    }

    fn write_index(&self, index: &SessionIndex) -> Result<(), StoreError> {
        let path = self.index_path_for(&index.session_id);
        let mut text = serde_json::to_string_pretty(index)
            .map_err(|error| StoreError::Encoding(WireError::Malformed(error.to_string())))?;
        text.push('\n');
        self.write_atomically(&path, &text)
    }

    /// Loads every record on disk, keyed by goal id.
    fn scan_records(&self) -> Result<BTreeMap<String, GoalRecord>, StoreError> {
        let directory = self.goals_dir();
        let mut records = BTreeMap::new();
        for entry in fs::read_dir(&directory).map_err(|error| io_error(&directory, error))? {
            let entry = entry.map_err(|error| io_error(&directory, error))?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some(RECORD_EXTENSION) {
                continue;
            }
            if let Some(record) = Self::read_record_at(&path)? {
                records.insert(record.goal_id.as_str().to_owned(), record);
            }
        }
        Ok(records)
    }

    /// Removes leftover temporary files, adopts unindexed records, and prunes dangling entries.
    fn recover(&self) -> Result<RecoveryReport, StoreError> {
        let mut report = RecoveryReport::default();

        for directory in [self.goals_dir(), self.sessions_dir()] {
            for entry in fs::read_dir(&directory).map_err(|error| io_error(&directory, error))? {
                let entry = entry.map_err(|error| io_error(&directory, error))?;
                let path = entry.path();
                let is_temporary = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(TEMP_PREFIX));
                if is_temporary {
                    fs::remove_file(&path).map_err(|error| io_error(&path, error))?;
                    report.discarded_partial_writes += 1;
                }
            }
        }

        let records = self.scan_records()?;
        let mut by_session: BTreeMap<String, Vec<&GoalRecord>> = BTreeMap::new();
        for record in records.values() {
            by_session
                .entry(record.session_id.as_str().to_owned())
                .or_default()
                .push(record);
        }

        // Sessions whose index exists but whose records are gone still need pruning, so the
        // walk covers every index file as well as every session named by a record.
        let sessions_dir = self.sessions_dir();
        let mut sessions: BTreeSet<String> = by_session.keys().cloned().collect();
        for entry in fs::read_dir(&sessions_dir).map_err(|error| io_error(&sessions_dir, error))? {
            let entry = entry.map_err(|error| io_error(&sessions_dir, error))?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some(RECORD_EXTENSION) {
                continue;
            }
            let text = fs::read_to_string(&path).map_err(|error| io_error(&path, error))?;
            let index: SessionIndex =
                serde_json::from_str(&text).map_err(|error| StoreError::Corrupt {
                    path: path.clone(),
                    source: WireError::Malformed(error.to_string()),
                })?;
            sessions.insert(index.session_id);
        }

        for session in sessions {
            let session_id =
                SessionId::new(session.clone()).map_err(|error| StoreError::Corrupt {
                    path: self.index_path_for(&session),
                    source: WireError::Invalid {
                        field: "session_id",
                        reason: error.to_string(),
                    },
                })?;
            let mut index = self.read_index(&session_id)?;
            let indexed = index.goal_ids.len();

            index
                .goal_ids
                .retain(|goal_id| records.contains_key(goal_id));
            let pruned = indexed - index.goal_ids.len();

            let mut orphans: Vec<&GoalRecord> = by_session
                .get(&session)
                .map(|records| {
                    records
                        .iter()
                        .filter(|record| {
                            !index
                                .goal_ids
                                .iter()
                                .any(|id| id == record.goal_id.as_str())
                        })
                        .copied()
                        .collect()
                })
                .unwrap_or_default();
            // Creation order is the order the index is supposed to hold; the identifier breaks
            // ties deterministically when a clock did not advance between two goals.
            orphans.sort_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then_with(|| left.goal_id.as_str().cmp(right.goal_id.as_str()))
            });
            let adopted = orphans.len();
            for record in orphans {
                index.goal_ids.push(record.goal_id.as_str().to_owned());
            }

            report.pruned_dangling += pruned;
            report.adopted_orphans += adopted;
            if pruned > 0 || adopted > 0 {
                self.write_index(&index)?;
            }
        }

        Ok(report)
    }

    fn save_blocking(&self, record: &GoalRecord) -> Result<(), StoreError> {
        let encoded = wire::encode(record).map_err(StoreError::Encoding)?;
        let path = self.record_path_for(record.goal_id.as_str());

        let _guard = self.writes.lock().unwrap_or_else(|poisoned| {
            // A poisoned lock means some other caller panicked mid-save. The next save still has
            // to check the revision it finds on disk, which is unaffected by that panic.
            poisoned.into_inner()
        });

        let existing = Self::read_record_at(&path)?;
        let expected = existing
            .as_ref()
            .map_or(1, |stored| stored.revision.saturating_add(1));
        if record.revision != expected {
            return Err(StoreError::Conflict {
                expected,
                held: record.revision,
            });
        }

        let mut index = self.read_index(&record.session_id)?;
        let is_new = !index
            .goal_ids
            .iter()
            .any(|goal_id| goal_id == record.goal_id.as_str());

        let mut held = self.usage(&record.session_id)?;
        if !is_new {
            // A replacement is charged its new size, not its old size as well.
            let existing_bytes = fs::metadata(&path).map_or(0, |metadata| metadata.len());
            held.bytes = held.bytes.saturating_sub(existing_bytes);
        }
        self.budget
            .admit(held, encoded.len(), is_new)
            .map_err(StoreError::Budget)?;

        self.write_atomically(&path, &encoded)?;

        if is_new {
            index.goal_ids.push(record.goal_id.as_str().to_owned());
            self.write_index(&index)?;
        }

        self.accepted_writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn list_blocking(&self, session_id: &SessionId) -> Result<Vec<GoalRecord>, StoreError> {
        let index = self.read_index(session_id)?;
        let mut records = Vec::with_capacity(index.goal_ids.len());
        for goal_id in &index.goal_ids {
            let path = self.record_path_for(goal_id);
            let record = Self::read_record_at(&path)?.ok_or_else(|| StoreError::Corrupt {
                path,
                source: WireError::Invalid {
                    field: "goal_ids",
                    reason: format!("the index names {goal_id}, which no longer exists"),
                },
            })?;
            records.push(record);
        }
        Ok(records)
    }
}

impl GoalStorePort for FileGoalStore {
    fn load(&self, goal_id: &GoalId) -> PortFuture<'_, Result<Option<GoalRecord>, PortError>> {
        let outcome =
            Self::read_record_at(&self.record_path_for(goal_id.as_str())).map_err(PortError::from);
        Box::pin(async move { outcome })
    }

    fn save(&self, record: GoalRecord) -> PortFuture<'_, Result<(), PortError>> {
        let outcome = self.save_blocking(&record).map_err(PortError::from);
        Box::pin(async move { outcome })
    }

    fn list_for_session(
        &self,
        session_id: &SessionId,
    ) -> PortFuture<'_, Result<Vec<GoalRecord>, PortError>> {
        let outcome = self.list_blocking(session_id).map_err(PortError::from);
        Box::pin(async move { outcome })
    }
}

#[cfg(test)]
mod tests {
    use super::{FileGoalStore, StoreError, digest_of};
    use crate::budget::{BudgetError, GoalBudget};
    use crate::testing::{TempRoot, goal_id, record, session_id};
    use claw_application::ports::PortError;

    #[test]
    fn identifiers_become_fixed_width_lowercase_filenames() {
        let digest = digest_of("session/../../etc:goal-1");

        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(digest, digest_of("session/../../etc:goal-2"));
    }

    #[test]
    fn a_path_traversing_identifier_stays_inside_the_store() {
        let root = TempRoot::new("traversal");
        let store = FileGoalStore::open(root.path()).expect("store opens");
        let hostile = "../../../../etc/passwd";

        let path = store.record_path_for(hostile);

        assert!(path.starts_with(root.path()));
        assert_eq!(
            path.components()
                .filter(|component| component.as_os_str() == std::ffi::OsStr::new(".."))
                .count(),
            0
        );
    }

    #[test]
    fn a_rejected_revision_writes_nothing_at_all() {
        let root = TempRoot::new("revision");
        let store = FileGoalStore::open(root.path()).expect("store opens");
        let mut first = record("s", "s:goal-1", "objective", 1);

        store.save_blocking(&first).expect("the first write lands");
        first.revision = 5;
        let error = store
            .save_blocking(&first)
            .expect_err("a stale revision is refused");

        assert!(matches!(
            error,
            StoreError::Conflict {
                expected: 2,
                held: 5
            }
        ));
        assert_eq!(store.accepted_writes(), 1);
        let stored = FileGoalStore::read_record_at(&store.record_path_for("s:goal-1"))
            .expect("readable")
            .expect("present");
        assert_eq!(stored.revision, 1);
    }

    #[test]
    fn a_budget_refusal_leaves_the_store_untouched() {
        let root = TempRoot::new("budget");
        let store = FileGoalStore::open_with_budget(
            root.path(),
            GoalBudget {
                max_goals_per_session: 1,
                max_record_bytes: 64 * 1024,
                max_session_bytes: 64 * 1024,
            },
        )
        .expect("store opens");

        store
            .save_blocking(&record("s", "s:goal-1", "first", 1))
            .expect("the first goal fits");
        let error = store
            .save_blocking(&record("s", "s:goal-2", "second", 1))
            .expect_err("the second goal does not");

        assert!(matches!(
            error,
            StoreError::Budget(BudgetError::TooManyGoals { limit: 1, held: 1 })
        ));
        assert_eq!(store.accepted_writes(), 1);
        assert!(!store.record_path_for("s:goal-2").exists());
        assert_eq!(store.usage(&session_id("s")).expect("usage").goals, 1);
    }

    #[test]
    fn store_failures_map_onto_the_port_vocabulary_the_runtime_branches_on() {
        let conflict: PortError = StoreError::Conflict {
            expected: 2,
            held: 1,
        }
        .into();
        assert_eq!(
            conflict,
            PortError::Conflict("expected revision 2, caller held 1".to_owned())
        );
        assert!(conflict.is_retryable());

        let budget: PortError =
            StoreError::Budget(BudgetError::TooManyGoals { limit: 1, held: 1 }).into();
        assert_eq!(budget.label(), "invalid");
        assert!(!budget.is_retryable());
    }

    #[test]
    fn a_goal_id_that_is_not_indexed_is_still_loadable_by_id() {
        let root = TempRoot::new("load-by-id");
        let store = FileGoalStore::open(root.path()).expect("store opens");
        store
            .save_blocking(&record("s", "s:goal-1", "objective", 1))
            .expect("write lands");

        let loaded = FileGoalStore::read_record_at(&store.record_path_for("s:goal-1"))
            .expect("readable")
            .expect("present");

        assert_eq!(loaded.goal_id, goal_id("s:goal-1"));
        assert_eq!(loaded.objective, "objective");
    }
}

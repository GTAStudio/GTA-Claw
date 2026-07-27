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
//! [`File::sync_all`](std::fs::File::sync_all), renamed over its target, and then the directory
//! holding it is opened and `fsync`-ed in turn. `rename` over an existing path is atomic on POSIX
//! and on Windows, so a reader sees either the whole previous record or the whole new one; the
//! directory sync is what makes the rename itself survive sudden power loss, because a synced
//! file whose new directory entry is still only in the page cache can come back under its old
//! name. A write is only acknowledged once both steps have run, which is what lets
//! [`FileGoalStore::open`] promise that an acknowledged goal survives the process — and, when the
//! directory sync succeeded, the machine.
//!
//! Only Unix exposes directory synchronization through [`std`]. On every other target the step is
//! skipped, and [`FileGoalStore::synced_publications`] does not count the publication, so the
//! store never claims a guarantee the platform did not give it. A directory sync that is attempted
//! and fails is *not* an error: by then the new bytes are published and the previous ones are
//! gone, so there is nothing to roll back and nothing to retry. It is counted in
//! [`FileGoalStore::unsynced_publications`] instead, which is the only signal that carries it.
//!
//! The record is written before the session index, so a crash between the two leaves a goal file
//! that no index mentions. That is the orphan case [`FileGoalStore::open`] repairs, and it is
//! deliberately the safe direction to fail in: an unindexed record can be adopted, whereas an
//! index entry pointing at a record that was never written cannot be reconstructed.
//!
//! # Blocking
//!
//! [`GoalStorePort`] is asynchronous, but local filesystem I/O is not. The futures returned here
//! are already-complete: the work happens before the future is handed back. Dropping one of these
//! futures therefore cannot cancel or roll back the operation; callers that need pre-commit
//! cancellation must decide that before invoking the port.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write as _};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

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
const WRITE_LOCK_FILE: &str = ".goal-store.lock";

/// Maximum attempts made to acquire the cross-process store lock.
pub const WRITE_LOCK_ATTEMPTS: usize = 64;

/// Delay between cross-process store-lock attempts.
pub const WRITE_LOCK_RETRY_DELAY: Duration = Duration::from_millis(1);

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

/// Observable result of compacting progress payloads in closed goals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompactionSummary {
    /// Closed goals inspected.
    pub closed_goals_examined: usize,
    /// Goal records rewritten with a smaller progress history.
    pub goals_rewritten: usize,
    /// Progress entries removed from rewritten records.
    pub progress_entries_removed: usize,
    /// On-disk record bytes reclaimed.
    pub reclaimed_bytes: u64,
    /// Goal identities retained in the session history.
    pub goal_ids_preserved: usize,
}

impl CompactionSummary {
    /// Returns whether every closed goal was already within the requested history bound.
    #[must_use]
    pub const fn is_noop(&self) -> bool {
        self.goals_rewritten == 0
    }
}

/// Execution semantics callers may need before invoking the synchronous disk port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreOperationSemantics {
    /// Whether dropping the returned future can stop work that has not committed.
    pub cancellable_after_invocation: bool,
    /// Whether mutations are serialized with other store instances and processes.
    pub cross_process_serialized: bool,
    /// Maximum attempts made before a contended operation reports [`StoreError::Busy`].
    pub write_lock_attempts: usize,
    /// Delay between lock attempts.
    pub write_lock_retry_delay: Duration,
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
    /// Another process held the store lock for the full bounded wait.
    Busy {
        /// Number of acquisition attempts made.
        attempts: usize,
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
            Self::Busy { attempts } => {
                write!(
                    formatter,
                    "goal store remained busy after {attempts} lock attempts"
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
            Self::Conflict { .. } | Self::Busy { .. } => None,
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
            StoreError::Busy { attempts } => {
                Self::Conflict(format!("goal store busy after {attempts} lock attempts"))
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

struct HeldStoreLock<'a> {
    file: &'a File,
    path: &'a Path,
    released: bool,
}

impl HeldStoreLock<'_> {
    fn release(mut self) -> Result<(), StoreError> {
        self.file
            .unlock()
            .map_err(|error| io_error(self.path, error))?;
        self.released = true;
        Ok(())
    }
}

impl Drop for HeldStoreLock<'_> {
    fn drop(&mut self) {
        if !self.released {
            let _ = self.file.unlock();
        }
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

/// Flushes a directory's own entries, reporting whether the flush was actually performed.
///
/// `Ok(false)` means the target has no directory synchronization to perform, not that one was
/// skipped: [`std`] exposes it only on Unix, so the same platform split `claw-config` uses for its
/// atomic writer is reproduced here. Callers distinguish the two so that a store never reports a
/// power-loss guarantee the platform never gave.
#[cfg(unix)]
fn sync_directory_entries(directory: &Path) -> std::io::Result<bool> {
    File::open(directory)?.sync_all()?;
    Ok(true)
}

/// Reports that no directory synchronization exists on this target.
#[cfg(not(unix))]
fn sync_directory_entries(_directory: &Path) -> std::io::Result<bool> {
    Ok(false)
}

/// A durable [`GoalStorePort`] backed by a directory.
#[derive(Debug)]
pub struct FileGoalStore {
    root: PathBuf,
    budget: GoalBudget,
    recovery: RecoveryReport,
    /// Serialises lock acquisition within one process.
    writes: Mutex<()>,
    /// Advisory lock held across each read/check/write transaction.
    write_lock: File,
    write_lock_path: PathBuf,
    /// Feeds the unique suffix of temporary files so two concurrent writers never share one.
    sequence: AtomicU64,
    accepted_writes: AtomicU64,
    synced_publications: AtomicU64,
    unsynced_publications: AtomicU64,
    unlock_failures: AtomicU64,
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
        let write_lock_path = root.join(WRITE_LOCK_FILE);
        let write_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&write_lock_path)
            .map_err(|error| io_error(&write_lock_path, error))?;

        let mut store = Self {
            root,
            budget,
            recovery: RecoveryReport::default(),
            writes: Mutex::new(()),
            write_lock,
            write_lock_path,
            sequence: AtomicU64::new(0),
            accepted_writes: AtomicU64::new(0),
            synced_publications: AtomicU64::new(0),
            unsynced_publications: AtomicU64::new(0),
            unlock_failures: AtomicU64::new(0),
        };
        store.recovery = store.with_store_lock(|| store.recover())?;
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

    /// Returns the cancellation, concurrency, and bounded-wait behavior of this adapter.
    #[must_use]
    pub const fn operation_semantics(&self) -> StoreOperationSemantics {
        StoreOperationSemantics {
            cancellable_after_invocation: false,
            cross_process_serialized: true,
            write_lock_attempts: WRITE_LOCK_ATTEMPTS,
            write_lock_retry_delay: WRITE_LOCK_RETRY_DELAY,
        }
    }

    /// Returns how many writes this store instance accepted.
    ///
    /// Refused writes are not counted, which is what makes this usable as evidence that a
    /// rejected save touched nothing.
    #[must_use]
    pub fn accepted_writes(&self) -> u64 {
        self.accepted_writes.load(Ordering::SeqCst)
    }

    /// Returns how many files this store published into a synchronized directory.
    ///
    /// A save publishes the record, and a save that adds a goal to a session publishes the index
    /// too, so this counts files rather than saves. It is incremented only after the directory
    /// holding the file has been `fsync`-ed, which makes it the evidence that the rename itself is
    /// power-loss durable and not merely atomic.
    ///
    /// This stays at zero on targets where [`std`] exposes no directory synchronization, which is
    /// everything but Unix. Zero there means "the platform offers no such step", not "the step was
    /// skipped".
    #[must_use]
    pub fn synced_publications(&self) -> u64 {
        self.synced_publications.load(Ordering::SeqCst)
    }

    /// Returns how many files were published but whose directory could not be synchronized.
    ///
    /// This is not an error count: every write it counts is on disk and was acknowledged. It is
    /// the one signal that separates "the bytes are published" from "the publication will still be
    /// there after a power cut", so a caller that must not confuse the two has to read it. A
    /// healthy store leaves it at zero.
    #[must_use]
    pub fn unsynced_publications(&self) -> u64 {
        self.unsynced_publications.load(Ordering::SeqCst)
    }

    /// Returns how many explicit store-lock releases failed.
    ///
    /// A failed release never changes the result of work that already
    /// committed. The lock guard retries during drop, while this counter lets
    /// operators distinguish a healthy release path from degraded filesystem
    /// lock behavior.
    #[must_use]
    pub fn unlock_failures(&self) -> u64 {
        self.unlock_failures.load(Ordering::SeqCst)
    }

    /// Returns what one session currently occupies.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] when the index or a record cannot be inspected.
    pub fn usage(&self, session_id: &SessionId) -> Result<BudgetUsage, StoreError> {
        self.with_store_lock(|| self.usage_unlocked(session_id))
    }

    fn usage_unlocked(&self, session_id: &SessionId) -> Result<BudgetUsage, StoreError> {
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

    /// Compacts progress payloads in closed goals while preserving every goal identity.
    ///
    /// Goal files and index entries are deliberately retained: the runtime mints
    /// the next goal identifier from history length, so deleting an old entry
    /// would permit identifier reuse. The newest `keep_recent_progress` entries
    /// remain available on each closed goal; older entries are folded into
    /// `compacted_entries`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Busy`] when another process holds the store lock
    /// for the bounded acquisition window, or the relevant encoding and I/O
    /// failures.
    pub fn compact_closed_history(
        &self,
        session_id: &SessionId,
        keep_recent_progress: usize,
    ) -> Result<CompactionSummary, StoreError> {
        self.with_store_lock(|| {
            let index = self.read_index(session_id)?;
            let mut summary = CompactionSummary {
                goal_ids_preserved: index.goal_ids.len(),
                ..CompactionSummary::default()
            };
            for goal_id in &index.goal_ids {
                let path = self.record_path_for(goal_id);
                let Some(mut record) = Self::read_record_at(&path)? else {
                    return Err(StoreError::Corrupt {
                        path,
                        source: WireError::Invalid {
                            field: "goal_ids",
                            reason: format!("the index names {goal_id}, which no longer exists"),
                        },
                    });
                };
                if !record.status.is_closed() {
                    continue;
                }
                summary.closed_goals_examined += 1;
                let remove = record.progress.len().saturating_sub(keep_recent_progress);
                if remove == 0 {
                    continue;
                }

                let previous_bytes = fs::metadata(&path)
                    .map_err(|error| io_error(&path, error))?
                    .len();
                let newly_compacted = record.progress[..remove]
                    .iter()
                    .filter(|entry| !entry.compacted)
                    .count();
                record.progress.drain(..remove);
                record.compacted_entries = record
                    .compacted_entries
                    .saturating_add(u64::try_from(newly_compacted).unwrap_or(u64::MAX));
                record.revision = record.revision.saturating_add(1);

                let encoded = wire::encode(&record).map_err(StoreError::Encoding)?;
                self.write_atomically(&path, &encoded)?;
                self.accepted_writes.fetch_add(1, Ordering::SeqCst);

                summary.goals_rewritten += 1;
                summary.progress_entries_removed =
                    summary.progress_entries_removed.saturating_add(remove);
                summary.reclaimed_bytes = summary
                    .reclaimed_bytes
                    .saturating_add(previous_bytes.saturating_sub(encoded.len() as u64));
            }
            Ok(summary)
        })
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

    /// Writes `contents` to `path` so that a reader sees all of it or none of it, and so that the
    /// publication survives a power cut rather than only a process crash.
    ///
    /// The temporary sibling is flushed before the rename and the directory holding it is flushed
    /// after, because a rename whose directory entry is still only in the page cache can be lost
    /// even though every byte of the file it names was already on the platter.
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

        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(io_error(path, error));
        }

        // Both the temporary file's creation and its rename are entries in this one directory, so
        // a single sync after the rename covers the whole publication. A failure here is recorded
        // rather than returned: the new bytes are already in place and the previous ones are
        // already gone, so reporting failure would tell the caller to retry a write that in fact
        // landed, and the revision check would then refuse the retry.
        match sync_directory_entries(directory) {
            Ok(true) => {
                self.synced_publications.fetch_add(1, Ordering::SeqCst);
            }
            Ok(false) => {}
            Err(_) => {
                self.unsynced_publications.fetch_add(1, Ordering::SeqCst);
            }
        }
        Ok(())
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

    fn with_store_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let _guard = self.writes.lock().unwrap_or_else(|poisoned| {
            // Disk state, not mutex poison, decides whether the next operation is valid.
            poisoned.into_inner()
        });
        let mut acquired = false;
        for attempt in 1..=WRITE_LOCK_ATTEMPTS {
            match self.write_lock.try_lock() {
                Ok(()) => {
                    acquired = true;
                    break;
                }
                Err(std::fs::TryLockError::WouldBlock) if attempt < WRITE_LOCK_ATTEMPTS => {
                    thread::sleep(WRITE_LOCK_RETRY_DELAY);
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(StoreError::Busy {
                        attempts: WRITE_LOCK_ATTEMPTS,
                    });
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(io_error(&self.write_lock_path, error));
                }
            }
        }
        if !acquired {
            return Err(StoreError::Busy {
                attempts: WRITE_LOCK_ATTEMPTS,
            });
        }

        let lock = HeldStoreLock {
            file: &self.write_lock,
            path: &self.write_lock_path,
            released: false,
        };
        let outcome = operation();
        let release_failed = lock.release().is_err();
        self.finish_locked_operation(outcome, release_failed)
    }

    fn finish_locked_operation<T>(
        &self,
        outcome: Result<T, StoreError>,
        release_failed: bool,
    ) -> Result<T, StoreError> {
        if release_failed {
            self.unlock_failures.fetch_add(1, Ordering::SeqCst);
        }
        outcome
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

        self.with_store_lock(|| {
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

            let mut held = self.usage_unlocked(&record.session_id)?;
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
        })
    }

    fn list_blocking(&self, session_id: &SessionId) -> Result<Vec<GoalRecord>, StoreError> {
        self.with_store_lock(|| {
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
        })
    }
}

impl GoalStorePort for FileGoalStore {
    fn load(&self, goal_id: &GoalId) -> PortFuture<'_, Result<Option<GoalRecord>, PortError>> {
        let outcome =
            Self::read_record_at(&self.record_path_for(goal_id.as_str())).map_err(PortError::from);
        Box::pin(async move { outcome })
    }

    fn save(&self, record: GoalRecord) -> PortFuture<'_, Result<(), PortError>> {
        // Work intentionally completes before this future exists. Dropping it
        // cannot cancel or roll back a local filesystem mutation.
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
    use crate::testing::{TempRoot, block_on, goal_id, record, session_id};
    use claw_application::ports::PortError;
    use claw_application::ports::goal::GoalStorePort;
    use std::fs::OpenOptions;
    use std::sync::{Arc, Barrier};
    use std::thread;

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
    fn independent_store_instances_serialize_the_same_revision() {
        let root = TempRoot::new("cross-instance-write");
        let first = Arc::new(FileGoalStore::open(root.path()).expect("first store opens"));
        let second = Arc::new(FileGoalStore::open(root.path()).expect("second store opens"));
        let barrier = Arc::new(Barrier::new(3));

        let workers = [Arc::clone(&first), Arc::clone(&second)].map(|store| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let candidate = record("s", "s:goal-1", "objective", 1);
                barrier.wait();
                store.save_blocking(&candidate)
            })
        });
        barrier.wait();
        let outcomes = workers.map(|worker| worker.join().expect("writer did not panic"));

        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Err(StoreError::Conflict { .. })))
                .count(),
            1
        );
        assert_eq!(
            first.accepted_writes() + second.accepted_writes(),
            1,
            "only the serialized winner is acknowledged"
        );
    }

    #[test]
    fn lock_contention_has_a_bounded_actionable_failure() {
        let root = TempRoot::new("write-lock-busy");
        let store = FileGoalStore::open(root.path()).expect("store opens");
        let external = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&store.write_lock_path)
            .expect("lock file opens");
        external.lock().expect("external holder acquires the lock");

        let error = store
            .save_blocking(&record("s", "s:goal-1", "objective", 1))
            .expect_err("the bounded wait expires");
        assert!(matches!(
            error,
            StoreError::Busy {
                attempts: super::WRITE_LOCK_ATTEMPTS
            }
        ));

        external.unlock().expect("external lock releases");
        store
            .save_blocking(&record("s", "s:goal-1", "objective", 1))
            .expect("the operation succeeds once contention clears");
    }

    #[test]
    fn dropping_an_unpolled_save_future_does_not_claim_cancellation() {
        let root = TempRoot::new("save-cancellation");
        let store = FileGoalStore::open(root.path()).expect("store opens");
        let semantics = store.operation_semantics();
        assert!(!semantics.cancellable_after_invocation);
        assert!(semantics.cross_process_serialized);

        let future = GoalStorePort::save(&store, record("s", "s:goal-1", "objective", 1));
        drop(future);

        let loaded = block_on(GoalStorePort::load(&store, &goal_id("s:goal-1")))
            .expect("load succeeds")
            .expect("the synchronous save committed before its future was returned");
        assert_eq!(loaded.objective, "objective");
    }

    #[test]
    fn an_unlock_failure_never_overwrites_a_committed_outcome() {
        let root = TempRoot::new("unlock-outcome");
        let store = FileGoalStore::open(root.path()).expect("store opens");
        let committed = store
            .finish_locked_operation(Ok("committed"), true)
            .expect("the committed outcome wins");
        assert_eq!(committed, "committed");
        assert!(matches!(
            store.finish_locked_operation::<()>(Err(StoreError::Busy { attempts: 7 }), true),
            Err(StoreError::Busy { attempts: 7 })
        ));
        assert_eq!(store.unlock_failures(), 2);
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

        let busy: PortError = StoreError::Busy { attempts: 64 }.into();
        assert_eq!(
            busy,
            PortError::Conflict("goal store busy after 64 lock attempts".to_owned())
        );
        assert!(busy.is_retryable());

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

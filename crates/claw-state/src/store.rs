use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Mutex;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
#[cfg(unix)]
use std::sync::{LazyLock, Mutex as StdMutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Connection, Row, SqliteConnection, SqlitePool};

use crate::error::{database, database_code};
use crate::{
    AuthenticationRepository, DeviceRepository, SessionRepository, StateError, TaskRepository,
};

const APPLICATION_ID: i64 = 0x4754_4143;
const LATEST_SCHEMA_VERSION: i64 = 2;
const SNAPSHOT_PROVENANCE_OWNER: &str = "gta-claw-standalone-snapshot-v1";
#[cfg(unix)]
const UNIX_LOCK_IDENTITY_XATTR: &str = "user.gta-claw.writer-lock-path";
#[cfg(unix)]
const UNIX_BACKUP_SEAL_XATTR: &str = "user.gta-claw.backup-seal-id";
#[cfg(unix)]
const UNIX_SIDECAR_GENERATION_XATTR: &str = "user.gta-claw.sidecar-generation";
const BACKUP_SEAL_MAGIC: &str = "gta-claw-backup-seal-v1";
const MAX_CONFIGURED_TIMEOUT: Duration = Duration::from_secs(60);

fn file_control_database(
    operation: &'static str,
    error: claw_sqlite_file_control::FileControlError,
) -> StateError {
    error.code().map_or_else(
        || database(operation, sqlx::Error::Protocol(error.to_string())),
        |code| database_code(operation, code, error.to_string()),
    )
}
#[cfg(test)]
static FAIL_AFTER_PUBLICATION: std::sync::LazyLock<Mutex<std::collections::HashSet<PathBuf>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static CREATE_DESTINATION_BEFORE_PUBLICATION: std::sync::LazyLock<
    Mutex<std::collections::HashSet<PathBuf>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static CREATE_BACKUP_TEMP_BEFORE_VACUUM: std::sync::LazyLock<
    Mutex<std::collections::HashSet<PathBuf>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static FAIL_BACKUP_HANDLER_RESET: std::sync::LazyLock<Mutex<std::collections::HashSet<PathBuf>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(all(test, windows))]
static FAIL_WINDOWS_SOURCE_REMOVAL: std::sync::LazyLock<Mutex<std::collections::HashSet<PathBuf>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static MIGRATION_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static OPEN_INITIALIZATION_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static OPEN_PRECOMMIT_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static OPEN_POSTCOMMIT_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(all(test, unix))]
static CHECKPOINT_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static SNAPSHOT_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, SnapshotTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static PUBLISHED_HANDOFF_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static BACKUP_CAPTURE_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, Arc<claw_sqlite_file_control::VacuumExecutionGate>>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static FINAL_CONNECTION_CLOSE_FAILURES: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, FinalConnectionCloseFailure>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
struct MigrationTestBarrier {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
struct SnapshotTestBarrier {
    temporary: Arc<Mutex<Option<PathBuf>>>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum FinalConnectionCloseFailure {
    Error,
    Timeout,
}
const MIGRATION_TABLE_SQL: &str = "
CREATE TABLE IF NOT EXISTS claw_schema_migrations (
    version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
    name TEXT NOT NULL,
    checksum TEXT NOT NULL CHECK (length(checksum) = 64),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
) STRICT";

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
    destructive: bool,
}

#[derive(Clone, Copy)]
enum BackupValidationMode {
    LatestSource,
    SupportedRestorePrefix,
    ExactVersion(i64),
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial",
        sql: include_str!("../migrations/0001_initial.sql"),
        destructive: false,
    },
    Migration {
        version: 2,
        name: "pagination_indexes",
        sql: include_str!("../migrations/0002_pagination_indexes.sql"),
        destructive: false,
    },
];

/// SQLite durability policy applied to every connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SynchronousPolicy {
    /// Sync at critical WAL checkpoints with strong performance.
    Normal,
    /// Sync every transaction for the strongest ordinary durability.
    Full,
}

impl SynchronousPolicy {
    const fn sqlx(self) -> SqliteSynchronous {
        match self {
            Self::Normal => SqliteSynchronous::Normal,
            Self::Full => SqliteSynchronous::Full,
        }
    }
}

/// Explicit configuration for an on-disk state store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreConfig {
    path: PathBuf,
    max_connections: u32,
    busy_timeout: Duration,
    acquire_timeout: Duration,
    open_timeout: Duration,
    close_timeout: Duration,
    synchronous: SynchronousPolicy,
}

impl StoreConfig {
    /// Creates a production-oriented configuration for an explicit file.
    ///
    /// The path must be absolute and its parent directory must already exist.
    /// The parent is pinned for the store lifetime and must be owned exclusively
    /// by the service (mode `0700` on Unix; a current-service-only writable DACL
    /// on Windows).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_connections: 1,
            busy_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(5),
            open_timeout: Duration::from_secs(30),
            close_timeout: Duration::from_millis(1_500),
            synchronous: SynchronousPolicy::Full,
        }
    }

    /// Sets the bounded connection count.
    #[must_use]
    pub const fn with_max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Sets SQLite's lock wait timeout.
    #[must_use]
    pub const fn with_busy_timeout(mut self, busy_timeout: Duration) -> Self {
        self.busy_timeout = busy_timeout;
        self
    }

    /// Sets the fail-closed wait for the identity-bound connection.
    #[must_use]
    pub const fn with_acquire_timeout(mut self, acquire_timeout: Duration) -> Self {
        self.acquire_timeout = acquire_timeout;
        self
    }

    /// Sets one overall deadline for inspection, connection, and migration.
    #[must_use]
    pub const fn with_open_timeout(mut self, open_timeout: Duration) -> Self {
        self.open_timeout = open_timeout;
        self
    }

    /// Sets the maximum graceful pool-drain wait during close.
    #[must_use]
    pub const fn with_close_timeout(mut self, close_timeout: Duration) -> Self {
        self.close_timeout = close_timeout;
        self
    }

    /// Sets the SQLite synchronous policy.
    #[must_use]
    pub const fn with_synchronous(mut self, synchronous: SynchronousPolicy) -> Self {
        self.synchronous = synchronous;
        self
    }

    /// Returns the configured database path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Effective SQLite settings for health and deployment inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreSettings {
    /// SQLite journal mode.
    pub journal_mode: String,
    /// Whether foreign keys are enforced.
    pub foreign_keys: bool,
    /// Busy timeout in milliseconds.
    pub busy_timeout_ms: i64,
    /// Numeric SQLite synchronous policy.
    pub synchronous: i64,
    /// Maximum pooled connections.
    pub max_connections: u32,
}

/// Result of a WAL checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointReport {
    /// Number of readers or writers that prevented a complete checkpoint.
    pub busy: i64,
    /// WAL frames present when the checkpoint ran.
    pub log_frames: i64,
    /// WAL frames moved into the database.
    pub checkpointed_frames: i64,
}

/// Corruption and schema health information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthReport {
    /// SQLite application identifier.
    pub application_id: i64,
    /// Applied schema version.
    pub schema_version: i64,
    /// Highest schema version understood by this binary.
    pub supported_schema_version: i64,
    /// Results other than `ok` returned by `PRAGMA integrity_check`.
    pub integrity_errors: Vec<String>,
    /// Number of foreign-key violations.
    pub foreign_key_violations: i64,
    /// Canonical migration-history problems.
    pub migration_errors: Vec<String>,
}

impl HealthReport {
    /// Returns whether the database is structurally sound and supported.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.application_id == APPLICATION_ID
            && self.schema_version == self.supported_schema_version
            && self.integrity_errors.is_empty()
            && self.foreign_key_violations == 0
            && self.migration_errors.is_empty()
    }
}

/// Persisted owner information reclaimed after the OS proved no live writer remained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredWriterLock {
    /// Owner token left by the terminated process.
    pub previous_owner: String,
    /// Time the terminated process acquired ownership.
    pub previous_acquired_at_ms: i64,
}

/// Exclusive writer access to one durable SQLite database.
pub struct StateStore {
    path: PathBuf,
    database_parent_path: PathBuf,
    lock_path: PathBuf,
    owner: String,
    recovered_writer: Option<RecoveredWriterLock>,
    pool: SqlitePool,
    lock_file: File,
    lock_identity: Option<Vec<u8>>,
    _process_identity: ProcessIdentityGuard,
    _database_file: File,
    _database_parent: File,
    writer_generation: Arc<AtomicU64>,
    max_connections: u32,
    operation_timeout: Duration,
    busy_timeout: Duration,
    close_timeout: Duration,
}

#[derive(Clone, Copy)]
pub(crate) struct OperationalIdentity<'store> {
    database_parent_path: &'store Path,
    database_parent: &'store File,
    database_path: &'store Path,
    database_file: &'store File,
    lock_path: &'store Path,
    lock_file: &'store File,
    lock_identity: Option<&'store [u8]>,
    writer_generation: &'store AtomicU64,
    pub(crate) busy_timeout: Duration,
}

impl OperationalIdentity<'_> {
    pub(crate) fn verify(self) -> Result<(), StateError> {
        if self.writer_generation.load(Ordering::Acquire) != 1 {
            return Err(StateError::InvalidPath {
                path: self.database_path.to_owned(),
                reason: "state writer generation is no longer live",
            });
        }
        verify_directory_path_identity(self.database_parent_path, self.database_parent)
            .and_then(|()| verify_path_identity(self.database_path, self.database_file))
            .and_then(|()| verify_path_identity(self.lock_path, self.lock_file))
            .and_then(|()| {
                verify_store_lock_binding(
                    self.database_path,
                    self.database_file,
                    self.lock_path,
                    self.lock_file,
                    self.lock_identity,
                )
            })
            .and_then(|()| validate_sqlite_sidecars(self.database_path, self.lock_identity))
    }
}

#[cfg(unix)]
static PROCESS_IDENTITIES: LazyLock<StdMutex<std::collections::HashSet<(u64, u64)>>> =
    LazyLock::new(|| StdMutex::new(std::collections::HashSet::new()));

struct ProcessIdentityGuard {
    #[cfg(unix)]
    identity: Option<(u64, u64)>,
}

struct OpenDeadlineState {
    deadline: std::time::Instant,
    timeout_ms: u64,
    operation: &'static str,
    busy_timeout: Duration,
    expired: Arc<std::sync::atomic::AtomicBool>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    finished: std::sync::atomic::AtomicBool,
    final_commit_state: std::sync::atomic::AtomicU8,
}

impl OpenDeadlineState {
    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        loop {
            let state = self
                .final_commit_state
                .load(std::sync::atomic::Ordering::Acquire);
            let next = match state {
                0 => 1,
                2 => 3,
                1 | 3 => return,
                _ => return,
            };
            if self
                .final_commit_state
                .compare_exchange(
                    state,
                    next,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_ok()
            {
                return;
            }
        }
    }

    fn begin_final_commit(&self) -> Result<(), StateError> {
        if !self.permits_sqlite_work()
            || self
                .final_commit_state
                .compare_exchange(
                    0,
                    2,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_err()
        {
            return Err(self.timeout_error());
        }
        Ok(())
    }

    fn finish_final_commit(&self) {
        let _ = self.final_commit_state.compare_exchange(
            2,
            0,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
    }

    fn permits_sqlite_work(&self) -> bool {
        if std::time::Instant::now() >= self.deadline {
            self.expired
                .store(true, std::sync::atomic::Ordering::Release);
        }

        self.finished.load(std::sync::atomic::Ordering::Acquire)
            || (!self.cancelled.load(std::sync::atomic::Ordering::Acquire)
                && !self.expired.load(std::sync::atomic::Ordering::Acquire))
    }

    fn timeout_error(&self) -> StateError {
        StateError::OperationTimedOut {
            operation: self.operation,
            timeout_ms: self.timeout_ms,
        }
    }

    fn deadline_or_error(
        deadline_state: Option<&OpenDeadlineState>,
        error: StateError,
    ) -> StateError {
        let Some(deadline_state) = deadline_state else {
            return error;
        };
        if std::time::Instant::now() >= deadline_state.deadline {
            deadline_state
                .expired
                .store(true, std::sync::atomic::Ordering::Release);
        }
        if deadline_state
            .expired
            .load(std::sync::atomic::Ordering::Acquire)
            || deadline_state
                .cancelled
                .load(std::sync::atomic::Ordering::Acquire)
        {
            deadline_state.timeout_error()
        } else {
            error
        }
    }
}

async fn install_open_deadline_handler(
    connection: &mut SqliteConnection,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<(), StateError> {
    if let Some(deadline_state) = deadline_state {
        let mut handle = connection
            .lock_handle()
            .await
            .map_err(|error| database("lock deadline-bound SQLite connection", error))?;
        handle.set_progress_handler(100, move || deadline_state.permits_sqlite_work());
    }
    Ok(())
}

impl Drop for ProcessIdentityGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(identity) = self.identity.take() {
            PROCESS_IDENTITIES
                .lock()
                .expect("process identity registry lock poisoned")
                .remove(&identity);
        }
    }
}

async fn close_undelivered_store(
    mut store: StateStore,
    deadline: tokio::time::Instant,
    deadline_state: Arc<OpenDeadlineState>,
) -> Result<(), StateError> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let timeout_ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
    let connection = tokio::time::timeout_at(deadline, store.pool.acquire())
        .await
        .map_err(|_| StateError::OperationTimedOut {
            operation: "acquire undelivered claim cleanup connection",
            timeout_ms,
        })?
        .map_err(|error| database("acquire undelivered claim cleanup connection", error))?;
    let mut connection = connection;
    {
        let mut handle = connection
            .lock_handle()
            .await
            .map_err(|error| database("clear undelivered cleanup progress handler", error))?;
        handle.set_progress_handler(0, || true);
    }
    claw_sqlite_file_control::set_busy_timeout(&mut connection, remaining)
        .await
        .map_err(|error| {
            file_control_database("bound undelivered claim cleanup busy timeout", error)
        })?;
    let (mut connection, mut token) =
        claw_sqlite_file_control::begin_manual_pool_transaction(connection, remaining)
            .await
            .map_err(|error| file_control_database("begin undelivered claim cleanup", error))?;
    {
        let deadline = deadline.into_std();
        let mut handle = connection
            .lock_handle()
            .await
            .map_err(|error| database("install undelivered cleanup deadline", error))?;
        handle.set_progress_handler(100, move || std::time::Instant::now() < deadline);
    }
    let mut committed = false;
    let operation = async {
        let released =
            sqlx::query("DELETE FROM claw_writer_lock WHERE singleton = 1 AND owner = ?")
                .bind(&store.owner)
                .execute(&mut *connection)
                .await
                .map_err(|error| database("release undelivered writer claim", error))?;
        if released.rows_affected() != 1 {
            return Err(StateError::InvalidMigrationHistory {
                reason: "undelivered writer claim was not owned by this open lifecycle".to_owned(),
            });
        }
        claw_sqlite_file_control::commit_synchronously(&mut connection, &mut token)
            .await
            .map_err(|error| file_control_database("commit undelivered claim cleanup", error))?;
        committed = true;
        let remaining_claims = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM claw_writer_lock WHERE singleton = 1 AND owner = ?",
        )
        .bind(&store.owner)
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| database("verify undelivered writer claim absence", error))?;
        if remaining_claims != 0 {
            return Err(StateError::InvalidMigrationHistory {
                reason: "undelivered writer claim remained after committed cleanup".to_owned(),
            });
        }
        Ok(())
    }
    .await;
    if let Err(primary) = operation {
        let rollback = if committed {
            Ok(())
        } else {
            claw_sqlite_file_control::rollback_synchronously(&mut connection, &mut token)
                .await
                .map_err(|error| file_control_database("rollback undelivered claim cleanup", error))
        };
        let close = connection
            .close()
            .await
            .map_err(|error| database("close failed undelivered cleanup connection", error));
        let cleanup = match (rollback, close) {
            (Ok(()), Ok(())) => return Err(primary),
            (rollback, close) => format!(
                "rollback: {}; close: {}",
                rollback
                    .err()
                    .map_or_else(|| "ok".to_owned(), |error| error.to_string()),
                close
                    .err()
                    .map_or_else(|| "ok".to_owned(), |error| error.to_string())
            ),
        };
        return Err(StateError::OperationCleanupFailed {
            operation: "undelivered writer claim cleanup",
            primary: Box::new(primary),
            cleanup,
        });
    }
    connection
        .close()
        .await
        .map_err(|error| database("close undelivered claim cleanup connection", error))?;
    deadline_state
        .finished
        .store(true, std::sync::atomic::Ordering::Release);
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    store.close_timeout = remaining;
    tokio::time::timeout_at(deadline, store.close_inner(true))
        .await
        .map_err(|_| StateError::OperationTimedOut {
            operation: "close undelivered state store",
            timeout_ms: u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
        })?
        .map(|_| ())
}

async fn open_timeout_error(
    lifecycle: tokio::task::JoinHandle<Result<(), StateError>>,
    timeout_ms: u64,
) -> StateError {
    let primary = StateError::OperationTimedOut {
        operation: "state store open",
        timeout_ms,
    };
    match lifecycle.await {
        Ok(Ok(())) => primary,
        Ok(Err(cleanup)) => StateError::OperationCleanupFailed {
            operation: "state store open",
            primary: Box::new(primary),
            cleanup: cleanup.to_string(),
        },
        Err(cleanup) => StateError::OperationCleanupFailed {
            operation: "state store open",
            primary: Box::new(primary),
            cleanup: format!("open cleanup lifecycle failed to join: {cleanup}"),
        },
    }
}

impl StateStore {
    /// Opens an explicit on-disk database, acquires its writer lock, and migrates forward.
    pub async fn open(config: StoreConfig) -> Result<Self, StateError> {
        validate_config(&config)?;
        let timeout_ms = u64::try_from(config.open_timeout.as_millis()).map_err(|_| {
            StateError::InvalidValue {
                field: "open timeout",
                reason: "must fit in milliseconds",
            }
        })?;
        let deadline = tokio::time::Instant::now()
            .checked_add(config.open_timeout)
            .ok_or(StateError::InvalidValue {
                field: "open timeout",
                reason: "is too large for the monotonic clock",
            })?;
        let cleanup_budget = config
            .open_timeout
            .checked_div(2)
            .unwrap_or(Duration::ZERO)
            .min(Duration::from_millis(500));
        let cancel_at = deadline
            .checked_sub(cleanup_budget)
            .unwrap_or(tokio::time::Instant::now());
        let deadline_state = Arc::new(OpenDeadlineState {
            deadline: deadline.into_std(),
            timeout_ms,
            operation: "state store open",
            busy_timeout: config.busy_timeout,
            expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            finished: std::sync::atomic::AtomicBool::new(false),
            final_commit_state: std::sync::atomic::AtomicU8::new(0),
        });
        let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel();
        let (delivery_ack_tx, delivery_ack_rx) = tokio::sync::oneshot::channel();
        let mut delivery_ack_tx = Some(delivery_ack_tx);
        let delivered_store = Arc::new(std::sync::Mutex::new(None));
        let task_delivered_store = Arc::clone(&delivered_store);
        let task_deadline_state = Arc::clone(&deadline_state);
        let lifecycle = tokio::spawn(async move {
            match Self::open_inner(config, Arc::clone(&task_deadline_state)).await {
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                    Ok(())
                }
                Ok(store) => {
                    #[cfg(test)]
                    wait_at_open_postcommit_test_barrier(store.path(), &task_deadline_state).await;
                    *task_delivered_store
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(store);
                    if ready_tx.send(Ok(())).is_err() {
                        let store = {
                            task_delivered_store
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .take()
                        };
                        if let Some(store) = store {
                            return close_undelivered_store(
                                store,
                                deadline,
                                Arc::clone(&task_deadline_state),
                            )
                            .await;
                        }
                        return Ok(());
                    }
                    if delivery_ack_rx.await.is_err() {
                        let store = {
                            task_delivered_store
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .take()
                        };
                        if let Some(store) = store {
                            return close_undelivered_store(
                                store,
                                deadline,
                                Arc::clone(&task_deadline_state),
                            )
                            .await;
                        }
                    }
                    Ok(())
                }
            }
        });
        let mut cancellation_guard = OperationCancellationGuard::new(Arc::clone(&deadline_state));
        tokio::select! {
            ready = &mut ready_rx => {
                match ready {
                    Ok(Err(error)) => Err(error),
                    Ok(Ok(())) => {
                        if tokio::time::Instant::now() >= cancel_at {
                            deadline_state
                                .expired
                                .store(true, std::sync::atomic::Ordering::Release);
                            deadline_state.cancel();
                            drop(delivery_ack_tx.take());
                            let error = open_timeout_error(lifecycle, timeout_ms).await;
                            cancellation_guard.disarm();
                            return Err(error);
                        }
                        let store = delivered_store
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                            .ok_or_else(|| {
                                database(
                                    "deliver opened state store",
                                    sqlx::Error::Protocol(
                                        "open lifecycle did not retain the delivered store".to_owned(),
                                    ),
                                )
                            })?;
                        delivery_ack_tx
                            .take()
                            .ok_or_else(|| {
                                database(
                                    "acknowledge opened state store",
                                    sqlx::Error::Protocol(
                                        "open delivery acknowledgement is missing".to_owned(),
                                    ),
                                )
                            })?
                            .send(())
                            .map_err(|_| {
                                database(
                                    "acknowledge opened state store",
                                    sqlx::Error::Protocol(
                                        "open lifecycle stopped before acknowledgement".to_owned(),
                                    ),
                                )
                            })?;
                        deadline_state
                            .finished
                            .store(true, std::sync::atomic::Ordering::Release);
                        cancellation_guard.disarm();
                        Ok(store)
                    }
                    Err(error) => Err(database(
                        "receive state store open readiness",
                        sqlx::Error::Protocol(error.to_string()),
                    )),
                }
            }
            () = tokio::time::sleep_until(cancel_at) => {
                deadline_state
                    .expired
                    .store(true, std::sync::atomic::Ordering::Release);
                deadline_state.cancel();
                drop(delivery_ack_tx.take());
                let error = open_timeout_error(lifecycle, timeout_ms).await;
                cancellation_guard.disarm();
                Err(error)
            }
        }
    }

    async fn open_inner(
        config: StoreConfig,
        deadline_state: Arc<OpenDeadlineState>,
    ) -> Result<Self, StateError> {
        let path = resolve_database_path(&config.path)?;
        let database_parent = pin_private_directory(&path)?;
        let database_parent_path = database_parent.path.clone();
        let creation_lock = acquire_creation_lock(&path)?;
        let database_file = open_database_file(&path)?;
        validate_private_database_file(&path, &database_file)?;
        verify_path_identity(&path, &database_file)?;
        reject_hard_link(&path, &database_file)?;
        validate_preflight_sidecars(&path, &database_file)?;
        let preflight_state = inspect_database(
            &path,
            &database_file,
            false,
            Some(Arc::clone(&deadline_state)),
        )
        .await?;
        prepare_windows_database_identity(&path)?;
        let allow_identity_initialization = (creation_lock.is_some()
            && matches!(preflight_state, InspectedDatabase::Fresh))
            || matches!(
                preflight_state,
                InspectedDatabase::Existing { schema_version: 0 }
            );
        let (lock_path, lock_file, process_identity) =
            acquire_store_lock(&path, &database_file, allow_identity_initialization)?;
        drop(creation_lock);
        let lock_identity =
            capture_store_lock_identity(&path, &database_file, &lock_path, &lock_file)?;
        let owner = writer_owner()?;
        let writer_generation = Arc::new(AtomicU64::new(1));
        verify_path_identity(&path, &database_file)?;
        let locked_state = inspect_database(
            &path,
            &database_file,
            false,
            Some(Arc::clone(&deadline_state)),
        )
        .await?;

        let remaining = deadline_state
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(deadline_state.timeout_error());
        }
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(config.busy_timeout.min(remaining))
            .synchronous(config.synchronous.sqlx());
        let configured_busy_timeout = config.busy_timeout;
        let verified_path = path.clone();
        let verified_parent_path = database_parent_path.clone();
        let verified_parent = Arc::new(database_parent.file.try_clone().map_err(|error| {
            file_error("clone state directory handle", &database_parent_path, error)
        })?);
        let verified_file = Arc::new(
            database_file
                .try_clone()
                .map_err(|error| file_error("clone connection identity handle", &path, error))?,
        );
        let verified_lock_path = lock_path.clone();
        let verified_lock_file = Arc::new(
            lock_file
                .try_clone()
                .map_err(|error| file_error("clone writer lock handle", &lock_path, error))?,
        );
        let verified_lock_identity = lock_identity.clone();
        let verified_writer_generation = Arc::clone(&writer_generation);
        let connections_ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let connect_ready = Arc::clone(&connections_ready);
        let connect_deadline_state = Arc::clone(&deadline_state);
        let acquire_path = verified_path.clone();
        let acquire_parent_path = verified_parent_path.clone();
        let acquire_parent = Arc::clone(&verified_parent);
        let acquire_file = Arc::clone(&verified_file);
        let acquire_lock_path = verified_lock_path.clone();
        let acquire_lock_file = Arc::clone(&verified_lock_file);
        let acquire_lock_identity = verified_lock_identity.clone();
        let acquire_writer_generation = Arc::clone(&verified_writer_generation);
        let acquire_ready = Arc::clone(&connections_ready);
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .after_connect(move |connection, _metadata| {
                let path = verified_path.clone();
                let parent_path = verified_parent_path.clone();
                let parent = Arc::clone(&verified_parent);
                let file = Arc::clone(&verified_file);
                let lock_path = verified_lock_path.clone();
                let lock_file = Arc::clone(&verified_lock_file);
                let lock_identity = verified_lock_identity.clone();
                let writer_generation = Arc::clone(&verified_writer_generation);
                let ready = Arc::clone(&connect_ready);
                let deadline_state = Arc::clone(&connect_deadline_state);
                Box::pin(async move {
                    let busy_timeout = if ready.load(std::sync::atomic::Ordering::Acquire) {
                        configured_busy_timeout
                    } else {
                        let remaining = deadline_state
                            .deadline
                            .saturating_duration_since(std::time::Instant::now());
                        if remaining.is_zero() {
                            return Err(sqlx::Error::Protocol(
                                "state store open deadline expired before connection bootstrap"
                                    .to_owned(),
                            ));
                        }
                        configured_busy_timeout.min(remaining)
                    };
                    claw_sqlite_file_control::set_busy_timeout(connection, busy_timeout)
                        .await
                        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
                    {
                        let mut handle = connection.lock_handle().await?;
                        handle.set_progress_handler(1_000, move || {
                            deadline_state.permits_sqlite_work()
                        });
                    }
                    if writer_generation.load(Ordering::Acquire) != 1 {
                        return Err(sqlx::Error::Protocol(
                            "state writer generation is no longer live".to_owned(),
                        ));
                    }
                    verify_directory_path_identity(&parent_path, &parent)
                        .and_then(|()| verify_path_identity(&path, &file))
                        .and_then(|()| verify_path_identity(&lock_path, &lock_file))
                        .and_then(|()| {
                            verify_store_lock_binding(
                                &path,
                                &file,
                                &lock_path,
                                &lock_file,
                                lock_identity.as_deref(),
                            )
                        })
                        .map_err(|error| sqlx::Error::Configuration(Box::new(error)))?;
                    verify_sqlite_connection_identity(connection).await?;
                    if ready.load(std::sync::atomic::Ordering::Acquire) {
                        claw_sqlite_file_control::set_busy_timeout(
                            connection,
                            configured_busy_timeout,
                        )
                        .await
                        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
                        secure_sqlite_sidecars(&path, lock_identity.as_deref())
                            .map_err(|error| sqlx::Error::Configuration(Box::new(error)))?;
                        install_store_commit_guard(
                            connection,
                            (&parent_path, &parent),
                            (&path, &file),
                            (&lock_path, &lock_file),
                            lock_identity.as_deref(),
                            (Arc::clone(&writer_generation), 1),
                        )
                        .await?;
                    }
                    Ok(())
                })
            })
            .before_acquire(move |connection, _metadata| {
                let path = acquire_path.clone();
                let parent_path = acquire_parent_path.clone();
                let parent = Arc::clone(&acquire_parent);
                let file = Arc::clone(&acquire_file);
                let lock_path = acquire_lock_path.clone();
                let lock_file = Arc::clone(&acquire_lock_file);
                let lock_identity = acquire_lock_identity.clone();
                let writer_generation = Arc::clone(&acquire_writer_generation);
                let ready = Arc::clone(&acquire_ready);
                Box::pin(async move {
                    if writer_generation.load(Ordering::Acquire) != 1 {
                        return Err(sqlx::Error::Protocol(
                            "state writer generation is no longer live".to_owned(),
                        ));
                    }
                    verify_directory_path_identity(&parent_path, &parent)
                        .and_then(|()| verify_path_identity(&path, &file))
                        .and_then(|()| verify_path_identity(&lock_path, &lock_file))
                        .and_then(|()| {
                            verify_store_lock_binding(
                                &path,
                                &file,
                                &lock_path,
                                &lock_file,
                                lock_identity.as_deref(),
                            )
                        })
                        .and_then(|()| {
                            if ready.load(std::sync::atomic::Ordering::Acquire) {
                                validate_sqlite_sidecars(&path, lock_identity.as_deref())
                            } else {
                                Ok(())
                            }
                        })
                        .map_err(|error| sqlx::Error::Configuration(Box::new(error)))?;
                    verify_sqlite_connection_identity(connection).await?;
                    Ok(true)
                })
            })
            .connect_with(options)
            .await
            .map_err(|error| database("open state database", error))?;
        if let Err(error) = verify_path_identity(&path, &database_file) {
            pool.close().await;
            return Err(error);
        }

        async fn initialize_connection_sidecars(
            connection: &mut SqliteConnection,
        ) -> Result<(), sqlx::Error> {
            async {
                let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
                    .fetch_one(&mut *connection)
                    .await?;
                if !matches!(application_id, 0 | APPLICATION_ID) {
                    return Err(sqlx::Error::Protocol(
                        "database application identity changed before sidecar initialization"
                            .to_owned(),
                    ));
                }
                sqlx::query("PRAGMA application_id = 1")
                    .execute(&mut *connection)
                    .await?;
                if application_id == APPLICATION_ID {
                    sqlx::query("PRAGMA application_id = 1196704067")
                        .execute(&mut *connection)
                        .await?;
                } else {
                    sqlx::query("PRAGMA application_id = 0")
                        .execute(&mut *connection)
                        .await?;
                }
                let restored = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
                    .fetch_one(&mut *connection)
                    .await?;
                if restored != application_id {
                    return Err(sqlx::Error::Protocol(
                        "database application identity changed during sidecar initialization"
                            .to_owned(),
                    ));
                }
                verify_sqlite_connection_identity(connection).await?;
                Ok::<(), sqlx::Error>(())
            }
            .await
        }

        let initial = pool
            .acquire()
            .await
            .map_err(|error| database("acquire initial state connection", error))?;
        let initial_busy_timeout = configured_busy_timeout.min(
            deadline_state
                .deadline
                .saturating_duration_since(std::time::Instant::now()),
        );
        let (initial, mut initial_transaction) =
            claw_sqlite_file_control::begin_manual_pool_transaction_with_restore(
                initial,
                initial_busy_timeout,
                initial_busy_timeout,
                Some(Arc::clone(&deadline_state.cancelled)),
            )
            .await
            .map_err(|error| file_control_database("begin SQLite sidecar initialization", error))?;
        let mut initial =
            BackupConnectionGuard::new_cancellable(initial, Arc::clone(&deadline_state));
        if let Err(error) = initialize_connection_sidecars(&mut initial).await {
            let primary = database("initialize SQLite sidecars", error);
            let rollback = claw_sqlite_file_control::rollback_synchronously(
                &mut initial,
                &mut initial_transaction,
            )
            .await;
            return Err(match rollback {
                Ok(()) => primary,
                Err(cleanup) => StateError::OperationCleanupFailed {
                    operation: "initialize SQLite sidecars",
                    primary: Box::new(primary),
                    cleanup: cleanup.to_string(),
                },
            });
        }
        claw_sqlite_file_control::commit_synchronously(&mut initial, &mut initial_transaction)
            .await
            .map_err(|error| {
                file_control_database("commit SQLite sidecar initialization", error)
            })?;
        secure_sqlite_sidecars(&path, lock_identity.as_deref())?;
        install_store_commit_guard(
            &mut initial,
            (&database_parent_path, &database_parent.file),
            (&path, &database_file),
            (&lock_path, &lock_file),
            lock_identity.as_deref(),
            (Arc::clone(&writer_generation), 1),
        )
        .await
        .map_err(|error| database("install initial commit guard", error))?;
        initial.mark_reusable();
        drop(initial);
        #[cfg(test)]
        wait_at_open_initialization_test_barrier(&path).await;

        let configured = async {
            let mut configured_connection = pool
                .acquire()
                .await
                .map_err(|error| database("acquire configured state connection", error))?;
            claw_sqlite_file_control::set_busy_timeout(
                &mut configured_connection,
                configured_busy_timeout,
            )
            .await
            .map_err(|error| {
                database(
                    "restore configured SQLite busy timeout",
                    sqlx::Error::Protocol(error.to_string()),
                )
            })?;
            secure_sqlite_sidecars(&path, lock_identity.as_deref())?;
            install_store_commit_guard(
                &mut configured_connection,
                (&database_parent_path, &database_parent.file),
                (&path, &database_file),
                (&lock_path, &lock_file),
                lock_identity.as_deref(),
                (Arc::clone(&writer_generation), 1),
            )
            .await
            .map_err(|error| database("install configured commit guard", error))?;
            Ok::<(), StateError>(())
        }
        .await;
        if let Err(error) = configured {
            return Err(
                if tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline_state.deadline),
                    pool.close(),
                )
                .await
                .is_ok()
                {
                    error
                } else {
                    StateError::OperationCleanupFailed {
                        operation: "state store open",
                        primary: Box::new(error),
                        cleanup: "pre-claim pool close exceeded the open deadline".to_owned(),
                    }
                },
            );
        }
        let recovered_writer = match initialize_database(
            &pool,
            &path,
            locked_state,
            &owner,
            Arc::clone(&deadline_state),
        )
        .await
        {
            Ok(recovered_writer) => recovered_writer,
            Err(error) => {
                pool.close().await;
                return Err(error);
            }
        };
        connections_ready.store(true, std::sync::atomic::Ordering::Release);
        Ok(Self {
            path,
            database_parent_path,
            lock_path,
            owner,
            recovered_writer,
            pool,
            lock_file,
            lock_identity,
            _process_identity: process_identity,
            _database_file: database_file,
            _database_parent: database_parent.file,
            writer_generation,
            max_connections: config.max_connections,
            operation_timeout: config.open_timeout,
            busy_timeout: config.busy_timeout,
            close_timeout: config.close_timeout,
        })
    }

    /// Returns the durable database path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns stale persisted ownership reclaimed during this open.
    #[must_use]
    pub fn recovered_writer(&self) -> Option<&RecoveredWriterLock> {
        self.recovered_writer.as_ref()
    }

    /// Returns the session repository.
    #[must_use]
    pub fn sessions(&self) -> SessionRepository<'_> {
        SessionRepository::new(&self.pool, &self.owner, self.operational_identity())
    }

    /// Returns the device repository.
    #[must_use]
    pub fn devices(&self) -> DeviceRepository<'_> {
        DeviceRepository::new(&self.pool, &self.owner, self.operational_identity())
    }

    /// Returns the authentication repository.
    #[must_use]
    pub fn authentications(&self) -> AuthenticationRepository<'_> {
        AuthenticationRepository::new(&self.pool, &self.owner, self.operational_identity())
    }

    /// Returns the task repository.
    #[must_use]
    pub fn tasks(&self) -> TaskRepository<'_> {
        TaskRepository::new(&self.pool, &self.owner, self.operational_identity())
    }

    fn operational_identity(&self) -> OperationalIdentity<'_> {
        OperationalIdentity {
            database_parent_path: &self.database_parent_path,
            database_parent: &self._database_parent,
            database_path: &self.path,
            database_file: &self._database_file,
            lock_path: &self.lock_path,
            lock_file: &self.lock_file,
            lock_identity: self.lock_identity.as_deref(),
            writer_generation: &self.writer_generation,
            busy_timeout: self.busy_timeout,
        }
    }

    /// Reads the effective connection and durability settings.
    pub async fn settings(&self) -> Result<StoreSettings, StateError> {
        let row = sqlx::query(
            "SELECT
                (SELECT journal_mode FROM pragma_journal_mode) AS journal_mode,
                (SELECT foreign_keys FROM pragma_foreign_keys) AS foreign_keys,
                (SELECT timeout FROM pragma_busy_timeout) AS busy_timeout_ms,
                (SELECT synchronous FROM pragma_synchronous) AS synchronous",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|error| database("inspect SQLite settings", error))?;
        Ok(StoreSettings {
            journal_mode: row.get("journal_mode"),
            foreign_keys: row.get::<i64, _>("foreign_keys") == 1,
            busy_timeout_ms: row.get("busy_timeout_ms"),
            synchronous: row.get("synchronous"),
            max_connections: self.max_connections,
        })
    }

    /// Creates a same-version, transactionally consistent snapshot sealed to
    /// the current machine and service identity.
    pub async fn backup_to(&self, destination: impl AsRef<Path>) -> Result<(), StateError> {
        let requested_destination = destination.as_ref();
        ensure_database_artifacts_absent(requested_destination)?;
        let destination = resolve_database_path(requested_destination)?;
        let timeout_ms = u64::try_from(self.operation_timeout.as_millis()).map_err(|_| {
            StateError::InvalidValue {
                field: "backup timeout",
                reason: "must fit in milliseconds",
            }
        })?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.operation_timeout)
            .ok_or(StateError::InvalidValue {
                field: "backup timeout",
                reason: "is too large for the monotonic clock",
            })?;
        let expected_version = tokio::time::timeout_at(deadline, schema_version(&self.pool))
            .await
            .map_err(|_| StateError::OperationTimedOut {
                operation: "SQLite backup",
                timeout_ms,
            })??;
        if expected_version != LATEST_SCHEMA_VERSION {
            return Err(StateError::InvalidMigrationHistory {
                reason: format!(
                    "backup source version {expected_version} is not latest version {LATEST_SCHEMA_VERSION}"
                ),
            });
        }
        backup_pool(
            &self.pool,
            &destination,
            BackupValidationMode::LatestSource,
            deadline,
            timeout_ms,
            Some(self.operational_identity()),
        )
        .await
    }

    /// Restores a locally sealed backup to a destination that does not yet exist.
    ///
    /// Copying a backup to another machine or service identity is intentionally
    /// unsupported and returns [`StateError::BackupNotPortable`].
    pub async fn restore_backup(
        backup: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<(), StateError> {
        let timeout_ms = u64::try_from(MAX_CONFIGURED_TIMEOUT.as_millis())
            .expect("maximum configured timeout fits u64");
        let deadline = tokio::time::Instant::now() + MAX_CONFIGURED_TIMEOUT;
        let deadline_state = Arc::new(OpenDeadlineState {
            deadline: deadline.into_std(),
            timeout_ms,
            operation: "SQLite restore",
            busy_timeout: MAX_CONFIGURED_TIMEOUT,
            expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            finished: std::sync::atomic::AtomicBool::new(false),
            final_commit_state: std::sync::atomic::AtomicU8::new(0),
        });
        let backup = resolve_snapshot_source_path(backup.as_ref())?;
        let backup_file = open_existing_file_no_follow(&backup)?;
        verify_path_identity(&backup, &backup_file)?;
        reject_hard_link(&backup, &backup_file)?;
        let backup_snapshot = PinnedSnapshot::from_file(&backup, backup_file)?;
        let sealed_digest = validate_standalone_snapshot_source_pinned(
            &backup_snapshot,
            Some(Arc::clone(&deadline_state)),
        )
        .await?;
        let requested_destination = destination.as_ref();
        ensure_database_artifacts_absent(requested_destination)?;
        let destination = resolve_database_path(requested_destination)?;
        ensure_database_artifacts_absent(&destination)?;
        let destination_directory = pin_private_directory(&destination)?;
        let temporary = snapshot_temporary_path(&destination, "restore")?;
        let temporary_directory = pin_private_directory(&temporary)?;
        let mut temporary_guard =
            SnapshotCleanupGuard::new_pinned(&temporary, &temporary_directory)?;
        let mut cancellation_guard = OperationCancellationGuard::new(Arc::clone(&deadline_state));
        snapshot_database(
            &backup,
            &backup_snapshot.file,
            &temporary,
            Some(&sealed_digest),
            Some(Arc::clone(&deadline_state)),
        )
        .await?;
        let pinned = match PinnedSnapshot::open(&temporary) {
            Ok(pinned) => pinned,
            Err(error) => return Err(cleanup_failed_snapshot(&temporary, error)),
        };
        temporary_guard.bind_file(&pinned.file)?;
        #[cfg(test)]
        if tokio::time::timeout_at(
            deadline,
            wait_at_snapshot_test_barrier(&destination, &temporary),
        )
        .await
        .is_err()
        {
            return Err(cleanup_pinned_or_error(
                "SQLite restore",
                pinned,
                deadline_state.timeout_error(),
            ));
        }
        if let Err(error) =
            validate_snapshot_marker_pinned(&pinned, Some(Arc::clone(&deadline_state))).await
        {
            return Err(cleanup_pinned_or_error("SQLite restore", pinned, error));
        }
        if let Err(error) = clear_backup_writer_lock(&pinned).await {
            return Err(cleanup_pinned_or_error("SQLite restore", pinned, error));
        }
        if let Err(error) = validate_backup_pinned(
            &pinned,
            BackupValidationMode::SupportedRestorePrefix,
            Some(Arc::clone(&deadline_state)),
        )
        .await
        {
            return Err(cleanup_pinned_or_error("SQLite restore", pinned, error));
        }
        let mut identity_guard =
            match initialize_restored_store_identity(&temporary, &pinned.file, &destination) {
                Ok(guard) => guard,
                Err(error) => return Err(cleanup_pinned_or_error("SQLite restore", pinned, error)),
            };
        if let Err(error) = pinned.sync() {
            let error = match identity_guard.cleanup() {
                Ok(()) => error,
                Err(cleanup) => append_operation_cleanup(
                    "SQLite restore",
                    error,
                    format!("restored lock cleanup failed: {cleanup}"),
                ),
            };
            return Err(cleanup_pinned_or_error("SQLite restore", pinned, error));
        }
        if let Err(error) = publish_snapshot(
            pinned,
            &destination,
            "SQLite restore",
            Some((deadline, timeout_ms)),
            &destination_directory,
        ) {
            let error = if matches!(error, StateError::PublicationUncertain { .. }) {
                identity_guard.disarm();
                error
            } else {
                match identity_guard.cleanup() {
                    Ok(()) => error,
                    Err(cleanup) => append_operation_cleanup(
                        "SQLite restore",
                        error,
                        format!("restored lock cleanup failed: {cleanup}"),
                    ),
                }
            };
            return Err(cleanup_failed_snapshot(&temporary, error));
        }
        #[cfg(test)]
        wait_at_published_handoff_test_barrier(&destination).await;
        if let Err(error) = validate_published_snapshot_handoff(&destination) {
            identity_guard.disarm();
            cancellation_guard.disarm();
            temporary_guard.disarm();
            return Err(StateError::PublicationUncertain {
                path: destination,
                reason: format!(
                    "published restore failed final identity/sidecar validation: {error}"
                ),
            });
        }
        identity_guard.disarm();
        cancellation_guard.disarm();
        temporary_guard.disarm();
        Ok(())
    }

    /// Runs SQLite structural and referential integrity checks.
    pub async fn health(&self) -> Result<HealthReport, StateError> {
        self.operational_identity().verify()?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| database("begin health snapshot", error))?;
        let mut migration_errors = migration_health_errors_connection(&mut transaction).await?;
        let persisted_owner = sqlx::query_scalar::<_, String>(
            "SELECT owner FROM claw_writer_lock WHERE singleton = 1",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database("read health application writer", error))?;
        if persisted_owner.as_deref() != Some(self.owner.as_str()) {
            migration_errors
                .push("application writer ownership does not match the live store".to_owned());
        }
        let results = sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
            .fetch_all(&mut *transaction)
            .await
            .map_err(|error| database("run SQLite integrity check", error))?;
        let integrity_errors = results
            .into_iter()
            .filter(|result| result != "ok")
            .collect();
        let foreign_key_violations =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pragma_foreign_key_check")
                .fetch_one(&mut *transaction)
                .await
                .map_err(|error| database("run foreign key check", error))?;
        let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| database("read health application id", error))?;
        let schema_version =
            sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM claw_schema_migrations")
                .fetch_one(&mut *transaction)
                .await
                .map_err(|error| database("read health schema version", error))?;
        let user_version = sqlx::query_scalar::<_, i64>("PRAGMA user_version")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| database("read health user version", error))?;
        if user_version != schema_version {
            migration_errors.push(format!(
                "SQLite user_version {user_version} does not match migration version {schema_version}"
            ));
        }
        self.operational_identity().verify()?;
        transaction
            .commit()
            .await
            .map_err(|error| database("commit health snapshot", error))?;
        Ok(HealthReport {
            application_id,
            schema_version,
            supported_schema_version: LATEST_SCHEMA_VERSION,
            integrity_errors,
            foreign_key_violations,
            migration_errors,
        })
    }

    /// Checkpoints and truncates the WAL.
    pub async fn checkpoint(&self) -> Result<CheckpointReport, StateError> {
        self.operational_identity().verify()?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|error| database("acquire checkpoint connection", error))?;
        verify_sqlite_connection_identity(&mut connection)
            .await
            .map_err(|error| database("verify checkpoint database identity", error))?;
        let row = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| database("checkpoint SQLite WAL", error))?;
        #[cfg(all(test, unix))]
        wait_at_checkpoint_test_barrier(&self.path).await;
        verify_sqlite_connection_identity(&mut connection)
            .await
            .map_err(|error| database("reverify checkpoint database identity", error))?;
        self.operational_identity().verify()?;
        let report = CheckpointReport {
            busy: row.get(0),
            log_frames: row.get(1),
            checkpointed_frames: row.get(2),
        };
        drop(connection);
        Ok(report)
    }

    /// Checkpoints, closes all pooled connections, and releases the writer lock.
    pub async fn close(self) -> Result<CheckpointReport, StateError> {
        self.close_inner(false).await
    }

    async fn close_inner(
        self,
        application_lock_already_released: bool,
    ) -> Result<CheckpointReport, StateError> {
        let deadline = tokio::time::Instant::now() + self.close_timeout;
        let mut reasons = Vec::new();
        let identity_valid = match verify_directory_path_identity(
            &self.database_parent_path,
            &self._database_parent,
        )
        .and_then(|()| verify_path_identity(&self.path, &self._database_file))
        .and_then(|()| {
            verify_store_lock_binding(
                &self.path,
                &self._database_file,
                &self.lock_path,
                &self.lock_file,
                self.lock_identity.as_deref(),
            )
        }) {
            Ok(()) => true,
            Err(error) => {
                reasons.push(format!("database identity unavailable: {error}"));
                false
            }
        };
        let mut connection = if identity_valid {
            match tokio::time::timeout_at(deadline, self.pool.acquire()).await {
                Ok(Ok(connection)) => Some(connection),
                Ok(Err(error)) => {
                    reasons.push(format!(
                        "acquire final close connection failed: {}",
                        database("acquire final close connection", error)
                    ));
                    None
                }
                Err(_) => {
                    reasons
                        .push("acquire final close connection exceeded close deadline".to_owned());
                    None
                }
            }
        } else {
            None
        };

        let closing_pool = self.pool.clone();
        let mut close_future = Box::pin(closing_pool.close());
        let pool_closed_immediately = std::future::poll_fn(|context| {
            use std::future::Future as _;
            use std::task::Poll;

            Poll::Ready(matches!(
                close_future.as_mut().poll(context),
                Poll::Ready(())
            ))
        })
        .await;

        let checkpoint = if let Some(connection) = connection.as_mut() {
            let checkpoint_result = tokio::time::timeout_at(
                deadline,
                sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").fetch_one(&mut **connection),
            )
            .await;
            match checkpoint_result {
                Ok(Ok(row)) => {
                    let report = CheckpointReport {
                        busy: row.get(0),
                        log_frames: row.get(1),
                        checkpointed_frames: row.get(2),
                    };
                    if report.busy == 0 {
                        Some(report)
                    } else {
                        reasons.push(format!(
                            "checkpoint remained busy with {} WAL frames and {} checkpointed frames",
                            report.log_frames, report.checkpointed_frames
                        ));
                        None
                    }
                }
                Ok(Err(error)) => {
                    reasons.push(format!(
                        "checkpoint failed: {}",
                        database("checkpoint SQLite WAL", error)
                    ));
                    None
                }
                Err(_) => {
                    reasons.push("checkpoint exceeded close deadline".to_owned());
                    None
                }
            }
        } else {
            None
        };
        let application_lock_released = if application_lock_already_released {
            true
        } else if let Some(connection) = connection.as_mut() {
            let release_result = tokio::time::timeout_at(
                deadline,
                sqlx::query("DELETE FROM claw_writer_lock WHERE singleton = 1 AND owner = ?")
                    .bind(&self.owner)
                    .execute(&mut **connection),
            )
            .await;
            match release_result {
                Ok(Ok(released)) if released.rows_affected() == 1 => true,
                Ok(Ok(_)) => {
                    reasons
                        .push("application writer lock ownership changed unexpectedly".to_owned());
                    false
                }
                Ok(Err(error)) => {
                    reasons.push(format!(
                        "application writer release failed: {}",
                        database("release application writer lock", error)
                    ));
                    false
                }
                Err(_) => {
                    reasons.push("application writer release exceeded close deadline".to_owned());
                    false
                }
            }
        } else {
            false
        };
        self.writer_generation.store(0, Ordering::Release);
        let final_connection_closed = if let Some(connection) = connection.take() {
            match close_final_connection(connection, deadline, &self.path).await {
                Ok(()) => true,
                Err(reason) => {
                    reasons.push(reason);
                    false
                }
            }
        } else {
            false
        };

        let pool_drain_completed = pool_closed_immediately
            || tokio::time::timeout_at(deadline, close_future)
                .await
                .is_ok();
        if !pool_drain_completed {
            reasons.push(format!(
                "pool drain exceeded the single {} ms close deadline",
                self.close_timeout.as_millis()
            ));
        }
        let pool_closed = final_connection_closed && pool_drain_completed;
        let os_lock_released = match File::unlock(&self.lock_file) {
            Ok(()) => true,
            Err(error) => {
                reasons.push(format!(
                    "OS identity lock release failed: {}",
                    file_error("release writer lock", &self.lock_path, error)
                ));
                false
            }
        };
        match (
            checkpoint,
            application_lock_released,
            final_connection_closed,
            os_lock_released,
            pool_closed,
        ) {
            (Some(report), true, true, true, true) => Ok(report),
            (
                checkpoint,
                application_lock_released,
                final_connection_closed,
                os_lock_released,
                pool_closed,
            ) => Err(StateError::CloseDegraded {
                checkpoint_completed: checkpoint.is_some(),
                application_lock_released,
                final_connection_closed,
                pool_closed,
                os_lock_released,
                reason: reasons.join("; "),
            }),
        }
    }
}

async fn close_final_connection(
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    deadline: tokio::time::Instant,
    _path: &Path,
) -> Result<(), String> {
    #[cfg(test)]
    if let Some(failure) = FINAL_CONNECTION_CLOSE_FAILURES
        .lock()
        .expect("final connection close failures lock poisoned")
        .remove(_path)
    {
        drop(connection);
        return Err(match failure {
            FinalConnectionCloseFailure::Error => {
                "final connection close failed: injected test failure".to_owned()
            }
            FinalConnectionCloseFailure::Timeout => {
                "final connection close exceeded close deadline".to_owned()
            }
        });
    }
    match tokio::time::timeout_at(deadline, connection.close()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!(
            "final connection close failed: {}",
            database("close final state connection", error)
        )),
        Err(_) => Err("final connection close exceeded close deadline".to_owned()),
    }
}

#[cfg(unix)]
struct RestoredIdentityGuard {
    lock_path: PathBuf,
    lock_file: Option<File>,
    armed: bool,
}

#[cfg(unix)]
impl RestoredIdentityGuard {
    fn cleanup(&mut self) -> Result<(), StateError> {
        let Some(lock_file) = self.lock_file.take() else {
            self.armed = false;
            return Ok(());
        };
        verify_path_identity(&self.lock_path, &lock_file)?;
        drop(lock_file);
        std::fs::remove_file(&self.lock_path).map_err(|error| {
            file_error("remove unused restored writer lock", &self.lock_path, error)
        })?;
        sync_parent_directory(&self.lock_path)?;
        self.armed = false;
        Ok(())
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.lock_file.take();
    }
}

#[cfg(unix)]
impl Drop for RestoredIdentityGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cleanup();
        }
    }
}

#[cfg(windows)]
struct RestoredIdentityGuard {
    identity_file: Option<File>,
    armed: bool,
}

#[cfg(windows)]
impl RestoredIdentityGuard {
    fn cleanup(&mut self) -> Result<(), StateError> {
        let Some(identity_file) = self.identity_file.take() else {
            self.armed = false;
            return Ok(());
        };
        drop(identity_file);
        self.armed = false;
        Ok(())
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.identity_file.take();
    }
}

#[cfg(windows)]
impl Drop for RestoredIdentityGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cleanup();
        }
    }
}

#[cfg(all(not(unix), not(windows)))]
struct RestoredIdentityGuard;

#[cfg(all(not(unix), not(windows)))]
impl RestoredIdentityGuard {
    fn cleanup(&mut self) -> Result<(), StateError> {
        Ok(())
    }

    fn disarm(&mut self) {}
}

fn cleanup_identity_or_error(
    operation: &'static str,
    guard: &mut RestoredIdentityGuard,
    error: StateError,
) -> StateError {
    match guard.cleanup() {
        Ok(()) => error,
        Err(cleanup) => append_operation_cleanup(
            operation,
            error,
            format!("restored writer-lock cleanup failed: {cleanup}"),
        ),
    }
}

#[cfg(unix)]
fn initialize_restored_store_identity(
    path: &Path,
    expected_file: &File,
    _published_path: &Path,
) -> Result<RestoredIdentityGuard, StateError> {
    let file = open_database_file(path)?;
    if !files_share_identity_from_handles_portable(expected_file, &file)? {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "restored snapshot changed before identity initialization",
        });
    }
    verify_path_identity(path, &file)?;
    let (lock_path, lock_file, process_identity) = acquire_store_lock(path, &file, true)?;
    drop(process_identity);
    Ok(RestoredIdentityGuard {
        lock_path,
        lock_file: Some(lock_file),
        armed: true,
    })
}

#[cfg(windows)]
fn initialize_restored_store_identity(
    path: &Path,
    _expected_file: &File,
    published_path: &Path,
) -> Result<RestoredIdentityGuard, StateError> {
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    };

    const PREFIX: &str = "gta-claw-writer-v1\n";
    let identity_path = writer_identity_path_for(path);
    let mut identity_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&identity_path)
        .map_err(|error| {
            file_error(
                "reserve restored Windows identity stream",
                &identity_path,
                error,
            )
        })?;
    let identity = format!("{PREFIX}{}", published_path.display());
    identity_file
        .seek(SeekFrom::Start(0))
        .and_then(|_| identity_file.set_len(0))
        .and_then(|_| identity_file.write_all(identity.as_bytes()))
        .and_then(|_| identity_file.sync_all())
        .map_err(|error| {
            file_error(
                "prepare held restored Windows identity stream",
                &identity_path,
                error,
            )
        })?;
    Ok(RestoredIdentityGuard {
        identity_file: Some(identity_file),
        armed: true,
    })
}

#[cfg(all(not(unix), not(windows)))]
fn initialize_restored_store_identity(
    _path: &Path,
    _expected_file: &File,
    _published_path: &Path,
) -> Result<RestoredIdentityGuard, StateError> {
    Ok(RestoredIdentityGuard)
}

fn validate_published_snapshot_handoff(path: &Path) -> Result<(), StateError> {
    let file = open_existing_file_no_follow(path)?;
    validate_private_database_file(path, &file)?;
    verify_path_identity(path, &file)?;
    reject_hard_link(path, &file)?;
    validate_preflight_sidecars(path, &file)
}

fn validate_config(config: &StoreConfig) -> Result<(), StateError> {
    let path = &config.path;
    if path.as_os_str().is_empty() {
        return Err(StateError::InvalidPath {
            path: path.clone(),
            reason: "must not be empty",
        });
    }
    if path == Path::new(":memory:") {
        return Err(StateError::InvalidPath {
            path: path.clone(),
            reason: "in-memory databases are not permitted",
        });
    }
    if path.to_str().is_none() {
        return Err(StateError::InvalidPath {
            path: path.clone(),
            reason: "must be valid Unicode",
        });
    }
    if !path.is_absolute() {
        return Err(StateError::InvalidPath {
            path: path.clone(),
            reason: "must be an absolute path inside a service-private directory",
        });
    }
    if config.max_connections == 0 || config.max_connections > 8 {
        return Err(StateError::InvalidValue {
            field: "maximum connections",
            reason: "must be between one and eight identity-bound connections",
        });
    }
    validate_duration("busy timeout", config.busy_timeout, MAX_CONFIGURED_TIMEOUT)?;
    validate_duration(
        "connection acquire timeout",
        config.acquire_timeout,
        MAX_CONFIGURED_TIMEOUT,
    )?;
    validate_duration("open timeout", config.open_timeout, MAX_CONFIGURED_TIMEOUT)?;
    validate_duration(
        "close timeout",
        config.close_timeout,
        Duration::from_millis(1_500),
    )?;
    Ok(())
}

fn validate_duration(
    field: &'static str,
    duration: Duration,
    maximum: Duration,
) -> Result<(), StateError> {
    if duration.is_zero() {
        return Err(StateError::InvalidValue {
            field,
            reason: "must be greater than zero",
        });
    }
    if duration > maximum {
        return Err(StateError::InvalidValue {
            field,
            reason: "exceeds the supported safe upper bound",
        });
    }
    if !duration.subsec_nanos().is_multiple_of(1_000_000) {
        return Err(StateError::InvalidValue {
            field,
            reason: "must use whole-millisecond precision",
        });
    }
    Ok(())
}

fn resolve_database_path(path: &Path) -> Result<PathBuf, StateError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(StateError::InvalidPath {
                path: path.to_owned(),
                reason: "symbolic-link database paths are not supported",
            });
        }

        Ok(_) => {
            let file_name = path.file_name().ok_or_else(|| StateError::InvalidPath {
                path: path.to_owned(),
                reason: "must include a database file name",
            })?;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let canonical_parent = std::fs::canonicalize(parent)
                .map_err(|error| file_error("canonicalize state directory", parent, error))?;
            return Ok(canonical_parent.join(file_name));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(file_error("inspect state database path", path, error));
        }
    }
    let file_name = path.file_name().ok_or_else(|| StateError::InvalidPath {
        path: path.to_owned(),
        reason: "must include a database file name",
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|error| file_error("canonicalize state directory", parent, error))?;
    Ok(canonical_parent.join(file_name))
}

fn resolve_snapshot_source_path(path: &Path) -> Result<PathBuf, StateError> {
    if !path.is_absolute() {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "snapshot source must be an absolute path",
        });
    }
    let file_name = path.file_name().ok_or_else(|| StateError::InvalidPath {
        path: path.to_owned(),
        reason: "snapshot source must include a file name",
    })?;
    let parent = path.parent().ok_or_else(|| StateError::InvalidPath {
        path: path.to_owned(),
        reason: "snapshot source must have a parent directory",
    })?;
    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|error| file_error("canonicalize snapshot source directory", parent, error))?;
    validate_snapshot_source_directory(&canonical_parent)?;
    Ok(canonical_parent.join(file_name))
}

#[cfg(unix)]
fn validate_snapshot_source_directory(path: &Path) -> Result<(), StateError> {
    let file = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| file_error("open snapshot source directory", path, error.into()))?;
    let metadata = file
        .metadata()
        .map_err(|error| file_error("inspect snapshot source directory", path, error))?;
    if !metadata.file_type().is_dir()
        || !claw_sqlite_file_control::unix_file_is_service_private(
            &file,
            rustix::process::geteuid().as_raw(),
            0o700,
        )
        .map_err(|_| StateError::InvalidPath {
            path: path.to_owned(),
            reason: "snapshot source directory ACL could not be validated",
        })?
    {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "snapshot source directory must be service-owned, mode 0700, and non-symlink",
        });
    }
    Ok(())
}

#[cfg(windows)]
fn validate_snapshot_source_directory(path: &Path) -> Result<(), StateError> {
    validate_state_directory(path)
}

#[cfg(all(not(unix), not(windows)))]
fn validate_snapshot_source_directory(path: &Path) -> Result<(), StateError> {
    Err(StateError::InvalidPath {
        path: path.to_owned(),
        reason: "private snapshot source directories are unsupported",
    })
}

#[cfg(windows)]
fn validate_state_directory(path: &Path) -> Result<(), StateError> {
    let file = open_windows_directory_no_follow(path)?;
    if !claw_sqlite_file_control::windows_file_is_service_private(&file).map_err(|error| {
        StateError::InvalidPath {
            path: path.to_owned(),
            reason: match error.code() {
                Some(_) => "state directory security descriptor could not be validated",
                None => "state directory security descriptor could not be validated",
            },
        }
    })? {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "state directory grants write or delete access outside the service identity",
        });
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn validate_state_directory(path: &Path) -> Result<(), StateError> {
    Err(StateError::InvalidPath {
        path: path.to_owned(),
        reason: "service-private state directories are unsupported on this platform",
    })
}

#[cfg(unix)]
fn open_database_file(path: &Path) -> Result<File, StateError> {
    let exists = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(StateError::InvalidPath {
                path: path.to_owned(),
                reason: "symbolic-link database paths are not supported",
            });
        }

        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(file_error("inspect state database path", path, error)),
    };
    let mut flags =
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    if !exists {
        flags |= rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL;
    }
    rustix::fs::open(path, flags, rustix::fs::Mode::from_bits_retain(0o600))
        .map(File::from)
        .map_err(|error| file_error("open state database file", path, error.into()))
}

#[cfg(windows)]
fn open_database_file(path: &Path) -> Result<File, StateError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_DAC, WRITE_OWNER,
    };

    let exists = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(StateError::InvalidPath {
                path: path.to_owned(),
                reason: "Windows reparse-point database paths are not supported",
            });
        }
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(file_error("inspect Windows database path", path, error)),
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    if exists {
        options.create(false);
    } else {
        options
            .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)
            .create_new(true);
    }
    let file = options
        .open(path)
        .map_err(|error| file_error("open Windows database atomically", path, error))?;
    reject_windows_reparse(
        path,
        &file
            .metadata()
            .map_err(|error| file_error("inspect Windows database handle", path, error))?,
    )?;
    if !exists {
        claw_sqlite_file_control::secure_new_windows_file(&file).map_err(|error| {
            StateError::InvalidPath {
                path: path.to_owned(),
                reason: match error.code() {
                    Some(_) => "new state database security descriptor could not be applied",
                    None => "new state database security descriptor could not be applied",
                },
            }
        })?;
    }
    Ok(file)
}

#[cfg(unix)]
fn validate_private_database_file(path: &Path, file: &File) -> Result<(), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| file_error("inspect state database security", path, error))?;
    if !metadata.file_type().is_file()
        || !claw_sqlite_file_control::unix_file_is_service_private(
            file,
            rustix::process::geteuid().as_raw(),
            0o600,
        )
        .map_err(|_| StateError::InvalidPath {
            path: path.to_owned(),
            reason: "state database ACL could not be validated",
        })?
        || metadata.nlink() != 1
    {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "state database must be service-owned, mode 0600, regular, and single-link",
        });
    }

    Ok(())
}

#[cfg(windows)]
fn validate_private_database_file(path: &Path, file: &File) -> Result<(), StateError> {
    if !claw_sqlite_file_control::windows_file_is_service_private(file).map_err(|_| {
        StateError::InvalidPath {
            path: path.to_owned(),
            reason: "state database security descriptor could not be validated",
        }
    })? {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "state database grants write or delete access outside the service identity",
        });
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn validate_private_database_file(path: &Path, _file: &File) -> Result<(), StateError> {
    Err(StateError::InvalidPath {
        path: path.to_owned(),
        reason: "private state database files are unsupported on this platform",
    })
}

#[cfg(unix)]
fn secure_private_snapshot_file(path: &Path) -> Result<(), StateError> {
    use std::os::unix::fs::PermissionsExt as _;

    let file = open_existing_file_no_follow_writable(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| file_error("secure private SQLite artifact", path, error))?;
    validate_private_database_file(path, &file)
}

#[cfg(windows)]
fn secure_private_snapshot_file(path: &Path) -> Result<(), StateError> {
    let file = open_windows_security_file(path)?;
    claw_sqlite_file_control::secure_new_windows_file(&file).map_err(|_| {
        StateError::InvalidPath {
            path: path.to_owned(),
            reason: "private SQLite artifact security descriptor could not be applied",
        }
    })?;
    validate_private_database_file(path, &file)
}

#[cfg(windows)]
fn open_windows_security_file(path: &Path) -> Result<File, StateError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_DAC, WRITE_OWNER,
    };

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| file_error("open Windows security handle", path, error))?;
    reject_windows_reparse(
        path,
        &file
            .metadata()
            .map_err(|error| file_error("inspect Windows security handle", path, error))?,
    )?;
    Ok(file)
}

#[cfg(all(not(unix), not(windows)))]
fn secure_private_snapshot_file(path: &Path) -> Result<(), StateError> {
    Err(StateError::InvalidPath {
        path: path.to_owned(),
        reason: "private SQLite artifacts are unsupported on this platform",
    })
}

#[cfg(unix)]
fn validate_private_snapshot_file(path: &Path, file: &File) -> Result<(), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| file_error("inspect snapshot security", path, error))?;
    let mode = metadata.mode() & 0o7777;
    if !metadata.file_type().is_file()
        || !matches!(mode, 0o400 | 0o600)
        || !claw_sqlite_file_control::unix_file_is_service_private(
            file,
            rustix::process::geteuid().as_raw(),
            mode,
        )
        .map_err(|_| StateError::InvalidPath {
            path: path.to_owned(),
            reason: "snapshot ACL could not be validated",
        })?
        || metadata.nlink() != 1
    {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "snapshot must be service-owned, private, regular, and single-link",
        });
    }
    Ok(())
}

#[cfg(windows)]
fn validate_private_snapshot_file(path: &Path, file: &File) -> Result<(), StateError> {
    validate_private_database_file(path, file)
}

#[cfg(all(not(unix), not(windows)))]
fn validate_private_snapshot_file(path: &Path, _file: &File) -> Result<(), StateError> {
    Err(StateError::InvalidPath {
        path: path.to_owned(),
        reason: "private snapshots are unsupported on this platform",
    })
}

#[cfg(all(not(unix), not(windows)))]
fn open_database_file(path: &Path) -> Result<File, StateError> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|error| file_error("open state database file", path, error))
}

#[cfg(windows)]
fn open_windows_file_no_follow(path: &Path, create: bool, write: bool) -> Result<File, StateError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    OpenOptions::new()
        .create(create)
        .read(true)
        .write(write)
        .truncate(false)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            file_error(
                "open Windows file without following reparse points",
                path,
                error,
            )
        })
}

#[cfg(windows)]
fn open_windows_directory_no_follow(path: &Path) -> Result<File, StateError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            file_error(
                "open Windows directory without reparse traversal",
                path,
                error,
            )
        })
}

#[cfg(windows)]
fn reject_windows_reparse(path: &Path, metadata: &std::fs::Metadata) -> Result<(), StateError> {
    use std::os::windows::fs::MetadataExt as _;

    if metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
    {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "Windows reparse-point database paths are not supported",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn reject_hard_link(path: &Path, file: &File) -> Result<(), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    if file
        .metadata()
        .map_err(|error| file_error("inspect state database links", path, error))?
        .nlink()
        > 1
    {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "hard-linked SQLite databases are not supported",
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_hard_link(_path: &Path, _file: &File) -> Result<(), StateError> {
    Ok(())
}

#[cfg(unix)]
fn verify_path_identity(path: &Path, file: &File) -> Result<(), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|error| file_error("verify state database path", path, error))?;
    if path_metadata.file_type().is_symlink() {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "symbolic-link database paths are not supported",
        });
    }
    let file_metadata = file
        .metadata()
        .map_err(|error| file_error("verify state database handle", path, error))?;
    if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino() {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "database path changed after its identity was verified",
        });
    }
    Ok(())
}

#[cfg(windows)]
fn verify_path_identity(path: &Path, file: &File) -> Result<(), StateError> {
    let current = open_windows_file_no_follow(path, false, false)?;
    reject_windows_reparse(
        path,
        &current
            .metadata()
            .map_err(|error| file_error("verify Windows database path", path, error))?,
    )?;
    let expected = same_file::Handle::from_file(
        file.try_clone()
            .map_err(|error| file_error("clone Windows identity handle", path, error))?,
    )
    .map_err(|error| file_error("read locked Windows file identity", path, error))?;
    let current = same_file::Handle::from_file(current)
        .map_err(|error| file_error("read current Windows file identity", path, error))?;
    if expected != current {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "database path changed after its Windows identity was verified",
        });
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn verify_path_identity(path: &Path, _file: &File) -> Result<(), StateError> {
    if std::fs::symlink_metadata(path)
        .map_err(|error| file_error("verify state database path", path, error))?
        .file_type()
        .is_symlink()
    {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "symbolic-link database paths are not supported",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn verify_directory_path_identity(path: &Path, file: &File) -> Result<(), StateError> {
    verify_path_identity(path, file)
}

#[cfg(windows)]
fn verify_directory_path_identity(path: &Path, file: &File) -> Result<(), StateError> {
    let current = open_windows_directory_no_follow(path)?;
    let expected = claw_sqlite_file_control::windows_file_identity(file).map_err(|_| {
        StateError::InvalidPath {
            path: path.to_owned(),
            reason: "stable Windows state-directory identity is unavailable",
        }
    })?;
    let actual = claw_sqlite_file_control::windows_file_identity(&current).map_err(|_| {
        StateError::InvalidPath {
            path: path.to_owned(),
            reason: "current Windows state-directory identity is unavailable",
        }
    })?;
    if expected != actual {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "state directory path changed after its identity was verified",
        });
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn verify_directory_path_identity(path: &Path, _file: &File) -> Result<(), StateError> {
    Err(StateError::InvalidPath {
        path: path.to_owned(),
        reason: "stable state-directory identity is unsupported on this platform",
    })
}

#[cfg(unix)]
fn open_existing_file_no_follow(path: &Path) -> Result<File, StateError> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| file_error("open file without following links", path, error.into()))
}

#[cfg(windows)]
fn open_existing_file_no_follow(path: &Path) -> Result<File, StateError> {
    let file = open_windows_file_no_follow(path, false, false)?;
    reject_windows_reparse(
        path,
        &file
            .metadata()
            .map_err(|error| file_error("inspect Windows file handle", path, error))?,
    )?;
    Ok(file)
}

#[cfg(all(not(unix), not(windows)))]
fn open_existing_file_no_follow(path: &Path) -> Result<File, StateError> {
    File::open(path).map_err(|error| file_error("open file without following links", path, error))
}

#[cfg(unix)]
fn open_existing_file_no_follow_writable(path: &Path) -> Result<File, StateError> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        file_error(
            "open writable file without following links",
            path,
            error.into(),
        )
    })
}

#[cfg(windows)]
fn open_existing_file_no_follow_writable(path: &Path) -> Result<File, StateError> {
    let file = open_windows_file_no_follow(path, false, true)?;
    reject_windows_reparse(
        path,
        &file
            .metadata()
            .map_err(|error| file_error("inspect writable Windows file handle", path, error))?,
    )?;
    Ok(file)
}

#[cfg(all(not(unix), not(windows)))]
fn open_existing_file_no_follow_writable(path: &Path) -> Result<File, StateError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| file_error("open writable file without following links", path, error))
}

fn writer_owner() -> Result<String, StateError> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| StateError::InvalidValue {
        field: "OS random source",
        reason: "failed to generate a writer identity nonce",
    })?;
    Ok(format!(
        "process-{}-{}",
        std::process::id(),
        hex_encode(&nonce)
    ))
}

#[cfg(unix)]
fn snapshot_temporary_path(destination: &Path, purpose: &str) -> Result<PathBuf, StateError> {
    let digest = migration_checksum(&destination.to_string_lossy());
    Ok(private_lock_root_for(destination)?.join(format!(
        ".gta-claw-{purpose}-{digest}-{}.sqlite",
        writer_owner()?
    )))
}

#[cfg(not(unix))]
fn snapshot_temporary_path(destination: &Path, purpose: &str) -> Result<PathBuf, StateError> {
    let owner = writer_owner()?;
    let digest = migration_checksum(&destination.to_string_lossy());
    Ok(destination.with_file_name(format!(".gta-claw-{purpose}-{digest}-{owner}.sqlite")))
}

fn database_artifacts(database: &Path) -> [PathBuf; 4] {
    [
        database.to_owned(),
        sqlite_sidecar(database, "-wal"),
        sqlite_sidecar(database, "-shm"),
        sqlite_sidecar(database, "-journal"),
    ]
}

fn sqlite_mutable_sidecars(database: &Path) -> [PathBuf; 3] {
    [
        sqlite_sidecar(database, "-wal"),
        sqlite_sidecar(database, "-shm"),
        sqlite_sidecar(database, "-journal"),
    ]
}

#[cfg(unix)]
fn validate_preflight_sidecars(database: &Path, database_file: &File) -> Result<(), StateError> {
    use xattr::FileExt as _;

    let sidecars = sqlite_mutable_sidecars(database);
    let mut any_sidecar = false;
    for sidecar in &sidecars {
        any_sidecar |= path_entry_exists(sidecar)?;
    }
    if !any_sidecar {
        return Ok(());
    }
    let generation = database_file
        .get_xattr(UNIX_LOCK_IDENTITY_XATTR)
        .map_err(|error| file_error("read preflight database generation", database, error))?
        .ok_or_else(|| StateError::InvalidPath {
            path: database.to_owned(),
            reason: "database with sidecars is missing its persistent generation",
        })?;
    for sidecar in sidecars {
        if !path_entry_exists(&sidecar)? {
            continue;
        }
        let file = open_existing_file_no_follow(&sidecar)?;
        validate_private_database_file(&sidecar, &file)?;
        let actual = file
            .get_xattr(UNIX_SIDECAR_GENERATION_XATTR)
            .map_err(|error| file_error("read preflight sidecar generation", &sidecar, error))?
            .ok_or_else(|| StateError::InvalidPath {
                path: sidecar.clone(),
                reason: "SQLite sidecar generation is missing",
            })?;
        if actual != generation {
            return Err(StateError::InvalidPath {
                path: sidecar,
                reason: "SQLite sidecar belongs to a different database generation",
            });
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_preflight_sidecars(database: &Path, database_file: &File) -> Result<(), StateError> {
    let mut any_sidecar = false;
    for sidecar in sqlite_mutable_sidecars(database) {
        any_sidecar |= path_entry_exists(&sidecar)?;
    }
    if !any_sidecar {
        return Ok(());
    }
    let lock_path = lock_path_for(database);
    let lock_file = open_windows_file_no_follow(&lock_path, false, false)?;
    match lock_file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(StateError::StoreLocked { path: lock_path });
        }
        Err(std::fs::TryLockError::Error(error)) => {
            return Err(file_error(
                "acquire preflight Windows writer lock",
                &lock_path,
                error,
            ));
        }
    }
    let generation =
        verify_windows_lock_binding(database, database_file, &lock_path, &lock_file, None)?;
    let generation_record =
        claw_sqlite_file_control::windows_sidecar_generation_record(&generation);
    File::unlock(&lock_file)
        .map_err(|error| file_error("release preflight Windows writer lock", &lock_path, error))?;
    for sidecar in sqlite_mutable_sidecars(database) {
        if !path_entry_exists(&sidecar)? {
            continue;
        }
        let file = open_existing_file_no_follow(&sidecar)?;
        validate_private_database_file(&sidecar, &file)?;
        match read_windows_sidecar_generation(&sidecar, generation_record.len())? {
            WindowsSidecarGeneration::Value(actual) if actual != generation_record => {
                return Err(StateError::InvalidPath {
                    path: sidecar,
                    reason: "SQLite sidecar belongs to a different database generation",
                });
            }
            WindowsSidecarGeneration::Value(_) => {}
            WindowsSidecarGeneration::Missing => {
                return Err(StateError::InvalidPath {
                    path: sidecar,
                    reason: "SQLite sidecar generation is missing",
                });
            }
            WindowsSidecarGeneration::Incomplete => {
                return Err(StateError::InvalidPath {
                    path: sidecar,
                    reason: "SQLite sidecar generation is incomplete",
                });
            }
        }
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn validate_preflight_sidecars(database: &Path, _database_file: &File) -> Result<(), StateError> {
    if sqlite_mutable_sidecars(database)
        .iter()
        .any(|sidecar| path_entry_exists(sidecar).unwrap_or(true))
    {
        return Err(StateError::InvalidPath {
            path: database.to_owned(),
            reason: "preflight sidecar validation is unsupported",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn secure_sqlite_sidecars(database: &Path, generation: Option<&[u8]>) -> Result<(), StateError> {
    use std::os::unix::fs::PermissionsExt as _;
    use xattr::FileExt as _;

    let generation = generation.ok_or_else(|| StateError::InvalidPath {
        path: database.to_owned(),
        reason: "sidecar generation is unavailable",
    })?;
    for sidecar in sqlite_mutable_sidecars(database) {
        if !path_entry_exists(&sidecar)? {
            continue;
        }
        let file = open_existing_file_no_follow_writable(&sidecar)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| file_error("secure SQLite sidecar", &sidecar, error))?;
        validate_private_database_file(&sidecar, &file)?;
        match file
            .get_xattr(UNIX_SIDECAR_GENERATION_XATTR)
            .map_err(|error| file_error("read SQLite sidecar generation", &sidecar, error))?
        {
            Some(current) if current != generation => {
                return Err(StateError::InvalidPath {
                    path: sidecar,
                    reason: "SQLite sidecar belongs to a different database generation",
                });
            }
            Some(_) => {}
            None => {
                rustix::fs::fsetxattr(
                    &file,
                    UNIX_SIDECAR_GENERATION_XATTR,
                    generation,
                    rustix::fs::XattrFlags::CREATE,
                )
                .map_err(|error| {
                    file_error("persist SQLite sidecar generation", &sidecar, error.into())
                })?;
                file.sync_all().map_err(|error| {
                    file_error("sync SQLite sidecar generation", &sidecar, error)
                })?;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_sqlite_sidecars(database: &Path, generation: Option<&[u8]>) -> Result<(), StateError> {
    use xattr::FileExt as _;

    let generation = generation.ok_or_else(|| StateError::InvalidPath {
        path: database.to_owned(),
        reason: "sidecar generation is unavailable",
    })?;
    for sidecar in sqlite_mutable_sidecars(database) {
        if !path_entry_exists(&sidecar)? {
            continue;
        }
        let file = open_existing_file_no_follow(&sidecar)?;
        validate_private_database_file(&sidecar, &file)?;
        let current = file
            .get_xattr(UNIX_SIDECAR_GENERATION_XATTR)
            .map_err(|error| file_error("verify SQLite sidecar generation", &sidecar, error))?
            .ok_or_else(|| StateError::InvalidPath {
                path: sidecar.clone(),
                reason: "SQLite sidecar generation is missing",
            })?;
        if current != generation {
            return Err(StateError::InvalidPath {
                path: sidecar,
                reason: "SQLite sidecar belongs to a different database generation",
            });
        }
    }
    Ok(())
}

#[cfg(windows)]
fn sidecar_generation_path(sidecar: &Path) -> PathBuf {
    let mut path = sidecar.as_os_str().to_owned();
    path.push(":gta-claw-generation");
    PathBuf::from(path)
}

#[cfg(windows)]
enum WindowsSidecarGeneration {
    Missing,
    Incomplete,
    Value(Vec<u8>),
}

#[cfg(windows)]
fn read_windows_sidecar_generation(
    sidecar: &Path,
    expected_len: usize,
) -> Result<WindowsSidecarGeneration, StateError> {
    use std::io::Read as _;

    let path = sidecar_generation_path(sidecar);
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(WindowsSidecarGeneration::Missing);
        }
        Err(error) => return Err(file_error("open SQLite sidecar generation", sidecar, error)),
    };
    let length = file
        .metadata()
        .map_err(|error| file_error("inspect SQLite sidecar generation", sidecar, error))?
        .len();
    if length != u64::try_from(expected_len).expect("generation length fits u64") {
        return Ok(WindowsSidecarGeneration::Incomplete);
    }
    let mut generation = vec![0_u8; expected_len];
    file.read_exact(&mut generation)
        .map_err(|error| file_error("read SQLite sidecar generation", sidecar, error))?;
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|error| file_error("finish SQLite sidecar generation", sidecar, error))?
        != 0
    {
        return Err(StateError::InvalidPath {
            path: sidecar.to_owned(),
            reason: "SQLite sidecar generation exceeds its expected length",
        });
    }
    Ok(WindowsSidecarGeneration::Value(generation))
}

#[cfg(windows)]
fn secure_sqlite_sidecars(database: &Path, generation: Option<&[u8]>) -> Result<(), StateError> {
    use std::io::Write as _;

    let generation = generation.ok_or_else(|| StateError::InvalidPath {
        path: database.to_owned(),
        reason: "sidecar generation is unavailable",
    })?;
    let generation_record = claw_sqlite_file_control::windows_sidecar_generation_record(generation);
    for sidecar in sqlite_mutable_sidecars(database) {
        if !path_entry_exists(&sidecar)? {
            continue;
        }
        let file = open_existing_file_no_follow_writable(&sidecar)?;
        let generation_path = sidecar_generation_path(&sidecar);
        match read_windows_sidecar_generation(&sidecar, generation_record.len())? {
            WindowsSidecarGeneration::Value(current) => {
                validate_private_database_file(&sidecar, &file)?;
                if current != generation_record {
                    return Err(StateError::InvalidPath {
                        path: sidecar,
                        reason: "SQLite sidecar belongs to a different database generation",
                    });
                }
            }
            WindowsSidecarGeneration::Missing => {
                let security_file = open_windows_security_file(&sidecar)?;
                claw_sqlite_file_control::secure_new_windows_file(&security_file).map_err(
                    |_| StateError::InvalidPath {
                        path: sidecar.clone(),
                        reason: "new SQLite sidecar security descriptor could not be applied",
                    },
                )?;
                validate_private_database_file(&sidecar, &security_file)?;
                let mut metadata = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&generation_path)
                    .map_err(|error| {
                        file_error("create SQLite sidecar generation", &sidecar, error)
                    })?;
                metadata
                    .write_all(&generation_record)
                    .and_then(|()| metadata.sync_all())
                    .map_err(|error| {
                        file_error("persist SQLite sidecar generation", &sidecar, error)
                    })?;
            }
            WindowsSidecarGeneration::Incomplete => {
                return Err(StateError::InvalidPath {
                    path: sidecar,
                    reason: "SQLite sidecar generation is incomplete",
                });
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_sqlite_sidecars(database: &Path, generation: Option<&[u8]>) -> Result<(), StateError> {
    let generation = generation.ok_or_else(|| StateError::InvalidPath {
        path: database.to_owned(),
        reason: "sidecar generation is unavailable",
    })?;
    let generation_record = claw_sqlite_file_control::windows_sidecar_generation_record(generation);
    for sidecar in sqlite_mutable_sidecars(database) {
        if !path_entry_exists(&sidecar)? {
            continue;
        }
        let file = open_existing_file_no_follow(&sidecar)?;
        validate_private_database_file(&sidecar, &file)?;
        let current = match read_windows_sidecar_generation(&sidecar, generation_record.len())? {
            WindowsSidecarGeneration::Value(current) => current,
            WindowsSidecarGeneration::Missing if !path_entry_exists(&sidecar)? => continue,
            WindowsSidecarGeneration::Missing => {
                return Err(StateError::InvalidPath {
                    path: sidecar,
                    reason: "SQLite sidecar generation is missing",
                });
            }
            WindowsSidecarGeneration::Incomplete => {
                return Err(StateError::InvalidPath {
                    path: sidecar,
                    reason: "SQLite sidecar generation is incomplete",
                });
            }
        };
        if current != generation_record {
            return Err(StateError::InvalidPath {
                path: sidecar,
                reason: "SQLite sidecar belongs to a different database generation",
            });
        }
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn secure_sqlite_sidecars(database: &Path, _generation: Option<&[u8]>) -> Result<(), StateError> {
    Err(StateError::InvalidPath {
        path: database.to_owned(),
        reason: "secure SQLite sidecars are unsupported on this platform",
    })
}

#[cfg(all(not(unix), not(windows)))]
fn validate_sqlite_sidecars(database: &Path, _generation: Option<&[u8]>) -> Result<(), StateError> {
    secure_sqlite_sidecars(database, None)
}

fn ensure_database_artifacts_absent(database: &Path) -> Result<(), StateError> {
    for collision in database_artifacts(database) {
        if path_entry_exists(&collision)? {
            return Err(StateError::BackupDestinationExists { path: collision });
        }
    }
    let lock_path = writer_lock_collision_path(database);
    if path_entry_exists(&lock_path)? {
        return Err(StateError::BackupDestinationExists { path: lock_path });
    }
    Ok(())
}

struct PinnedSnapshot {
    path: PathBuf,
    file: File,
    parent_path: PathBuf,
    parent_directory: File,
}

struct SnapshotCleanupGuard {
    path: PathBuf,
    pinned_parent: Option<File>,
    expected_file: Option<File>,
    armed: bool,
}

impl SnapshotCleanupGuard {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            pinned_parent: None,
            expected_file: None,
            armed: true,
        }
    }

    fn new_pinned(path: &Path, parent: &PinnedPrivateDirectory) -> Result<Self, StateError> {
        Ok(Self {
            path: path.to_owned(),
            pinned_parent: Some(parent.file.try_clone().map_err(|error| {
                file_error("clone cleanup directory handle", &parent.path, error)
            })?),
            expected_file: None,
            armed: true,
        })
    }

    fn bind_file(&mut self, file: &File) -> Result<(), StateError> {
        #[cfg(unix)]
        {
            self.expected_file =
                Some(file.try_clone().map_err(|error| {
                    file_error("clone cleanup identity handle", &self.path, error)
                })?);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };

            let expected = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&self.path)
                .map_err(|error| file_error("open cleanup identity handle", &self.path, error))?;
            reject_windows_reparse(
                &self.path,
                &expected.metadata().map_err(|error| {
                    file_error("inspect cleanup identity handle", &self.path, error)
                })?,
            )?;
            if !files_share_identity_from_handles_portable(file, &expected)? {
                return Err(StateError::InvalidPath {
                    path: self.path.clone(),
                    reason: "cleanup identity handle does not match staging file",
                });
            }
            self.expected_file = Some(expected);
        }
        Ok(())
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
fn verify_child_identity_at(parent: &File, path: &Path, expected: &File) -> Result<(), StateError> {
    let name = path.file_name().ok_or_else(|| StateError::InvalidPath {
        path: path.to_owned(),
        reason: "pinned child has no file name",
    })?;
    let current = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        file_error(
            "open cleanup child through pinned parent",
            path,
            error.into(),
        )
    })?;
    if files_share_identity_from_handles_portable(expected, &current)? {
        Ok(())
    } else {
        Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "cleanup child no longer matches its pinned identity",
        })
    }
}

impl Drop for SnapshotCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        #[cfg(unix)]
        if let (Some(parent), Some(expected_file)) =
            (self.pinned_parent.as_ref(), self.expected_file.as_ref())
            && verify_child_identity_at(parent, &self.path, expected_file).is_err()
        {
            return;
        }
        #[cfg(not(unix))]
        if let Some(expected_file) = &self.expected_file
            && verify_path_identity(&self.path, expected_file).is_err()
        {
            return;
        }
        #[cfg(not(unix))]
        let _pinned_parent_lifetime = self.pinned_parent.as_ref();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        for artifact in database_artifacts(&self.path) {
            loop {
                #[cfg(unix)]
                let removal = if let Some(parent) = self.pinned_parent.as_ref() {
                    artifact
                        .file_name()
                        .ok_or_else(|| std::io::Error::other("artifact has no file name"))
                        .and_then(|name| {
                            rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::empty())
                                .map_err(std::io::Error::from)
                        })
                } else {
                    std::fs::remove_file(&artifact)
                };
                #[cfg(not(unix))]
                let removal = std::fs::remove_file(&artifact);
                match removal {
                    Ok(()) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                    Err(error)
                        if std::time::Instant::now() < deadline
                            && (matches!(error.raw_os_error(), Some(32) | Some(33))
                                || error.kind() == std::io::ErrorKind::PermissionDenied) =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

struct OperationCancellationGuard {
    state: Arc<OpenDeadlineState>,
    armed: bool,
}

impl OperationCancellationGuard {
    fn new(state: Arc<OpenDeadlineState>) -> Self {
        Self { state, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for OperationCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.state.cancel();
        }
    }
}

struct BackupConnectionGuard {
    connection: Option<sqlx::pool::PoolConnection<sqlx::Sqlite>>,
    cancellation: Option<Arc<OpenDeadlineState>>,
    reusable: bool,
    runtime: Option<tokio::runtime::Handle>,
}

impl BackupConnectionGuard {
    fn new_cancellable(
        connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
        cancellation: Arc<OpenDeadlineState>,
    ) -> Self {
        Self {
            connection: Some(connection),
            cancellation: Some(cancellation),
            reusable: false,
            runtime: tokio::runtime::Handle::try_current().ok(),
        }
    }

    fn mark_reusable(&mut self) {
        self.reusable = true;
    }

    async fn discard(&mut self) {
        if let Some(cancellation) = &self.cancellation {
            cancellation
                .cancelled
                .store(true, std::sync::atomic::Ordering::Release);
        }
        if let Some(connection) = self.connection.take() {
            let _ = connection.close().await;
        }
    }
}

impl std::ops::Deref for BackupConnectionGuard {
    type Target = SqliteConnection;

    fn deref(&self) -> &Self::Target {
        self.connection
            .as_ref()
            .expect("backup connection remains live")
            .as_ref()
    }
}

impl std::ops::DerefMut for BackupConnectionGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connection
            .as_mut()
            .expect("backup connection remains live")
            .as_mut()
    }
}

impl Drop for BackupConnectionGuard {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            if self.reusable {
                if let Some(runtime) = &self.runtime {
                    let _runtime_context = runtime.enter();
                    drop(connection);
                } else {
                    std::mem::forget(connection);
                }
            } else {
                if let Some(cancellation) = &self.cancellation {
                    cancellation
                        .cancelled
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                if let Some(runtime) = &self.runtime {
                    let runtime = runtime.clone();
                    let connection = Arc::new(std::sync::Mutex::new(Some(connection)));
                    let worker_connection = Arc::clone(&connection);
                    let worker_runtime = runtime.clone();
                    let worker = std::thread::Builder::new()
                        .name("claw-state-pool-close".to_owned())
                        .spawn(move || {
                            if let Some(connection) = worker_connection
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .take()
                            {
                                let _ = worker_runtime.block_on(connection.close());
                            }
                        });
                    if let Ok(worker) = worker {
                        let _ = worker.join();
                    } else if let Some(connection) = connection
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                    {
                        runtime.spawn(async move {
                            let _ = connection.close().await;
                        });
                    }
                } else {
                    std::mem::forget(connection);
                }
            }
        }
    }
}

struct OwnedSqliteConnectionGuard {
    connection: Option<SqliteConnection>,
    cancellation: Option<Arc<OpenDeadlineState>>,
    runtime: Option<tokio::runtime::Handle>,
}

impl OwnedSqliteConnectionGuard {
    fn new(connection: SqliteConnection) -> Self {
        Self {
            connection: Some(connection),
            cancellation: None,
            runtime: tokio::runtime::Handle::try_current().ok(),
        }
    }

    fn new_cancellable(
        connection: SqliteConnection,
        cancellation: Option<Arc<OpenDeadlineState>>,
    ) -> Self {
        Self {
            connection: Some(connection),
            cancellation,
            runtime: tokio::runtime::Handle::try_current().ok(),
        }
    }

    async fn close(mut self) -> Result<(), sqlx::Error> {
        let result = self
            .connection
            .take()
            .expect("owned SQLite connection remains live")
            .close()
            .await;
        self.cancellation = None;
        result
    }
}

impl std::ops::Deref for OwnedSqliteConnectionGuard {
    type Target = SqliteConnection;

    fn deref(&self) -> &Self::Target {
        self.connection
            .as_ref()
            .expect("owned SQLite connection remains live")
    }
}

impl std::ops::DerefMut for OwnedSqliteConnectionGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connection
            .as_mut()
            .expect("owned SQLite connection remains live")
    }
}

impl Drop for OwnedSqliteConnectionGuard {
    fn drop(&mut self) {
        if let Some(cancellation) = &self.cancellation {
            cancellation
                .cancelled
                .store(true, std::sync::atomic::Ordering::Release);
        }
        if let Some(connection) = self.connection.take() {
            if let Some(runtime) = &self.runtime {
                let runtime = runtime.clone();
                let connection = Arc::new(std::sync::Mutex::new(Some(connection)));
                let worker_connection = Arc::clone(&connection);
                let worker_runtime = runtime.clone();
                let worker = std::thread::Builder::new()
                    .name("claw-state-close".to_owned())
                    .spawn(move || {
                        if let Some(connection) = worker_connection
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                        {
                            let _ = worker_runtime.block_on(connection.close());
                        }
                    });
                if let Ok(worker) = worker {
                    let _ = worker.join();
                } else if let Some(connection) = connection
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    runtime.spawn(async move {
                        let _ = connection.close().await;
                    });
                }
            } else {
                let connection = Arc::new(std::sync::Mutex::new(Some(connection)));
                let worker_connection = Arc::clone(&connection);
                let worker = std::thread::Builder::new()
                    .name("claw-state-close".to_owned())
                    .spawn(move || {
                        let connection = worker_connection
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take();
                        let Some(connection) = connection else {
                            return;
                        };
                        match tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        {
                            Ok(runtime) => {
                                let _ = runtime.block_on(connection.close());
                            }
                            Err(_) => drop(connection),
                        }
                    });
                if worker.is_err()
                    && let Some(connection) = connection
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                {
                    drop(connection);
                }
            }
        }
    }
}

impl PinnedSnapshot {
    fn open(path: &Path) -> Result<Self, StateError> {
        let file = open_existing_file_no_follow(path)?;
        verify_path_identity(path, &file)?;
        reject_hard_link(path, &file)?;
        Self::from_file(path, file)
    }

    fn from_file(path: &Path, file: File) -> Result<Self, StateError> {
        validate_private_snapshot_file(path, &file)?;
        let (parent_path, parent_directory) = {
            let pinned = pin_private_directory(path)?;
            (pinned.path, pinned.file)
        };
        Ok(Self {
            path: path.to_owned(),
            file,
            parent_path,
            parent_directory,
        })
    }

    fn verify(&self) -> Result<(), StateError> {
        verify_path_identity(&self.path, &self.file)?;
        verify_directory_path_identity(&self.parent_path, &self.parent_directory)?;
        Ok(())
    }

    fn cleanup(self) -> Result<(), StateError> {
        #[cfg(unix)]
        {
            verify_child_identity_at(&self.parent_directory, &self.path, &self.file)?;
            let file_name = self
                .path
                .file_name()
                .ok_or_else(|| StateError::InvalidPath {
                    path: self.path.clone(),
                    reason: "snapshot has no file name",
                })?;
            rustix::fs::unlinkat(
                &self.parent_directory,
                file_name,
                rustix::fs::AtFlags::empty(),
            )
            .map_err(|error| {
                file_error(
                    "remove pinned snapshot through held parent",
                    &self.path,
                    error.into(),
                )
            })
        }
        #[cfg(windows)]
        {
            self.verify()?;
            let path = self.path.clone();
            drop(self);
            remove_snapshot_artifacts(&path)
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            Err(StateError::InvalidPath {
                path: self.path,
                reason: "pinned snapshot cleanup is unsupported",
            })
        }
    }

    fn sync(&self) -> Result<(), StateError> {
        self.verify()?;
        let writable = open_existing_file_no_follow_writable(&self.path)?;
        if !files_share_identity_from_handles_portable(&self.file, &writable)? {
            return Err(StateError::InvalidPath {
                path: self.path.clone(),
                reason: "snapshot changed before durable sync",
            });
        }
        writable
            .sync_all()
            .map_err(|error| file_error("sync pinned SQLite snapshot", &self.path, error))?;
        self.verify()
    }
}

fn path_entry_exists(path: &Path) -> Result<bool, StateError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(file_error("inspect filesystem entry", path, error)),
    }
}

struct SidecarReservations {
    wal_path: PathBuf,
    shm_path: PathBuf,
    journal_path: PathBuf,
    _wal_file: File,
    _shm_file: File,
    _journal_file: File,
}

impl SidecarReservations {
    fn release(self) -> Result<(), StateError> {
        let Self {
            wal_path,
            shm_path,
            journal_path,
            _wal_file,
            _shm_file,
            _journal_file,
        } = self;
        verify_path_identity(&wal_path, &_wal_file)?;
        verify_path_identity(&shm_path, &_shm_file)?;
        verify_path_identity(&journal_path, &_journal_file)?;
        drop((_wal_file, _shm_file, _journal_file));
        std::fs::remove_file(&wal_path)
            .map_err(|error| file_error("release destination WAL reservation", &wal_path, error))?;
        std::fs::remove_file(&shm_path)
            .map_err(|error| file_error("release destination SHM reservation", &shm_path, error))?;
        std::fs::remove_file(&journal_path).map_err(|error| {
            file_error(
                "release destination journal reservation",
                &journal_path,
                error,
            )
        })
    }
}

fn reserve_destination_sidecars(database: &Path) -> Result<SidecarReservations, StateError> {
    ensure_database_artifacts_absent(database)?;
    let wal_path = sqlite_sidecar(database, "-wal");
    let shm_path = sqlite_sidecar(database, "-shm");
    let journal_path = sqlite_sidecar(database, "-journal");
    let wal_file = match OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&wal_path)
    {
        Ok(file) => file,
        Err(error) => {
            return if path_entry_exists(&wal_path)? {
                Err(StateError::BackupDestinationExists { path: wal_path })
            } else {
                Err(file_error("reserve destination WAL", &wal_path, error))
            };
        }
    };
    let shm_file = match OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&shm_path)
    {
        Ok(file) => file,
        Err(error) => {
            let mut primary = file_error("reserve destination SHM", &shm_path, error);
            match path_entry_exists(&shm_path) {
                Ok(true) => {
                    primary = StateError::BackupDestinationExists {
                        path: shm_path.clone(),
                    };
                }
                Ok(false) => {}
                Err(inspection) => {
                    primary = append_operation_cleanup(
                        "SQLite snapshot reservation",
                        primary,
                        format!("failed destination SHM inspection: {inspection}"),
                    );
                }
            }
            let wal_owned = match verify_path_identity(&wal_path, &wal_file) {
                Ok(()) => true,
                Err(cleanup) => {
                    primary = append_operation_cleanup(
                        "SQLite snapshot reservation",
                        primary,
                        format!("WAL identity cleanup check failed; removal skipped: {cleanup}"),
                    );
                    false
                }
            };
            drop(wal_file);
            if wal_owned && let Err(cleanup) = std::fs::remove_file(&wal_path) {
                primary = append_operation_cleanup(
                    "SQLite snapshot reservation",
                    primary,
                    format!(
                        "WAL reservation cleanup failed: {}",
                        file_error("release destination WAL reservation", &wal_path, cleanup)
                    ),
                );
            }
            return Err(primary);
        }
    };
    let journal_file = match OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&journal_path)
    {
        Ok(file) => file,
        Err(error) => {
            let mut primary = file_error("reserve destination journal", &journal_path, error);
            match path_entry_exists(&journal_path) {
                Ok(true) => {
                    primary = StateError::BackupDestinationExists {
                        path: journal_path.clone(),
                    };
                }
                Ok(false) => {}
                Err(inspection) => {
                    primary = append_operation_cleanup(
                        "SQLite snapshot reservation",
                        primary,
                        format!("failed destination journal inspection: {inspection}"),
                    );
                }
            }
            let mut owned = [true, true];
            for (index, (path, file, label)) in
                [(&wal_path, &wal_file, "WAL"), (&shm_path, &shm_file, "SHM")]
                    .into_iter()
                    .enumerate()
            {
                if let Err(cleanup) = verify_path_identity(path, file) {
                    owned[index] = false;
                    primary = append_operation_cleanup(
                        "SQLite snapshot reservation",
                        primary,
                        format!(
                            "{label} identity cleanup check failed; removal skipped: {cleanup}"
                        ),
                    );
                }
            }
            drop((wal_file, shm_file));
            for (reservation, owned) in [(&wal_path, owned[0]), (&shm_path, owned[1])] {
                if owned && let Err(cleanup) = std::fs::remove_file(reservation) {
                    primary = append_operation_cleanup(
                        "SQLite snapshot reservation",
                        primary,
                        format!(
                            "sidecar reservation cleanup failed: {}",
                            file_error(
                                "release destination sidecar reservation",
                                reservation,
                                cleanup
                            )
                        ),
                    );
                }
            }
            return Err(primary);
        }
    };
    Ok(SidecarReservations {
        wal_path,
        shm_path,
        journal_path,
        _wal_file: wal_file,
        _shm_file: shm_file,
        _journal_file: journal_file,
    })
}

fn publish_snapshot(
    source: PinnedSnapshot,
    destination: &Path,
    operation: &'static str,
    publication_deadline: Option<(tokio::time::Instant, u64)>,
    destination_directory: &PinnedPrivateDirectory,
) -> Result<(), StateError> {
    if let Err(error) = source.verify() {
        return Err(cleanup_pinned_or_error(
            "SQLite snapshot publication",
            source,
            error,
        ));
    }
    if let Err(error) =
        verify_directory_path_identity(&destination_directory.path, &destination_directory.file)
    {
        return Err(cleanup_pinned_or_error(
            "SQLite snapshot publication",
            source,
            error,
        ));
    }
    let source_path = source.path.clone();
    let reservations = reserve_destination_sidecars(destination)?;
    #[cfg(test)]
    if take_publication_failpoint(&CREATE_DESTINATION_BEFORE_PUBLICATION, destination) {
        std::fs::write(destination, b"other publisher")
            .map_err(|error| file_error("inject competing publication", destination, error))?;
    }
    if let Some((deadline, timeout_ms)) = publication_deadline
        && tokio::time::Instant::now() >= deadline
    {
        drop(source);
        let primary = StateError::OperationTimedOut {
            operation,
            timeout_ms,
        };
        return Err(match reservations.release() {
            Ok(()) => primary,
            Err(cleanup) => append_operation_cleanup(
                operation,
                primary,
                format!("reservation cleanup failed: {cleanup}"),
            ),
        });
    }
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))]
    let published = publish_unix_snapshot(&source, destination, destination_directory);
    #[cfg(windows)]
    let published = publish_windows_snapshot(&source_path, destination);
    #[cfg(all(
        unix,
        not(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "redox"
        ))
    ))]
    let published = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace publication is unsupported on this target",
    ));
    if let Err(error) = published {
        #[cfg(unix)]
        let primary = if error.raw_os_error() == Some(18) {
            StateError::InvalidPath {
                path: destination.to_owned(),
                reason: "cross-filesystem snapshot publication is not supported",
            }
        } else {
            file_error(
                "publish SQLite snapshot without replacement",
                destination,
                error,
            )
        };
        #[cfg(not(unix))]
        let primary = file_error(
            "publish SQLite snapshot without replacement",
            destination,
            error,
        );
        let destination_owned = match path_entry_exists(destination) {
            Ok(false) => false,
            Ok(true) => match files_share_identity(&source_path, destination) {
                Ok(owned) => owned,
                Err(identity_error) => {
                    let reservation_cleanup = reservations.release();
                    return Err(StateError::PublicationUncertain {
                        path: destination.to_owned(),
                        reason: format!(
                            "{primary}; could not compare destination ownership: {identity_error}; reservation cleanup: {}",
                            result_diagnostic(reservation_cleanup)
                        ),
                    });
                }
            },
            Err(inspection_error) => {
                let reservation_cleanup = reservations.release();
                return Err(StateError::PublicationUncertain {
                    path: destination.to_owned(),
                    reason: format!(
                        "{primary}; could not inspect destination ownership: {inspection_error}; reservation cleanup: {}",
                        result_diagnostic(reservation_cleanup)
                    ),
                });
            }
        };
        return Err(cleanup_failed_publication(
            &source_path,
            destination,
            reservations,
            primary,
            destination_owned,
        ));
    }
    if let Err(error) = verify_path_identity(destination, &source.file) {
        let reservation_cleanup = reservations.release();
        return Err(StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: format!(
                "destination no longer names the pinned published snapshot: {error}; the competing entry was not removed; reservation cleanup: {}",
                result_diagnostic(reservation_cleanup)
            ),
        });
    }
    #[cfg(windows)]
    {
        #[cfg(test)]
        let injected = take_publication_failpoint(&FAIL_WINDOWS_SOURCE_REMOVAL, destination);
        #[cfg(not(test))]
        let injected = false;
        drop(source);
        if injected {
            let primary = StateError::FileSystem {
                operation: "injected Windows source removal failure",
                path: destination.to_owned(),
                message: "test fault injection".to_owned(),
            };
            return Err(cleanup_failed_publication(
                &source_path,
                destination,
                reservations,
                primary,
                true,
            ));
        }
        if let Err(error) = std::fs::remove_file(&source_path) {
            return Err(cleanup_failed_publication(
                &source_path,
                destination,
                reservations,
                file_error("remove published Windows staging name", &source_path, error),
                true,
            ));
        }
    }
    #[cfg(test)]
    if take_publication_failpoint(&FAIL_AFTER_PUBLICATION, destination) {
        let primary = StateError::FileSystem {
            operation: "injected post-publication failure",
            path: destination.to_owned(),
            message: "test fault injection".to_owned(),
        };
        return Err(cleanup_failed_publication(
            &source_path,
            destination,
            reservations,
            primary,
            true,
        ));
    }
    if let Err(error) = reservations.release() {
        return Err(publication_uncertain_after_release(destination, error));
    }
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))]
    let publication_sync = sync_published_snapshot(&source, destination, destination_directory);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    )))]
    let publication_sync = sync_parent_directory(destination);
    if let Err(error) = publication_sync {
        return Err(StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: format!("snapshot was published but directory sync failed: {error}"),
        });
    }
    Ok(())
}

struct PinnedPrivateDirectory {
    path: PathBuf,
    file: File,
}

fn pin_private_directory(destination: &Path) -> Result<PinnedPrivateDirectory, StateError> {
    let path = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_owned();
    #[cfg(unix)]
    let file = rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| file_error("open pinned publication directory", &path, error.into()))?;
    #[cfg(windows)]
    let file = open_windows_directory_no_follow(&path)?;
    #[cfg(all(not(unix), not(windows)))]
    let file = return Err(StateError::InvalidPath {
        path,
        reason: "pinned private directories are unsupported on this platform",
    });
    verify_directory_path_identity(&path, &file)?;
    validate_pinned_state_directory(&path, &file)?;
    Ok(PinnedPrivateDirectory { path, file })
}

#[cfg(unix)]
fn validate_pinned_state_directory(path: &Path, file: &File) -> Result<(), StateError> {
    let metadata = file
        .metadata()
        .map_err(|error| file_error("inspect pinned state directory", path, error))?;
    if !metadata.file_type().is_dir()
        || !claw_sqlite_file_control::unix_file_is_service_private(
            file,
            rustix::process::geteuid().as_raw(),
            0o700,
        )
        .map_err(|_| StateError::InvalidPath {
            path: path.to_owned(),
            reason: "state directory ACL could not be validated",
        })?
    {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "state directory must be owned by the service, mode 0700, and non-symlink",
        });
    }
    validate_unix_ancestor_rename_safety(path)?;
    Ok(())
}

#[cfg(unix)]
fn validate_unix_ancestor_rename_safety(path: &Path) -> Result<(), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let service_uid = rustix::process::geteuid().as_raw();
    for ancestor in path.ancestors().skip(1) {
        let file = rustix::fs::open(
            ancestor,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            file_error(
                "open state-directory ancestor without traversal",
                ancestor,
                error.into(),
            )
        })?;
        let metadata = file
            .metadata()
            .map_err(|error| file_error("inspect state-directory ancestor", ancestor, error))?;
        let mode = metadata.mode();
        let trusted_owner = matches!(metadata.uid(), 0) || metadata.uid() == service_uid;
        let writable_by_others = mode & 0o022 != 0;
        let root_sticky_directory =
            metadata.uid() == 0 && mode & 0o1000 != 0 && metadata.file_type().is_dir();
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || !trusted_owner
            || (writable_by_others && !root_sticky_directory)
            || !claw_sqlite_file_control::unix_file_has_trivial_acl(&file).map_err(|_| {
                StateError::InvalidPath {
                    path: path.to_owned(),
                    reason: "state directory ancestor ACL could not be validated",
                }
            })?
        {
            return Err(StateError::InvalidPath {
                path: path.to_owned(),
                reason: "state directory ancestors must prevent cross-principal renaming",
            });
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_pinned_state_directory(path: &Path, file: &File) -> Result<(), StateError> {
    reject_windows_reparse(
        path,
        &file
            .metadata()
            .map_err(|error| file_error("inspect pinned Windows state directory", path, error))?,
    )?;
    if !claw_sqlite_file_control::windows_file_is_service_private(file).map_err(|_| {
        StateError::InvalidPath {
            path: path.to_owned(),
            reason: "state directory security descriptor could not be validated",
        }
    })? {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "state directory grants write or delete access outside the service identity",
        });
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn validate_pinned_state_directory(path: &Path, _file: &File) -> Result<(), StateError> {
    Err(StateError::InvalidPath {
        path: path.to_owned(),
        reason: "private state directories are unsupported on this platform",
    })
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "redox"
))]
fn publish_unix_snapshot(
    source: &PinnedSnapshot,
    destination: &Path,
    destination_directory: &PinnedPrivateDirectory,
) -> std::io::Result<()> {
    verify_directory_path_identity(&destination_directory.path, &destination_directory.file)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let source_name = source
        .path
        .file_name()
        .ok_or_else(|| std::io::Error::other("snapshot source has no file name"))?;
    let destination_name = destination
        .file_name()
        .ok_or_else(|| std::io::Error::other("snapshot destination has no file name"))?;
    rustix::fs::renameat_with(
        &source.parent_directory,
        source_name,
        &destination_directory.file,
        destination_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "redox"
))]
fn sync_published_snapshot(
    source: &PinnedSnapshot,
    destination: &Path,
    destination_directory: &PinnedPrivateDirectory,
) -> Result<(), StateError> {
    verify_directory_path_identity(&destination_directory.path, &destination_directory.file)?;
    let destination_name = destination
        .file_name()
        .ok_or_else(|| StateError::InvalidPath {
            path: destination.to_owned(),
            reason: "snapshot destination has no file name",
        })?;
    let published_file = rustix::fs::openat(
        &destination_directory.file,
        destination_name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        file_error(
            "open published snapshot through pinned directory",
            destination,
            error.into(),
        )
    })?;
    if !files_share_identity_from_handles_portable(&source.file, &published_file)? {
        return Err(StateError::InvalidPath {
            path: destination.to_owned(),
            reason: "published snapshot identity changed before durable sync",
        });
    }
    #[cfg(target_vendor = "apple")]
    rustix::fs::fcntl_fullfsync(&published_file)
        .map_err(|error| file_error("full sync published snapshot", destination, error.into()))?;
    #[cfg(not(target_vendor = "apple"))]
    published_file
        .sync_all()
        .map_err(|error| file_error("sync published snapshot", destination, error))?;
    destination_directory.file.sync_all().map_err(|error| {
        file_error(
            "sync pinned publication directory",
            &destination_directory.path,
            error,
        )
    })
}

#[cfg(windows)]
fn publish_windows_snapshot(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::hard_link(source, destination)
}

#[cfg(test)]
fn take_publication_failpoint(
    failpoint: &Mutex<std::collections::HashSet<PathBuf>>,
    destination: &Path,
) -> bool {
    failpoint
        .lock()
        .expect("publication failpoint lock poisoned")
        .remove(destination)
}

fn cleanup_failed_publication(
    _source: &Path,
    destination: &Path,
    reservations: SidecarReservations,
    primary: StateError,
    destination_owned: bool,
) -> StateError {
    let reservation_cleanup = reservations.release();
    if destination_owned {
        return StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: format!(
                "{primary}; snapshot publication succeeded; reservation cleanup: {}",
                result_diagnostic(reservation_cleanup)
            ),
        };
    }
    match path_entry_exists(destination) {
        Ok(true) => {
            if reservation_cleanup.is_ok() {
                StateError::BackupDestinationExists {
                    path: destination.to_owned(),
                }
            } else {
                StateError::PublicationUncertain {
                    path: destination.to_owned(),
                    reason: format!(
                        "{primary}; destination belongs to another publisher; reservation cleanup: {}",
                        result_diagnostic(reservation_cleanup)
                    ),
                }
            }
        }
        Ok(false) if reservation_cleanup.is_ok() => primary,
        Ok(false) => StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: format!(
                "{primary}; reservation cleanup: {}",
                result_diagnostic(reservation_cleanup)
            ),
        },
        Err(error) => StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: format!(
                "{primary}; destination inspection failed: {error}; reservation cleanup: {}",
                result_diagnostic(reservation_cleanup)
            ),
        },
    }
}

fn publication_uncertain_after_release(destination: &Path, primary: StateError) -> StateError {
    let wal_exists = path_entry_exists(&sqlite_sidecar(destination, "-wal"));
    let shm_exists = path_entry_exists(&sqlite_sidecar(destination, "-shm"));
    let journal_exists = path_entry_exists(&sqlite_sidecar(destination, "-journal"));
    StateError::PublicationUncertain {
        path: destination.to_owned(),
        reason: format!(
            "snapshot was published but reservation cleanup failed: {primary}; WAL remains: {}; SHM remains: {}; journal remains: {}",
            bool_result_diagnostic(wal_exists),
            bool_result_diagnostic(shm_exists),
            bool_result_diagnostic(journal_exists)
        ),
    }
}

#[cfg(unix)]
fn files_share_identity_from_handles_portable(
    left: &File,
    right: &File,
) -> Result<bool, StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let left = left
        .metadata()
        .map_err(|error| file_error("inspect first pinned file identity", Path::new("."), error))?;
    let right = right.metadata().map_err(|error| {
        file_error("inspect second pinned file identity", Path::new("."), error)
    })?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(windows)]
fn files_share_identity_from_handles_portable(
    left: &File,
    right: &File,
) -> Result<bool, StateError> {
    let left = left
        .try_clone()
        .and_then(same_file::Handle::from_file)
        .map_err(|error| file_error("capture first pinned file identity", Path::new("."), error))?;
    let right = right
        .try_clone()
        .and_then(same_file::Handle::from_file)
        .map_err(|error| {
            file_error("capture second pinned file identity", Path::new("."), error)
        })?;
    Ok(left == right)
}

#[cfg(all(not(unix), not(windows)))]
fn files_share_identity_from_handles_portable(
    _left: &File,
    _right: &File,
) -> Result<bool, StateError> {
    Ok(false)
}

#[cfg(unix)]
fn files_share_identity(left: &Path, right: &Path) -> Result<bool, StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let left_metadata = std::fs::metadata(left)
        .map_err(|error| file_error("inspect publication source", left, error))?;
    let right_metadata = std::fs::metadata(right)
        .map_err(|error| file_error("inspect publication destination", right, error))?;
    Ok(left_metadata.dev() == right_metadata.dev() && left_metadata.ino() == right_metadata.ino())
}

#[cfg(windows)]
fn files_share_identity(left: &Path, right: &Path) -> Result<bool, StateError> {
    same_file::is_same_file(left, right)
        .map_err(|error| file_error("compare publication file identities", right, error))
}

#[cfg(all(not(unix), not(windows)))]
fn files_share_identity(_left: &Path, _right: &Path) -> Result<bool, StateError> {
    Ok(false)
}

fn bool_result_diagnostic(result: Result<bool, StateError>) -> String {
    match result {
        Ok(value) => value.to_string(),
        Err(error) => error.to_string(),
    }
}

fn result_diagnostic(result: Result<(), StateError>) -> String {
    match result {
        Ok(()) => "ok".to_owned(),
        Err(error) => error.to_string(),
    }
}

fn remove_snapshot_artifacts(database: &Path) -> Result<(), StateError> {
    for artifact in database_artifacts(database) {
        match std::fs::remove_file(&artifact) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(file_error(
                    "remove restore temporary file",
                    &artifact,
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn sqlite_sidecar(database: &Path, suffix: &str) -> PathBuf {
    let mut path = database.as_os_str().to_owned();
    path.push(suffix);
    PathBuf::from(path)
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn sync_parent_directory(path: &Path) -> Result<(), StateError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| file_error("sync restore directory", parent, error))
}

#[cfg(target_vendor = "apple")]
fn sync_parent_directory(path: &Path) -> Result<(), StateError> {
    if path_entry_exists(path)? {
        let file = File::open(path)
            .map_err(|error| file_error("open file for Apple full sync", path, error))?;
        rustix::fs::fcntl_fullfsync(&file)
            .map_err(|error| file_error("full sync file on Apple", path, error.into()))?;
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = File::open(parent)
        .map_err(|error| file_error("open directory for Apple full sync", parent, error))?;
    directory
        .sync_all()
        .map_err(|error| file_error("sync directory metadata on Apple", parent, error))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), StateError> {
    Ok(())
}

#[cfg(not(unix))]
fn lock_path_for(database: &Path) -> PathBuf {
    writer_lock_collision_path(database)
}

fn writer_lock_collision_path(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_owned();
    path.push(".writer.lock");
    PathBuf::from(path)
}

#[cfg(unix)]
fn acquire_creation_lock(path: &Path) -> Result<Option<File>, StateError> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.len() == 0 => {}
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(file_error("inspect database creation path", path, error)),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata = std::fs::metadata(parent)
        .map_err(|error| file_error("inspect database creation directory", parent, error))?;
    let file_name = path.file_name().ok_or_else(|| StateError::InvalidPath {
        path: path.to_owned(),
        reason: "database path must include a file name",
    })?;
    let encoded_name = hex_encode(file_name.as_bytes());
    let contents = format!(
        "v1\n{}\n{}\n{encoded_name}",
        parent_metadata.dev(),
        parent_metadata.ino()
    );
    let lock_path =
        private_lock_root_for(path)?.join(format!("create-{}.lock", migration_checksum(&contents)));
    let mut lock_file = open_private_lock_file(&lock_path, PrivateLockOpen::Create)?;
    match lock_file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(StateError::StoreLocked { path: lock_path });
        }
        Err(std::fs::TryLockError::Error(error)) => {
            return Err(file_error(
                "acquire database creation lock",
                &lock_path,
                error,
            ));
        }
    }
    initialize_or_validate_lock_contents(&lock_path, &mut lock_file, &contents, true)?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.len() == 0 => {
            Ok(Some(lock_file))
        }
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Some(lock_file)),
        Err(error) => Err(file_error("revalidate database creation path", path, error)),
    }
}

#[cfg(not(unix))]
fn acquire_creation_lock(_path: &Path) -> Result<Option<File>, StateError> {
    Ok(None)
}

#[cfg(all(unix, not(test)))]
fn default_private_lock_root() -> Result<PathBuf, StateError> {
    use std::os::unix::fs::DirBuilderExt as _;
    use uzers::os::unix::UserExt as _;

    let uid = uzers::get_effective_uid();
    let account = uzers::get_user_by_uid(uid).ok_or_else(|| StateError::InvalidPath {
        path: PathBuf::new(),
        reason: "OS account home is required for the private writer-lock namespace",
    })?;
    let account_home = account.home_dir();
    let home = std::fs::canonicalize(account_home).map_err(|error| {
        file_error(
            "canonicalize OS account home for private locks",
            account_home,
            error,
        )
    })?;
    let state = home.join(".gta-claw");
    let locks = state.join("locks");
    for directory in [&state, &locks] {
        match std::fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(file_error(
                    "create private writer-lock directory",
                    directory,
                    error,
                ));
            }
        }
        validate_private_lock_directory(directory)?;
    }
    Ok(locks)
}

#[cfg(all(unix, not(test)))]
fn private_lock_root_for(_path: &Path) -> Result<PathBuf, StateError> {
    default_private_lock_root()
}

#[cfg(all(unix, test))]
fn private_lock_root_for(path: &Path) -> Result<PathBuf, StateError> {
    use std::os::unix::fs::DirBuilderExt as _;

    if let Some(root) = path.ancestors().skip(1).find(|ancestor| {
        ancestor.file_name().and_then(|name| name.to_str()) == Some(".gta-claw-test-locks")
    }) {
        validate_private_lock_directory(root)?;
        return Ok(root.to_owned());
    }
    let parent = path.parent().ok_or_else(|| StateError::InvalidPath {
        path: path.to_owned(),
        reason: "test state path must have a private parent",
    })?;
    let fixture_root = path
        .ancestors()
        .skip(1)
        .find(|ancestor| {
            ancestor
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".tmp"))
        })
        .unwrap_or(parent);
    let root = fixture_root.join(".gta-claw-test-locks");
    match std::fs::DirBuilder::new().mode(0o700).create(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(file_error("create isolated test lock root", &root, error));
        }
    }
    validate_private_lock_directory(&root)?;
    Ok(root)
}

#[cfg(unix)]
fn validate_private_lock_directory(path: &Path) -> Result<(), StateError> {
    let file = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| file_error("open private writer-lock directory", path, error.into()))?;
    if !claw_sqlite_file_control::unix_file_is_service_private(
        &file,
        rustix::process::geteuid().as_raw(),
        0o700,
    )
    .map_err(|_| StateError::InvalidPath {
        path: path.to_owned(),
        reason: "writer-lock directory ACL could not be validated",
    })? {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "writer-lock directory must be owned, private, and non-symlink",
        });
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum PrivateLockOpen {
    Existing,
    Create,
    CreateNew,
}

#[cfg(unix)]
fn open_private_lock_file(path: &Path, open: PrivateLockOpen) -> Result<File, StateError> {
    let parent = path.parent().ok_or_else(|| StateError::InvalidPath {
        path: path.to_owned(),
        reason: "writer lock must have a private parent directory",
    })?;
    validate_private_lock_directory(parent)?;
    let base_flags =
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    let open_file = |flags| {
        rustix::fs::open(path, flags, rustix::fs::Mode::from_bits_retain(0o600)).map(File::from)
    };
    let (file, newly_created) = match open {
        PrivateLockOpen::Existing => (open_file(base_flags), false),
        PrivateLockOpen::CreateNew => (
            open_file(base_flags | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL),
            true,
        ),
        PrivateLockOpen::Create => {
            match open_file(base_flags | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL) {
                Ok(file) => (Ok(file), true),
                Err(rustix::io::Errno::EXIST) => (open_file(base_flags), false),
                Err(error) => (Err(error), false),
            }
        }
    };
    let file = file.map_err(|error| file_error("open private writer lock", path, error.into()))?;
    if newly_created {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| file_error("secure private writer lock", path, error))?;
    }
    validate_unix_lock_file(path, &file)?;
    Ok(file)
}

#[cfg(unix)]
fn initialize_or_validate_lock_contents(
    path: &Path,
    file: &mut File,
    expected: &str,
    initialize_empty: bool,
) -> Result<(), StateError> {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

    let length = file
        .metadata()
        .map_err(|error| file_error("inspect writer-lock contents", path, error))?
        .len();
    if length > 4096 {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "writer-lock identity contents are too large",
        });
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| file_error("seek writer-lock contents", path, error))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|error| file_error("read writer-lock contents", path, error))?;
    if contents.is_empty() && initialize_empty {
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(expected.as_bytes()))
            .and_then(|_| file.sync_all())
            .map_err(|error| file_error("initialize writer-lock identity", path, error))?;
        return Ok(());
    }
    if contents != expected {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "writer-lock contents do not match the database identity",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn read_lock_contents(path: &Path, file: &mut File) -> Result<String, StateError> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    file.seek(SeekFrom::Start(0))
        .map_err(|error| file_error("seek writer-lock contents", path, error))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|error| file_error("read writer-lock contents", path, error))?;
    Ok(contents)
}

#[cfg(unix)]
fn replace_lock_contents(path: &Path, file: &mut File, contents: &str) -> Result<(), StateError> {
    use std::io::{Seek as _, SeekFrom, Write as _};

    file.set_len(0)
        .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|()| file.write_all(contents.as_bytes()))
        .and_then(|()| file.sync_all())
        .map_err(|error| file_error("upgrade writer-lock identity", path, error))
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(windows)]
fn writer_identity_path_for(database: &Path) -> PathBuf {
    // An NTFS alternate stream follows the file identity across hard-link names.
    let mut path = database.as_os_str().to_owned();
    path.push(":gta-claw-writer-identity");
    PathBuf::from(path)
}

#[cfg(windows)]
fn acquire_writer_lock(path: &Path) -> Result<File, StateError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, WRITE_DAC, WRITE_OWNER};

    let exists = path_entry_exists(path)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .truncate(false)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    if exists {
        options.create(false);
    } else {
        options
            .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)
            .create_new(true);
    }
    let file = options.open(path).map_err(|error| {
        if matches!(error.raw_os_error(), Some(32) | Some(33)) {
            StateError::StoreLocked {
                path: path.to_owned(),
            }
        } else {
            file_error("open writer lock", path, error)
        }
    })?;
    if !exists {
        claw_sqlite_file_control::secure_new_windows_file(&file).map_err(|_| {
            StateError::InvalidPath {
                path: path.to_owned(),
                reason: "new writer lock security descriptor could not be applied",
            }
        })?;
    }
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(StateError::StoreLocked {
            path: path.to_owned(),
        }),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(file_error("acquire writer lock", path, error))
        }
    }
}

#[cfg(all(not(unix), not(windows)))]
fn acquire_writer_lock(path: &Path) -> Result<File, StateError> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|error| file_error("open writer lock", path, error))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(StateError::StoreLocked {
            path: path.to_owned(),
        }),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(file_error("acquire writer lock", path, error))
        }
    }
}

#[cfg(unix)]
fn acquire_store_lock(
    path: &Path,
    database_file: &File,
    allow_identity_initialization: bool,
) -> Result<(PathBuf, File, ProcessIdentityGuard), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = database_file
        .metadata()
        .map_err(|error| file_error("inspect database lock identity", path, error))?;
    let identity = (metadata.dev(), metadata.ino());
    if !PROCESS_IDENTITIES
        .lock()
        .expect("process identity registry lock poisoned")
        .insert(identity)
    {
        return Err(StateError::StoreLocked {
            path: path.to_owned(),
        });
    }
    let guard = ProcessIdentityGuard {
        identity: Some(identity),
    };
    let (lock_path, lock_file) =
        acquire_unix_identity_lock(path, database_file, identity, allow_identity_initialization)?;
    Ok((lock_path, lock_file, guard))
}

#[cfg(windows)]
fn acquire_store_lock(
    path: &Path,
    database_file: &File,
    _allow_identity_initialization: bool,
) -> Result<(PathBuf, File, ProcessIdentityGuard), StateError> {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

    let lock_path = lock_path_for(path);
    let mut lock_file = acquire_writer_lock(&lock_path)?;
    validate_private_database_file(&lock_path, &lock_file)?;
    let database_identity = claw_sqlite_file_control::windows_file_identity(database_file)
        .map_err(|_| StateError::InvalidPath {
            path: path.to_owned(),
            reason: "stable Windows database identity is unavailable",
        })?;
    let lock_identity =
        claw_sqlite_file_control::windows_file_identity(&lock_file).map_err(|_| {
            StateError::InvalidPath {
                path: lock_path.clone(),
                reason: "stable Windows lock identity is unavailable",
            }
        })?;
    let mut contents = String::new();
    lock_file
        .seek(SeekFrom::Start(0))
        .and_then(|_| lock_file.read_to_string(&mut contents))
        .map_err(|error| file_error("read Windows writer-lock header", &lock_path, error))?;
    let header_prefix = format!(
        "v2\n{}\n{}\n",
        hex_encode(&database_identity),
        hex_encode(&lock_identity)
    );
    if contents.is_empty() {
        contents = format!("{header_prefix}{}", writer_owner()?);
        lock_file
            .seek(SeekFrom::Start(0))
            .and_then(|_| lock_file.write_all(contents.as_bytes()))
            .and_then(|_| lock_file.sync_all())
            .map_err(|error| {
                file_error("initialize Windows writer-lock header", &lock_path, error)
            })?;
    } else if !contents.starts_with(&header_prefix)
        || contents[header_prefix.len()..].is_empty()
        || contents[header_prefix.len()..].contains('\n')
    {
        return Err(StateError::InvalidPath {
            path: lock_path,
            reason: "Windows writer-lock header does not match held file identities",
        });
    }
    Ok((lock_path, lock_file, ProcessIdentityGuard {}))
}

#[cfg(all(not(unix), not(windows)))]
fn acquire_store_lock(
    path: &Path,
    _database_file: &File,
    _allow_identity_initialization: bool,
) -> Result<(PathBuf, File, ProcessIdentityGuard), StateError> {
    let lock_path = lock_path_for(path);
    acquire_writer_lock(&lock_path).map(|file| (lock_path, file, ProcessIdentityGuard {}))
}

#[cfg(unix)]
fn acquire_unix_identity_lock(
    path: &Path,
    database_file: &File,
    identity: (u64, u64),
    allow_identity_initialization: bool,
) -> Result<(PathBuf, File), StateError> {
    use std::os::unix::fs::MetadataExt as _;
    use xattr::FileExt as _;

    if let Some(value) = database_file
        .get_xattr(UNIX_LOCK_IDENTITY_XATTR)
        .map_err(|error| file_error("read database lock identity", path, error))?
    {
        let parsed = parse_unix_lock_identity(path, &value, identity)?;
        let legacy_identity = parsed.lock_identity.is_none();
        let lock_path = parsed.path;
        let mut lock_file = open_private_lock_file(&lock_path, PrivateLockOpen::Existing)?;
        validate_persisted_lock_file_identity(path, &lock_file, parsed.lock_identity)?;
        acquire_private_lock(&lock_path, &lock_file)?;
        let contents = std::str::from_utf8(&value).map_err(|_| StateError::InvalidPath {
            path: path.to_owned(),
            reason: "database lock identity is not valid UTF-8",
        })?;
        let lock_contents = read_lock_contents(&lock_path, &mut lock_file)?;
        if lock_contents != contents {
            let lock_value = parse_unix_lock_identity(path, lock_contents.as_bytes(), identity)?;
            if parsed.lock_identity.is_some()
                && lock_value.lock_identity.is_none()
                && lock_value.path == lock_path
            {
                replace_lock_contents(&lock_path, &mut lock_file, contents)?;
            } else {
                return Err(StateError::InvalidPath {
                    path: lock_path,
                    reason: "writer-lock contents do not match the database identity",
                });
            }
        }
        if legacy_identity {
            let lock_metadata = lock_file.metadata().map_err(|error| {
                file_error("capture legacy writer-lock identity", &lock_path, error)
            })?;
            let file_name = lock_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| StateError::InvalidPath {
                    path: lock_path.clone(),
                    reason: "legacy writer-lock file name is invalid",
                })?;
            let prefix = format!("dev-{}-ino-{}-", identity.0, identity.1);
            let generation = file_name
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix(".lock"))
                .filter(|generation| !generation.is_empty())
                .ok_or_else(|| StateError::InvalidPath {
                    path: lock_path.clone(),
                    reason: "legacy writer-lock generation is invalid",
                })?;
            let lock_path_text = lock_path.to_str().ok_or_else(|| StateError::InvalidPath {
                path: lock_path.clone(),
                reason: "legacy writer-lock path is not valid Unicode",
            })?;
            let upgraded = format!(
                "v2\n{}\n{}\n{}\n{}\n{generation}\n{lock_path_text}",
                identity.0,
                identity.1,
                lock_metadata.dev(),
                lock_metadata.ino()
            );
            rustix::fs::fsetxattr(
                database_file,
                UNIX_LOCK_IDENTITY_XATTR,
                upgraded.as_bytes(),
                rustix::fs::XattrFlags::REPLACE,
            )
            .map_err(|error| file_error("upgrade database lock identity", path, error.into()))?;
            database_file
                .sync_all()
                .map_err(|error| file_error("sync upgraded database lock identity", path, error))?;
            replace_lock_contents(&lock_path, &mut lock_file, &upgraded)?;
        }
        return Ok((lock_path, lock_file));
    }
    if !allow_identity_initialization {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "existing database is missing its persistent lock identity",
        });
    }

    let token = writer_owner()?;
    let lock_path = private_lock_root_for(path)?.join(format!(
        "dev-{}-ino-{}-{token}.lock",
        identity.0, identity.1
    ));
    let lock_path_text = lock_path.to_str().ok_or_else(|| StateError::InvalidPath {
        path: lock_path.clone(),
        reason: "database lock identity must be valid Unicode",
    })?;
    let lock_temporary = lock_path.with_file_name(format!(".lock-publish-{}", writer_owner()?));
    let mut lock_file = open_private_lock_file(&lock_temporary, PrivateLockOpen::CreateNew)?;
    acquire_private_lock(&lock_temporary, &lock_file)?;
    let lock_metadata = lock_file
        .metadata()
        .map_err(|error| file_error("capture new writer-lock identity", &lock_temporary, error))?;
    let encoded = format!(
        "v2\n{}\n{}\n{}\n{}\n{token}\n{lock_path_text}",
        identity.0,
        identity.1,
        lock_metadata.dev(),
        lock_metadata.ino()
    );
    initialize_or_validate_lock_contents(&lock_temporary, &mut lock_file, &encoded, true)?;
    if let Err(error) = rustix::fs::renameat_with(
        rustix::fs::CWD,
        &lock_temporary,
        rustix::fs::CWD,
        &lock_path,
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        let mut primary = file_error(
            "publish persistent writer-lock inode",
            &lock_path,
            error.into(),
        );
        let temporary_owned = match verify_path_identity(&lock_temporary, &lock_file) {
            Ok(()) => true,
            Err(cleanup) => {
                primary = append_operation_cleanup(
                    "writer lock publication",
                    primary,
                    format!(
                        "temporary lock identity cleanup check failed; removal skipped: {cleanup}"
                    ),
                );
                false
            }
        };
        if let Err(unlock) = File::unlock(&lock_file) {
            primary = append_operation_cleanup(
                "writer lock publication",
                primary,
                format!(
                    "temporary lock unlock failed: {}",
                    file_error("release temporary writer lock", &lock_temporary, unlock)
                ),
            );
        }
        drop(lock_file);
        if temporary_owned && let Err(cleanup) = std::fs::remove_file(&lock_temporary) {
            primary = append_operation_cleanup(
                "writer lock publication",
                primary,
                format!(
                    "temporary lock removal failed: {}",
                    file_error("remove temporary writer lock", &lock_temporary, cleanup)
                ),
            );
        }
        if let Err(cleanup) = sync_parent_directory(&lock_temporary) {
            primary = append_operation_cleanup(
                "writer lock publication",
                primary,
                format!("temporary lock parent sync failed: {cleanup}"),
            );
        }
        return Err(primary);
    }
    verify_path_identity(&lock_path, &lock_file)?;
    sync_parent_directory(&lock_path)?;
    match rustix::fs::fsetxattr(
        database_file,
        UNIX_LOCK_IDENTITY_XATTR,
        encoded.as_bytes(),
        rustix::fs::XattrFlags::CREATE,
    ) {
        Ok(()) => {
            let persisted = database_file
                .get_xattr(UNIX_LOCK_IDENTITY_XATTR)
                .map_err(|error| file_error("verify database lock identity", path, error))?
                .ok_or_else(|| StateError::InvalidPath {
                    path: path.to_owned(),
                    reason: "database lock identity disappeared after publication",
                })?;
            if persisted != encoded.as_bytes() {
                return Err(StateError::InvalidPath {
                    path: path.to_owned(),
                    reason: "database lock identity changed after publication",
                });
            }
            database_file
                .sync_all()
                .map_err(|error| file_error("sync database lock identity", path, error))?;
            Ok((lock_path, lock_file))
        }
        Err(rustix::io::Errno::EXIST) => {
            verify_path_identity(&lock_path, &lock_file)?;
            File::unlock(&lock_file).map_err(|error| {
                file_error("release unpublished writer lock", &lock_path, error)
            })?;
            drop(lock_file);
            std::fs::remove_file(&lock_path).map_err(|error| {
                file_error("remove unreferenced writer lock", &lock_path, error)
            })?;
            sync_parent_directory(&lock_path)?;
            let winner = database_file
                .get_xattr(UNIX_LOCK_IDENTITY_XATTR)
                .map_err(|error| file_error("read winning database lock identity", path, error))?
                .ok_or_else(|| StateError::InvalidPath {
                    path: path.to_owned(),
                    reason: "database lock identity disappeared during initialization",
                })?;
            let parsed = parse_unix_lock_identity(path, &winner, identity)?;
            let winner_path = parsed.path;
            let mut winner_file = open_private_lock_file(&winner_path, PrivateLockOpen::Existing)?;
            validate_persisted_lock_file_identity(path, &winner_file, parsed.lock_identity)?;
            acquire_private_lock(&winner_path, &winner_file)?;
            let winner_contents =
                std::str::from_utf8(&winner).map_err(|_| StateError::InvalidPath {
                    path: path.to_owned(),
                    reason: "winning database lock identity is not valid UTF-8",
                })?;
            initialize_or_validate_lock_contents(
                &winner_path,
                &mut winner_file,
                winner_contents,
                false,
            )?;
            Ok((winner_path, winner_file))
        }
        Err(error) => {
            let mut primary = file_error("persist database lock identity", path, error.into());
            let lock_owned = match verify_path_identity(&lock_path, &lock_file) {
                Ok(()) => true,
                Err(cleanup) => {
                    primary = append_operation_cleanup(
                        "writer lock identity",
                        primary,
                        format!(
                            "unpublished lock identity cleanup check failed; removal skipped: {cleanup}"
                        ),
                    );
                    false
                }
            };
            if let Err(unlock) = File::unlock(&lock_file) {
                primary = append_operation_cleanup(
                    "writer lock identity",
                    primary,
                    format!(
                        "unpublished lock unlock failed: {}",
                        file_error("release unpublished writer lock", &lock_path, unlock)
                    ),
                );
            }
            drop(lock_file);
            if lock_owned && let Err(cleanup) = std::fs::remove_file(&lock_path) {
                primary = append_operation_cleanup(
                    "writer lock identity",
                    primary,
                    format!(
                        "unreferenced lock removal failed: {}",
                        file_error("remove unreferenced writer lock", &lock_path, cleanup)
                    ),
                );
            }
            if let Err(cleanup) = sync_parent_directory(&lock_path) {
                primary = append_operation_cleanup(
                    "writer lock identity",
                    primary,
                    format!("unreferenced lock parent sync failed: {cleanup}"),
                );
            }
            Err(primary)
        }
    }
}

#[cfg(unix)]
fn acquire_private_lock(path: &Path, file: &File) -> Result<(), StateError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => Err(StateError::StoreLocked {
            path: path.to_owned(),
        }),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(file_error("acquire private writer lock", path, error))
        }
    }
}

#[cfg(unix)]
struct ParsedUnixLockIdentity {
    path: PathBuf,
    lock_identity: Option<(u64, u64)>,
}

#[cfg(unix)]
fn parse_unix_lock_identity(
    database_path: &Path,
    value: &[u8],
    expected_identity: (u64, u64),
) -> Result<ParsedUnixLockIdentity, StateError> {
    let stored = std::str::from_utf8(value).map_err(|_| StateError::InvalidPath {
        path: database_path.to_owned(),
        reason: "database lock identity is not valid UTF-8",
    })?;
    let mut parts = stored.split('\n');
    let version = parts.next();
    let device = parts.next().and_then(|value| value.parse::<u64>().ok());
    let inode = parts.next().and_then(|value| value.parse::<u64>().ok());
    let (lock_identity, generation, stored_path) = match version {
        Some("v1") => (None, None, parts.next()),
        Some("v2") => {
            let lock_device = parts.next().and_then(|value| value.parse::<u64>().ok());
            let lock_inode = parts.next().and_then(|value| value.parse::<u64>().ok());
            let generation = parts.next();
            (lock_device.zip(lock_inode), generation, parts.next())
        }
        _ => {
            return Err(StateError::InvalidPath {
                path: database_path.to_owned(),
                reason: "database lock identity version is unsupported",
            });
        }
    };
    let (Some(device), Some(inode), Some(stored_path)) = (device, inode, stored_path) else {
        return Err(StateError::InvalidPath {
            path: database_path.to_owned(),
            reason: "database lock identity has an unsupported format",
        });
    };
    if parts.next().is_some() {
        return Err(StateError::InvalidPath {
            path: database_path.to_owned(),
            reason: "database lock identity has trailing fields",
        });
    }
    if (device, inode) != expected_identity {
        return Err(StateError::InvalidPath {
            path: database_path.to_owned(),
            reason: "database lock identity belongs to a different filesystem object",
        });
    }
    let lock_path = PathBuf::from(stored_path);
    if !lock_path.is_absolute() {
        return Err(StateError::InvalidPath {
            path: lock_path,
            reason: "database lock identity must be absolute",
        });
    }
    let parent = lock_path.parent().ok_or_else(|| StateError::InvalidPath {
        path: lock_path.clone(),
        reason: "database lock identity must have a private parent",
    })?;
    validate_private_lock_directory(parent)?;
    if parent != private_lock_root_for(database_path)? {
        return Err(StateError::InvalidPath {
            path: lock_path,
            reason: "database lock identity is outside the canonical private lock root",
        });
    }
    let expected_prefix = format!("dev-{device}-ino-{inode}-");
    let file_name = lock_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| StateError::InvalidPath {
            path: lock_path.clone(),
            reason: "database lock identity file name is invalid",
        })?;
    if !file_name.starts_with(&expected_prefix) || !file_name.ends_with(".lock") {
        return Err(StateError::InvalidPath {
            path: lock_path,
            reason: "database lock identity key does not match its filesystem identity",
        });
    }
    if let Some(generation) = generation
        && (generation.is_empty() || !file_name.ends_with(&format!("-{generation}.lock")))
    {
        return Err(StateError::InvalidPath {
            path: lock_path,
            reason: "database lock generation does not match its canonical path",
        });
    }
    Ok(ParsedUnixLockIdentity {
        path: lock_path,
        lock_identity,
    })
}

#[cfg(unix)]
fn validate_persisted_lock_file_identity(
    database_path: &Path,
    lock_file: &File,
    expected: Option<(u64, u64)>,
) -> Result<(), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let Some(expected) = expected else {
        return Ok(());
    };
    let metadata = lock_file
        .metadata()
        .map_err(|error| file_error("verify writer-lock inode identity", database_path, error))?;
    if (metadata.dev(), metadata.ino()) != expected {
        return Err(StateError::InvalidPath {
            path: database_path.to_owned(),
            reason: "persistent writer-lock inode was replaced",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn capture_store_lock_identity(
    database_path: &Path,
    database_file: &File,
    lock_path: &Path,
    lock_file: &File,
) -> Result<Option<Vec<u8>>, StateError> {
    use std::os::unix::fs::MetadataExt as _;
    use xattr::FileExt as _;

    let metadata = database_file
        .metadata()
        .map_err(|error| file_error("capture database lock identity", database_path, error))?;
    let value = database_file
        .get_xattr(UNIX_LOCK_IDENTITY_XATTR)
        .map_err(|error| file_error("capture persisted lock identity", database_path, error))?
        .ok_or_else(|| StateError::InvalidPath {
            path: database_path.to_owned(),
            reason: "database lock identity is missing after lock acquisition",
        })?;
    let parsed = parse_unix_lock_identity(database_path, &value, (metadata.dev(), metadata.ino()))?;
    if parsed.path != lock_path {
        return Err(StateError::InvalidPath {
            path: database_path.to_owned(),
            reason: "database lock identity does not name the held lock",
        });
    }
    validate_persisted_lock_file_identity(database_path, lock_file, parsed.lock_identity)?;
    Ok(Some(value))
}

#[cfg(windows)]
fn capture_store_lock_identity(
    database_path: &Path,
    database_file: &File,
    lock_path: &Path,
    lock_file: &File,
) -> Result<Option<Vec<u8>>, StateError> {
    verify_windows_lock_binding(database_path, database_file, lock_path, lock_file, None).map(Some)
}

#[cfg(all(not(unix), not(windows)))]
fn capture_store_lock_identity(
    _database_path: &Path,
    _database_file: &File,
    _lock_path: &Path,
    _lock_file: &File,
) -> Result<Option<Vec<u8>>, StateError> {
    Ok(None)
}

#[cfg(unix)]
fn verify_store_lock_binding(
    database_path: &Path,
    database_file: &File,
    lock_path: &Path,
    lock_file: &File,
    expected: Option<&[u8]>,
) -> Result<(), StateError> {
    use std::os::unix::fs::MetadataExt as _;
    use xattr::FileExt as _;

    let expected = expected.ok_or_else(|| StateError::InvalidPath {
        path: database_path.to_owned(),
        reason: "held database lock identity is missing",
    })?;
    let current = database_file
        .get_xattr(UNIX_LOCK_IDENTITY_XATTR)
        .map_err(|error| file_error("verify persisted lock identity", database_path, error))?
        .ok_or_else(|| StateError::InvalidPath {
            path: database_path.to_owned(),
            reason: "database lock identity was removed while open",
        })?;
    if current != expected {
        return Err(StateError::InvalidPath {
            path: database_path.to_owned(),
            reason: "database lock identity changed while open",
        });
    }
    let metadata = database_file
        .metadata()
        .map_err(|error| file_error("verify database lock identity", database_path, error))?;
    let parsed =
        parse_unix_lock_identity(database_path, &current, (metadata.dev(), metadata.ino()))?;
    if parsed.path != lock_path {
        return Err(StateError::InvalidPath {
            path: database_path.to_owned(),
            reason: "database lock identity no longer names the held lock",
        });
    }
    validate_persisted_lock_file_identity(database_path, lock_file, parsed.lock_identity)?;
    Ok(())
}

#[cfg(unix)]
async fn verify_sqlite_connection_identity(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    let moved = claw_sqlite_file_control::main_database_has_moved(connection)
        .await
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    if moved {
        Err(sqlx::Error::Protocol(
            "SQLite main database identity changed after open".to_owned(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
async fn install_sqlite_commit_guard(connection: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    claw_sqlite_file_control::install_moved_commit_guard(connection)
        .await
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))
}

#[cfg(unix)]
async fn install_store_commit_guard(
    connection: &mut SqliteConnection,
    database_parent: (&Path, &File),
    database: (&Path, &File),
    lock: (&Path, &File),
    expected_identity: Option<&[u8]>,
    writer_generation: (Arc<AtomicU64>, u64),
) -> Result<(), sqlx::Error> {
    let expected_identity = expected_identity
        .ok_or_else(|| sqlx::Error::Protocol("commit identity generation is missing".to_owned()))?;
    claw_sqlite_file_control::install_identity_commit_guard(
        connection,
        database_parent,
        database,
        lock,
        expected_identity,
        writer_generation,
    )
    .await
    .map_err(|error| sqlx::Error::Protocol(error.to_string()))
}

#[cfg(windows)]
async fn install_store_commit_guard(
    connection: &mut SqliteConnection,
    database_parent: (&Path, &File),
    database: (&Path, &File),
    lock: (&Path, &File),
    expected_identity: Option<&[u8]>,
    writer_generation: (Arc<AtomicU64>, u64),
) -> Result<(), sqlx::Error> {
    let expected_identity = expected_identity.ok_or_else(|| {
        sqlx::Error::Protocol("Windows commit identity generation is missing".to_owned())
    })?;
    claw_sqlite_file_control::install_windows_identity_commit_guard(
        connection,
        database_parent,
        database,
        lock,
        expected_identity,
        writer_generation,
    )
    .await
    .map_err(|error| sqlx::Error::Protocol(error.to_string()))
}

#[cfg(all(not(unix), not(windows)))]
async fn install_store_commit_guard(
    _connection: &mut SqliteConnection,
    _database_parent: (&Path, &File),
    _database: (&Path, &File),
    _lock: (&Path, &File),
    _expected_identity: Option<&[u8]>,
    _writer_generation: (Arc<AtomicU64>, u64),
) -> Result<(), sqlx::Error> {
    Err(sqlx::Error::Protocol(
        "commit identity guards are unsupported on this platform".to_owned(),
    ))
}

#[cfg(not(unix))]
async fn install_sqlite_commit_guard(
    _connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    Ok(())
}

#[cfg(not(unix))]
async fn verify_sqlite_connection_identity(
    _connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    Ok(())
}

#[cfg(windows)]
fn verify_store_lock_binding(
    database_path: &Path,
    database_file: &File,
    lock_path: &Path,
    lock_file: &File,
    expected: Option<&[u8]>,
) -> Result<(), StateError> {
    let current =
        verify_windows_lock_binding(database_path, database_file, lock_path, lock_file, expected)?;
    if let Some(expected) = expected
        && current != expected
    {
        return Err(StateError::InvalidPath {
            path: lock_path.to_owned(),
            reason: "Windows writer-lock generation changed while open",
        });
    }
    Ok(())
}

#[cfg(windows)]
fn verify_windows_lock_binding(
    database_path: &Path,
    database_file: &File,
    lock_path: &Path,
    lock_file: &File,
    expected: Option<&[u8]>,
) -> Result<Vec<u8>, StateError> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    verify_path_identity(database_path, database_file)?;
    verify_path_identity(lock_path, lock_file)?;
    validate_private_database_file(lock_path, lock_file)?;
    let database_identity = claw_sqlite_file_control::windows_file_identity(database_file)
        .map_err(|_| StateError::InvalidPath {
            path: database_path.to_owned(),
            reason: "stable Windows database identity is unavailable",
        })?;
    let lock_identity =
        claw_sqlite_file_control::windows_file_identity(lock_file).map_err(|_| {
            StateError::InvalidPath {
                path: lock_path.to_owned(),
                reason: "stable Windows lock identity is unavailable",
            }
        })?;
    let mut file = lock_file
        .try_clone()
        .map_err(|error| file_error("clone Windows writer lock", lock_path, error))?;
    let mut contents = Vec::new();
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_to_end(&mut contents))
        .map_err(|error| file_error("read Windows writer-lock header", lock_path, error))?;
    let prefix = format!(
        "v2\n{}\n{}\n",
        hex_encode(&database_identity),
        hex_encode(&lock_identity)
    );
    if !contents.starts_with(prefix.as_bytes())
        || contents[prefix.len()..].is_empty()
        || contents[prefix.len()..].contains(&b'\n')
    {
        return Err(StateError::InvalidPath {
            path: lock_path.to_owned(),
            reason: "Windows writer-lock header does not match held file identities",
        });
    }
    if let Some(expected) = expected
        && contents != expected
    {
        return Err(StateError::InvalidPath {
            path: lock_path.to_owned(),
            reason: "Windows writer-lock generation changed while open",
        });
    }
    Ok(contents)
}

#[cfg(all(not(unix), not(windows)))]
fn verify_store_lock_binding(
    _database_path: &Path,
    _database_file: &File,
    _lock_path: &Path,
    _lock_file: &File,
    _expected: Option<&[u8]>,
) -> Result<(), StateError> {
    Ok(())
}

#[cfg(unix)]
fn validate_unix_lock_file(path: &Path, file: &File) -> Result<(), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| file_error("inspect database identity lock", path, error))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || !claw_sqlite_file_control::unix_file_is_service_private(
            file,
            rustix::process::geteuid().as_raw(),
            0o600,
        )
        .map_err(|_| StateError::InvalidPath {
            path: path.to_owned(),
            reason: "database identity lock ACL could not be validated",
        })?
    {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "database identity lock must be a private single-link regular file",
        });
    }
    verify_path_identity(path, file)
}

#[cfg(not(windows))]
fn prepare_windows_database_identity(_database: &Path) -> Result<(), StateError> {
    Ok(())
}

#[cfg(windows)]
fn prepare_windows_database_identity(database: &Path) -> Result<(), StateError> {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

    const PREFIX: &str = "gta-claw-writer-v1\n";
    const MAX_IDENTITY_BYTES: u64 = 1_048_576;

    // Locking the shared identity stream makes first-name selection race-free.
    let identity_path = writer_identity_path_for(database);
    let mut identity_file = acquire_writer_lock(&identity_path)?;
    let length = identity_file
        .metadata()
        .map_err(|error| file_error("inspect writer lock identity", database, error))?
        .len();
    if length > MAX_IDENTITY_BYTES {
        return Err(StateError::InvalidPath {
            path: database.to_owned(),
            reason: "writer lock identity metadata is too large",
        });
    }

    identity_file
        .seek(SeekFrom::Start(0))
        .map_err(|error| file_error("seek writer lock identity", database, error))?;
    let mut bytes = Vec::with_capacity(length as usize);
    identity_file
        .read_to_end(&mut bytes)
        .map_err(|error| file_error("read writer lock identity", database, error))?;
    let expected = format!("{PREFIX}{}", database.display()).into_bytes();
    let mut update = bytes.is_empty();
    if !bytes.is_empty() {
        let text = std::str::from_utf8(&bytes).map_err(|_| StateError::InvalidPath {
            path: database.to_owned(),
            reason: "writer lock identity metadata is not valid UTF-8",
        })?;
        let stored = text
            .strip_prefix(PREFIX)
            .filter(|stored| !stored.is_empty())
            .ok_or_else(|| StateError::InvalidPath {
                path: database.to_owned(),
                reason: "writer lock identity metadata has an unsupported format",
            })?;
        let stored = PathBuf::from(stored);
        if stored != database {
            let case_only = stored
                .to_string_lossy()
                .to_lowercase()
                .eq(&database.to_string_lossy().to_lowercase());
            if case_only {
                let stored_file = open_windows_file_no_follow(&stored, false, false)?;
                let database_file = open_windows_file_no_follow(database, false, false)?;
                if claw_sqlite_file_control::windows_file_identity(&stored_file)
                    .map_err(|error| file_control_database("identify stored Windows path", error))?
                    != claw_sqlite_file_control::windows_file_identity(&database_file).map_err(
                        |error| file_control_database("identify current Windows path", error),
                    )?
                {
                    return Err(StateError::InvalidPath {
                        path: database.to_owned(),
                        reason: "case-only writer identity path names different files",
                    });
                }
                update = true;
            } else if path_entry_exists(&sqlite_sidecar(&stored, "-wal"))?
                || path_entry_exists(&sqlite_sidecar(&stored, "-shm"))?
                || path_entry_exists(&sqlite_sidecar(&stored, "-journal"))?
            {
                return Err(StateError::InvalidPath {
                    path: database.to_owned(),
                    reason: "database was moved without its SQLite sidecars",
                });
            } else if let Ok(canonical_stored) = std::fs::canonicalize(&stored) {
                if canonical_stored == database {
                    update = true;
                } else {
                    let stored_identity_path = writer_identity_path_for(&canonical_stored);
                    match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&stored_identity_path)
                    {
                        Ok(other_identity) => match other_identity.try_lock() {
                            Ok(()) => {
                                File::unlock(&other_identity).map_err(|error| {
                                    file_error(
                                        "release comparison writer identity",
                                        &stored_identity_path,
                                        error,
                                    )
                                })?;
                                update = true;
                            }
                            Err(std::fs::TryLockError::WouldBlock) => {
                                return Err(StateError::InvalidPath {
                                    path: database.to_owned(),
                                    reason: "hard-linked SQLite databases are not supported",
                                });
                            }
                            Err(std::fs::TryLockError::Error(error)) => {
                                return Err(file_error(
                                    "compare writer filesystem identity",
                                    &stored_identity_path,
                                    error,
                                ));
                            }
                        },
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            update = true;
                        }
                        Err(error) if matches!(error.raw_os_error(), Some(32) | Some(33)) => {
                            return Err(StateError::InvalidPath {
                                path: database.to_owned(),
                                reason: "hard-linked SQLite databases are not supported",
                            });
                        }
                        Err(error) => {
                            return Err(file_error(
                                "open comparison writer identity",
                                &stored_identity_path,
                                error,
                            ));
                        }
                    }
                }
            } else {
                update = true;
            }
        }
    }
    if update {
        identity_file
            .seek(SeekFrom::Start(0))
            .and_then(|_| identity_file.set_len(0))
            .and_then(|_| identity_file.write_all(&expected))
            .and_then(|_| identity_file.sync_all())
            .map_err(|error| file_error("persist writer lock identity", &identity_path, error))?;
    }
    File::unlock(&identity_file)
        .map_err(|error| file_error("release writer identity lock", &identity_path, error))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InspectedDatabase {
    Fresh,
    Existing { schema_version: i64 },
}

async fn inspect_database(
    path: &Path,
    database_file: &File,
    require_latest: bool,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<InspectedDatabase, StateError> {
    if database_file
        .metadata()
        .map_err(|error| file_error("inspect state database", path, error))?
        .len()
        == 0
    {
        return Ok(InspectedDatabase::Fresh);
    }
    verify_path_identity(path, database_file)?;
    for attempt in 0..3 {
        let temporary = inspection_temporary_path(path)?;
        let mut cleanup_guard = SnapshotCleanupGuard::new(&temporary);
        match materialize_sqlite_snapshot(
            path,
            database_file,
            &temporary,
            None,
            deadline_state.clone(),
        )
        .await
        {
            Ok(()) => {
                let result =
                    inspect_database_snapshot(&temporary, require_latest, deadline_state.clone())
                        .await;
                let cleanup = remove_snapshot_artifacts(&temporary);
                if cleanup.is_ok() {
                    cleanup_guard.disarm();
                }
                verify_path_identity(path, database_file)?;
                return match (result, cleanup) {
                    (Err(error), Err(cleanup)) => Err(append_operation_cleanup(
                        "SQLite inspection",
                        error,
                        format!("temporary cleanup failed: {cleanup}"),
                    )),
                    (Err(error), Ok(())) => Err(error),
                    (Ok(_), Err(error)) => Err(error),
                    (Ok(inspected), Ok(())) => Ok(inspected),
                };
            }
            Err(error) if attempt < 2 && is_transient_sidecar_change(path, &error) => {
                remove_snapshot_artifacts(&temporary)?;
                cleanup_guard.disarm();
            }
            Err(error) => {
                if let Err(cleanup) = remove_snapshot_artifacts(&temporary) {
                    return Err(append_operation_cleanup(
                        "SQLite inspection",
                        error,
                        format!("temporary cleanup failed: {cleanup}"),
                    ));
                }
                cleanup_guard.disarm();
                return Err(error);
            }
        }
    }
    unreachable!("inspection retries either return or continue")
}

fn is_transient_sidecar_change(database: &Path, error: &StateError) -> bool {
    let wal = sqlite_sidecar(database, "-wal");
    let shm = sqlite_sidecar(database, "-shm");
    matches!(
        error,
        StateError::FileSystem { path, .. } if path == &wal || path == &shm
    )
}

async fn inspect_database_snapshot(
    path: &Path,
    require_latest: bool,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<InspectedDatabase, StateError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .create_if_missing(false)
        .foreign_keys(true);
    let connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| database("inspect state database read-only", error))?;
    let mut connection =
        OwnedSqliteConnectionGuard::new_cancellable(connection, deadline_state.clone());
    install_open_deadline_handler(&mut connection, deadline_state.clone()).await?;
    let result = inspect_database_connection(&mut connection, require_latest).await;
    let close = connection
        .close()
        .await
        .map_err(|error| database("close database inspection", error));
    match (result, close) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(inspected), Ok(())) => Ok(inspected),
    }
}

async fn inspect_database_connection(
    connection: &mut SqliteConnection,
    require_latest: bool,
) -> Result<InspectedDatabase, StateError> {
    let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| database("read SQLite application id", error))?;
    if application_id == 0 {
        let existing_objects = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'",
        )
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| database("inspect unclaimed SQLite database", error))?;
        if existing_objects != 0 {
            return Err(StateError::InvalidValue {
                field: "SQLite application id",
                reason: "unclaimed database is not empty",
            });
        }
        return Ok(InspectedDatabase::Fresh);
    } else if application_id != APPLICATION_ID {
        return Err(StateError::InvalidValue {
            field: "SQLite application id",
            reason: "database belongs to another application",
        });
    }
    let schema_version = validate_migration_history_connection(connection, require_latest).await?;
    Ok(InspectedDatabase::Existing { schema_version })
}

fn inspection_temporary_path(database: &Path) -> Result<PathBuf, StateError> {
    let parent = database.parent().ok_or_else(|| StateError::InvalidPath {
        path: database.to_owned(),
        reason: "database path must have a parent",
    })?;
    let digest = migration_checksum(&database.to_string_lossy());
    Ok(parent.join(format!(
        ".gta-claw-inspect-{digest}-{}.sqlite",
        writer_owner()?
    )))
}

async fn initialize_database(
    pool: &SqlitePool,
    path: &Path,
    inspected: InspectedDatabase,
    owner: &str,
    deadline_state: Arc<OpenDeadlineState>,
) -> Result<Option<RecoveredWriterLock>, StateError> {
    if inspected == InspectedDatabase::Fresh {
        return initialize_fresh_database(pool, path, owner, deadline_state).await;
    }
    let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
        .fetch_one(pool)
        .await
        .map_err(|error| database("read SQLite application id", error))?;
    if application_id != APPLICATION_ID {
        return Err(StateError::InvalidValue {
            field: "SQLite application id",
            reason: "database belongs to another application",
        });
    }
    apply_migrations(pool, path, owner, deadline_state).await
}

async fn initialize_fresh_database(
    pool: &SqlitePool,
    path: &Path,
    owner: &str,
    deadline_state: Arc<OpenDeadlineState>,
) -> Result<Option<RecoveredWriterLock>, StateError> {
    #[cfg(not(test))]
    let _ = path;
    let pooled = pool
        .acquire()
        .await
        .map_err(|error| database("acquire state database bootstrap connection", error))?;
    let begin_busy_timeout = deadline_state.busy_timeout.min(
        deadline_state
            .deadline
            .saturating_duration_since(std::time::Instant::now()),
    );
    let begin_is_deadline_limited = begin_busy_timeout < deadline_state.busy_timeout;
    let (connection, mut transaction_token) =
        claw_sqlite_file_control::begin_manual_pool_transaction_with_restore(
            pooled,
            begin_busy_timeout,
            deadline_state.busy_timeout,
            Some(Arc::clone(&deadline_state.cancelled)),
        )
        .await
        .map_err(|error| {
            if begin_is_deadline_limited && error.code() == Some(5) {
                deadline_state.timeout_error()
            } else {
                file_control_database("begin state database bootstrap", error)
            }
        })?;
    let mut connection =
        BackupConnectionGuard::new_cancellable(connection, Arc::clone(&deadline_state));
    #[cfg(test)]
    wait_at_migration_test_barrier(path, &deadline_state).await;
    let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| database("revalidate bootstrap application id", error))?;
    let existing_objects = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(|error| database("revalidate bootstrap schema emptiness", error))?;
    if application_id != 0 || existing_objects != 0 {
        return Err(StateError::InvalidMigrationHistory {
            reason: "fresh database ownership or schema changed before bootstrap".to_owned(),
        });
    }
    sqlx::query("PRAGMA application_id = 1196704067")
        .execute(&mut *connection)
        .await
        .map_err(|error| database("set SQLite application id", error))?;
    sqlx::query(MIGRATION_TABLE_SQL)
        .execute(&mut *connection)
        .await
        .map_err(|error| database("create migration table", error))?;
    for migration in MIGRATIONS {
        sqlx::raw_sql(migration.sql)
            .execute(&mut *connection)
            .await
            .map_err(|error| database("apply bootstrap migration", error))?;
        sqlx::query(
            "INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
             VALUES (?, ?, ?, CAST(unixepoch('subsec') * 1000 AS INTEGER))",
        )
        .bind(migration.version)
        .bind(migration.name)
        .bind(migration_checksum(migration.sql))
        .execute(&mut *connection)
        .await
        .map_err(|error| database("record bootstrap migration", error))?;
    }
    set_sqlite_user_version(&mut connection, LATEST_SCHEMA_VERSION).await?;
    let recovered_writer = claim_application_lock_connection(&mut connection, owner).await?;
    validate_migration_history_connection(&mut connection, true).await?;
    #[cfg(test)]
    wait_at_open_precommit_test_barrier(path, &deadline_state).await;
    deadline_state.begin_final_commit()?;
    let commit =
        claw_sqlite_file_control::commit_synchronously(&mut connection, &mut transaction_token)
            .await;
    deadline_state.finish_final_commit();
    commit.map_err(|error| file_control_database("commit state database bootstrap", error))?;
    connection.mark_reusable();
    drop(connection);
    Ok(recovered_writer)
}

async fn claim_application_lock_connection(
    connection: &mut SqliteConnection,
    owner: &str,
) -> Result<Option<RecoveredWriterLock>, StateError> {
    let previous = sqlx::query(
        "SELECT owner, acquired_at_ms
         FROM claw_writer_lock
         WHERE singleton = 1",
    )
    .fetch_optional(&mut *connection)
    .await
    .map_err(|error| database("read previous application writer", error))?
    .map(|row| {
        Ok(RecoveredWriterLock {
            previous_owner: row.try_get("owner").map_err(|error| {
                StateError::InvalidMigrationHistory {
                    reason: format!("persisted application writer owner is invalid: {error}"),
                }
            })?,
            previous_acquired_at_ms: row.try_get("acquired_at_ms").map_err(|error| {
                StateError::InvalidMigrationHistory {
                    reason: format!("persisted application writer timestamp is invalid: {error}"),
                }
            })?,
        })
    })
    .transpose()?;
    sqlx::query(
        "DELETE FROM claw_writer_lock
         WHERE singleton = 1",
    )
    .execute(&mut *connection)
    .await
    .map_err(|error| database("clear stale application writer", error))?;
    sqlx::query(
        "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
         VALUES (1, ?, CAST(unixepoch('subsec') * 1000 AS INTEGER))",
    )
    .bind(owner)
    .execute(&mut *connection)
    .await
    .map_err(|error| database("claim application writer lock", error))?;
    Ok(previous)
}

async fn set_sqlite_user_version(
    connection: &mut SqliteConnection,
    version: i64,
) -> Result<(), StateError> {
    let sql = match version {
        0 => "PRAGMA user_version = 0",
        1 => "PRAGMA user_version = 1",
        2 => "PRAGMA user_version = 2",
        _ => {
            return Err(StateError::InvalidMigrationHistory {
                reason: format!("unsupported SQLite user version {version}"),
            });
        }
    };
    sqlx::query(sql)
        .execute(&mut *connection)
        .await
        .map_err(|error| database("set SQLite user version", error))?;
    Ok(())
}

async fn validate_migration_history_connection(
    connection: &mut SqliteConnection,
    require_latest: bool,
) -> Result<i64, StateError> {
    let table_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema
            WHERE type = 'table' AND name = 'claw_schema_migrations'
        )",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(|error| database("inspect migration table", error))?;
    if !table_exists {
        return Err(StateError::InvalidMigrationHistory {
            reason: "migration table is missing".to_owned(),
        });
    }

    let applied = sqlx::query(
        "SELECT version, name, checksum
         FROM claw_schema_migrations
         ORDER BY version",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| database("read migration history", error))?;
    let current_version = validate_migration_rows(&applied)?;
    validate_schema_prefix(connection, current_version).await?;
    if require_latest && current_version != LATEST_SCHEMA_VERSION {
        return Err(StateError::InvalidMigrationHistory {
            reason: format!(
                "schema version {current_version} is not the required version {LATEST_SCHEMA_VERSION}"
            ),
        });
    }
    Ok(current_version)
}

pub(crate) async fn validate_operational_schema(
    connection: &mut SqliteConnection,
) -> Result<(), StateError> {
    validate_migration_history_connection(connection, true)
        .await
        .map(|_| ())
}

#[derive(Debug, Eq, PartialEq)]
struct SchemaObjectDefinition {
    kind: String,
    name: String,
    table: String,
    sql: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct ForeignKeyDefinition {
    table: String,
    id: i64,
    sequence: i64,
    referenced_table: String,
    from_column: String,
    to_column: Option<String>,
    on_update: String,
    on_delete: String,
    match_type: String,
}

#[derive(Debug, Eq, PartialEq)]
struct SchemaFingerprint {
    objects: Vec<SchemaObjectDefinition>,
    foreign_keys: Vec<ForeignKeyDefinition>,
}

async fn validate_schema_prefix(
    connection: &mut SqliteConnection,
    version: i64,
) -> Result<(), StateError> {
    let actual = schema_fingerprint(connection).await?;
    let expected = expected_schema_fingerprint(version).await?;
    if actual != expected {
        return Err(StateError::InvalidMigrationHistory {
            reason: format!(
                "database schema definitions do not match migration history version {version}"
            ),
        });
    }
    Ok(())
}

async fn schema_fingerprint(
    connection: &mut SqliteConnection,
) -> Result<SchemaFingerprint, StateError> {
    let rows = sqlx::query(
        "SELECT type, name, tbl_name, sql
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
           AND type IN ('index', 'table', 'trigger', 'view')
         ORDER BY type, name",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| database("read canonical schema objects", error))?;
    let mut objects = Vec::with_capacity(rows.len());
    let mut table_names = Vec::new();
    for row in rows {
        let kind: String =
            row.try_get("type")
                .map_err(|error| StateError::InvalidMigrationHistory {
                    reason: format!("schema object has an invalid type: {error}"),
                })?;
        let name: String =
            row.try_get("name")
                .map_err(|error| StateError::InvalidMigrationHistory {
                    reason: format!("schema object has an invalid name: {error}"),
                })?;
        let table: String =
            row.try_get("tbl_name")
                .map_err(|error| StateError::InvalidMigrationHistory {
                    reason: format!("schema object {name} has an invalid table name: {error}"),
                })?;
        let sql = row
            .try_get::<Option<String>, _>("sql")
            .map_err(|error| StateError::InvalidMigrationHistory {
                reason: format!("schema object {name} has an invalid definition: {error}"),
            })?
            .map(|sql| normalize_schema_sql(&sql));
        if kind == "table" {
            table_names.push(name.clone());
        }
        objects.push(SchemaObjectDefinition {
            kind,
            name,
            table,
            sql,
        });
    }
    let mut foreign_keys = Vec::new();
    for table in table_names {
        let rows = sqlx::query(
            "SELECT id, seq, \"table\", \"from\", \"to\", on_update, on_delete,
                    \"match\" AS match_type
             FROM pragma_foreign_key_list(?)
             ORDER BY id, seq",
        )
        .bind(&table)
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| database("read canonical foreign keys", error))?;
        for row in rows {
            foreign_keys.push(ForeignKeyDefinition {
                table: table.clone(),
                id: row
                    .try_get("id")
                    .map_err(|error| StateError::InvalidMigrationHistory {
                        reason: format!("foreign key on {table} has an invalid id: {error}"),
                    })?,
                sequence: row.try_get("seq").map_err(|error| {
                    StateError::InvalidMigrationHistory {
                        reason: format!("foreign key on {table} has an invalid sequence: {error}"),
                    }
                })?,
                referenced_table: row.try_get("table").map_err(|error| {
                    StateError::InvalidMigrationHistory {
                        reason: format!(
                            "foreign key on {table} has an invalid referenced table: {error}"
                        ),
                    }
                })?,
                from_column: row.try_get("from").map_err(|error| {
                    StateError::InvalidMigrationHistory {
                        reason: format!(
                            "foreign key on {table} has an invalid source column: {error}"
                        ),
                    }
                })?,
                to_column: row.try_get("to").map_err(|error| {
                    StateError::InvalidMigrationHistory {
                        reason: format!(
                            "foreign key on {table} has an invalid target column: {error}"
                        ),
                    }
                })?,
                on_update: row.try_get("on_update").map_err(|error| {
                    StateError::InvalidMigrationHistory {
                        reason: format!(
                            "foreign key on {table} has invalid update action: {error}"
                        ),
                    }
                })?,
                on_delete: row.try_get("on_delete").map_err(|error| {
                    StateError::InvalidMigrationHistory {
                        reason: format!(
                            "foreign key on {table} has invalid delete action: {error}"
                        ),
                    }
                })?,
                match_type: row.try_get("match_type").map_err(|error| {
                    StateError::InvalidMigrationHistory {
                        reason: format!("foreign key on {table} has invalid match type: {error}"),
                    }
                })?,
            });
        }
    }
    Ok(SchemaFingerprint {
        objects,
        foreign_keys,
    })
}

async fn expected_schema_fingerprint(version: i64) -> Result<SchemaFingerprint, StateError> {
    let options = SqliteConnectOptions::new()
        .filename(":memory:")
        .create_if_missing(true)
        .foreign_keys(true);
    let connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| database("open expected schema database", error))?;
    let mut connection = OwnedSqliteConnectionGuard::new(connection);
    let build = async {
        sqlx::query(MIGRATION_TABLE_SQL)
            .execute(&mut *connection)
            .await
            .map_err(|error| database("create expected migration table", error))?;
        for migration in MIGRATIONS {
            if migration.version > version {
                break;
            }
            sqlx::raw_sql(migration.sql)
                .execute(&mut *connection)
                .await
                .map_err(|error| database("apply expected schema migration", error))?;
        }
        schema_fingerprint(&mut connection).await
    }
    .await;
    let close = connection
        .close()
        .await
        .map_err(|error| database("close expected schema database", error));
    match (build, close) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(fingerprint), Ok(())) => Ok(fingerprint),
    }
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn validate_migration_rows(applied: &[sqlx::sqlite::SqliteRow]) -> Result<i64, StateError> {
    for (index, row) in applied.iter().enumerate() {
        let version: i64 =
            row.try_get("version")
                .map_err(|error| StateError::InvalidMigrationHistory {
                    reason: format!(
                        "migration row {} has an invalid version: {error}",
                        index + 1
                    ),
                })?;
        let expected_version = i64::try_from(index + 1).expect("migration index fits i64");
        if version != expected_version {
            return Err(StateError::InvalidMigrationHistory {
                reason: format!(
                    "expected applied version {expected_version}, found version {version}"
                ),
            });
        }
        let Some(migration) = MIGRATIONS
            .iter()
            .find(|migration| migration.version == version)
        else {
            return Err(StateError::NewerSchema {
                found: version,
                supported: LATEST_SCHEMA_VERSION,
            });
        };
        let name: String =
            row.try_get("name")
                .map_err(|error| StateError::InvalidMigrationHistory {
                    reason: format!("migration {version} has an invalid name: {error}"),
                })?;
        if name != migration.name {
            return Err(StateError::InvalidMigrationHistory {
                reason: format!(
                    "migration {version} is named {name}, expected {}",
                    migration.name
                ),
            });
        }
        let applied_checksum: String =
            row.try_get("checksum")
                .map_err(|error| StateError::InvalidMigrationHistory {
                    reason: format!("migration {version} has an invalid checksum: {error}"),
                })?;
        let embedded_checksum = migration_checksum(migration.sql);
        if applied_checksum != embedded_checksum {
            return Err(StateError::MigrationChecksumDrift {
                version,
                applied: applied_checksum,
                embedded: embedded_checksum,
            });
        }
    }
    Ok(i64::try_from(applied.len()).expect("applied migration count fits i64"))
}

async fn apply_migrations(
    pool: &SqlitePool,
    path: &Path,
    owner: &str,
    deadline_state: Arc<OpenDeadlineState>,
) -> Result<Option<RecoveredWriterLock>, StateError> {
    let mut preliminary = pool
        .acquire()
        .await
        .map_err(|error| database("acquire migration inspection connection", error))?;
    let preliminary_version =
        validate_migration_history_connection(&mut preliminary, false).await?;
    drop(preliminary);
    for migration in MIGRATIONS {
        if migration.version > preliminary_version && migration.destructive {
            let destination = destructive_backup_path(path, preliminary_version, migration.version);
            ensure_destructive_backup(pool, &destination, preliminary_version).await?;
        }
    }

    let pooled = pool
        .acquire()
        .await
        .map_err(|error| database("acquire transactional migration connection", error))?;
    let begin_busy_timeout = deadline_state.busy_timeout.min(
        deadline_state
            .deadline
            .saturating_duration_since(std::time::Instant::now()),
    );
    let begin_is_deadline_limited = begin_busy_timeout < deadline_state.busy_timeout;
    let (connection, mut transaction_token) =
        claw_sqlite_file_control::begin_manual_pool_transaction_with_restore(
            pooled,
            begin_busy_timeout,
            deadline_state.busy_timeout,
            Some(Arc::clone(&deadline_state.cancelled)),
        )
        .await
        .map_err(|error| {
            if begin_is_deadline_limited && error.code() == Some(5) {
                deadline_state.timeout_error()
            } else {
                file_control_database("begin immediate schema migration", error)
            }
        })?;
    let mut connection =
        BackupConnectionGuard::new_cancellable(connection, Arc::clone(&deadline_state));
    #[cfg(test)]
    wait_at_migration_test_barrier(path, &deadline_state).await;
    let migration_result = async {
        let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| database("revalidate migration application id", error))?;
        if application_id != APPLICATION_ID {
            return Err(StateError::InvalidValue {
                field: "SQLite application id",
                reason: "database ownership changed before migration",
            });
        }
        let mut current_version =
            validate_migration_history_connection(&mut connection, false).await?;
        for migration in MIGRATIONS {
            if migration.version <= current_version {
                continue;
            }

            sqlx::raw_sql(migration.sql)
                .execute(&mut *connection)
                .await
                .map_err(|error| database("apply schema migration", error))?;
            sqlx::query(
                "INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
                 VALUES (?, ?, ?, CAST(unixepoch('subsec') * 1000 AS INTEGER))",
            )
            .bind(migration.version)
            .bind(migration.name)
            .bind(migration_checksum(migration.sql))
            .execute(&mut *connection)
            .await
            .map_err(|error| database("record schema migration", error))?;
            current_version = migration.version;
        }
        set_sqlite_user_version(&mut connection, current_version).await?;
        validate_migration_history_connection(&mut connection, true).await?;
        claim_application_lock_connection(&mut connection, owner).await
    }
    .await;
    let recovered_writer = migration_result?;
    #[cfg(test)]
    wait_at_open_precommit_test_barrier(path, &deadline_state).await;
    deadline_state.begin_final_commit()?;
    let commit =
        claw_sqlite_file_control::commit_synchronously(&mut connection, &mut transaction_token)
            .await;
    deadline_state.finish_final_commit();
    commit.map_err(|error| {
        file_control_database("commit schema migration and writer claim", error)
    })?;
    connection.mark_reusable();
    drop(connection);
    Ok(recovered_writer)
}

#[cfg(test)]
async fn wait_at_migration_test_barrier(path: &Path, deadline_state: &OpenDeadlineState) {
    let barrier = MIGRATION_TEST_BARRIER
        .lock()
        .expect("migration test barrier lock poisoned")
        .get(path)
        .map(|configured| {
            (
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        loop {
            tokio::select! {
                () = release.notified() => break,
                () = tokio::time::sleep(Duration::from_millis(1)) => {
                    if !deadline_state.permits_sqlite_work() {
                        break;
                    }
                }
            }
        }
        MIGRATION_TEST_BARRIER
            .lock()
            .expect("migration test barrier lock poisoned")
            .remove(path);
    }
}

#[cfg(test)]
async fn wait_at_open_initialization_test_barrier(path: &Path) {
    let barrier = OPEN_INITIALIZATION_TEST_BARRIER
        .lock()
        .expect("open initialization test barrier lock poisoned")
        .get(path)
        .map(|configured| {
            (
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        release.notified().await;
        OPEN_INITIALIZATION_TEST_BARRIER
            .lock()
            .expect("open initialization test barrier lock poisoned")
            .remove(path);
    }
}

#[cfg(test)]
async fn wait_at_open_precommit_test_barrier(path: &Path, deadline_state: &OpenDeadlineState) {
    let barrier = OPEN_PRECOMMIT_TEST_BARRIER
        .lock()
        .expect("open precommit test barrier lock poisoned")
        .get(path)
        .map(|configured| {
            (
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        loop {
            tokio::select! {
                () = release.notified() => break,
                () = tokio::time::sleep(Duration::from_millis(1)) => {
                    if !deadline_state.permits_sqlite_work() {
                        break;
                    }
                }
            }
        }
        OPEN_PRECOMMIT_TEST_BARRIER
            .lock()
            .expect("open precommit test barrier lock poisoned")
            .remove(path);
    }
}

#[cfg(test)]
async fn wait_at_open_postcommit_test_barrier(path: &Path, deadline_state: &OpenDeadlineState) {
    let barrier = OPEN_POSTCOMMIT_TEST_BARRIER
        .lock()
        .expect("open postcommit test barrier lock poisoned")
        .get(path)
        .map(|configured| {
            (
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        loop {
            tokio::select! {
                () = release.notified() => break,
                () = tokio::time::sleep(Duration::from_millis(1)) => {
                    if deadline_state.cancelled.load(std::sync::atomic::Ordering::Acquire) {
                        break;
                    }
                }
            }
        }
        OPEN_POSTCOMMIT_TEST_BARRIER
            .lock()
            .expect("open postcommit test barrier lock poisoned")
            .remove(path);
    }
}

#[cfg(all(test, unix))]
async fn wait_at_checkpoint_test_barrier(path: &Path) {
    let barrier = CHECKPOINT_TEST_BARRIER
        .lock()
        .expect("checkpoint test barrier lock poisoned")
        .get(path)
        .map(|configured| {
            (
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        release.notified().await;
        CHECKPOINT_TEST_BARRIER
            .lock()
            .expect("checkpoint test barrier lock poisoned")
            .remove(path);
    }
}

#[cfg(test)]
async fn wait_at_snapshot_test_barrier(destination: &Path, temporary: &Path) {
    let barrier = SNAPSHOT_TEST_BARRIER
        .lock()
        .expect("snapshot test barrier lock poisoned")
        .get(destination)
        .map(|configured| {
            (
                Arc::clone(&configured.temporary),
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((published_temporary, entered, release)) = barrier {
        *published_temporary
            .lock()
            .expect("snapshot temporary path lock poisoned") = Some(temporary.to_owned());
        entered.notify_one();
        release.notified().await;
        SNAPSHOT_TEST_BARRIER
            .lock()
            .expect("snapshot test barrier lock poisoned")
            .remove(destination);
    }
}

#[cfg(test)]
async fn wait_at_published_handoff_test_barrier(destination: &Path) {
    let barrier = PUBLISHED_HANDOFF_TEST_BARRIER
        .lock()
        .expect("published handoff test barrier lock poisoned")
        .get(destination)
        .map(|configured| {
            (
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        release.notified().await;
        PUBLISHED_HANDOFF_TEST_BARRIER
            .lock()
            .expect("published handoff test barrier lock poisoned")
            .remove(destination);
    }
}

async fn ensure_destructive_backup(
    pool: &SqlitePool,
    destination: &Path,
    expected_version: i64,
) -> Result<(), StateError> {
    if path_entry_exists(destination)? {
        validate_standalone_snapshot_source(destination).await?;
        return validate_backup(
            destination,
            BackupValidationMode::ExactVersion(expected_version),
        )
        .await
        .map(|_| ());
    }
    backup_pool(
        pool,
        destination,
        BackupValidationMode::ExactVersion(expected_version),
        tokio::time::Instant::now() + MAX_CONFIGURED_TIMEOUT,
        u64::try_from(MAX_CONFIGURED_TIMEOUT.as_millis())
            .expect("maximum configured timeout fits u64"),
        None,
    )
    .await
}

async fn snapshot_database(
    source: &Path,
    source_file: &File,
    destination: &Path,
    expected_digest: Option<&[u8]>,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<(), StateError> {
    materialize_sqlite_snapshot(
        source,
        source_file,
        destination,
        expected_digest,
        deadline_state,
    )
    .await
}

async fn materialize_sqlite_snapshot(
    source: &Path,
    source_file: &File,
    destination: &Path,
    expected_digest: Option<&[u8]>,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<(), StateError> {
    verify_path_identity(source, source_file)?;
    reject_hard_link(source, source_file)?;
    if let Some(expected_digest) = expected_digest
        && file_digest_with_deadline(source_file, deadline_state.as_deref())? != expected_digest
    {
        return Err(StateError::InvalidBackup {
            path: source.to_owned(),
            reason: "sealed snapshot bytes changed before materialization".to_owned(),
        });
    }
    ensure_database_artifacts_absent(destination)?;
    let destination_text = destination
        .to_str()
        .ok_or_else(|| StateError::InvalidPath {
            path: destination.to_owned(),
            reason: "snapshot path must be valid Unicode",
        })?;
    let options = SqliteConnectOptions::new()
        .filename(source)
        .read_only(true)
        .create_if_missing(false)
        .foreign_keys(true);
    let wal_path = sqlite_sidecar(source, "-wal");
    let shm_path = sqlite_sidecar(source, "-shm");
    let journal_path = sqlite_sidecar(source, "-journal");
    if path_entry_exists(&journal_path)? {
        return Err(StateError::InvalidPath {
            path: source.to_owned(),
            reason: "snapshot source has a rollback journal",
        });
    }
    let wal_existed = path_entry_exists(&wal_path)?;
    let shm_existed = path_entry_exists(&shm_path)?;
    if wal_existed != shm_existed {
        return Err(StateError::InvalidPath {
            path: source.to_owned(),
            reason: "snapshot source has an ambiguous WAL/SHM artifact set",
        });
    }
    if expected_digest.is_some() && wal_existed {
        return Err(StateError::InvalidBackup {
            path: source.to_owned(),
            reason: "sealed snapshot source must not have WAL or SHM sidecars".to_owned(),
        });
    }
    if !wal_existed {
        return materialize_pinned_main_snapshot(
            source,
            source_file,
            destination,
            [&wal_path, &shm_path, &journal_path],
            expected_digest,
            deadline_state,
        )
        .await;
    }
    let wal_file = open_existing_file_no_follow(&wal_path)?;
    let shm_file = open_existing_file_no_follow(&shm_path)?;
    verify_path_identity(&wal_path, &wal_file)?;
    verify_path_identity(&shm_path, &shm_file)?;
    reject_hard_link(&wal_path, &wal_file)?;
    reject_hard_link(&shm_path, &shm_file)?;
    let connection = match SqliteConnection::connect_with(&options).await {
        Ok(connection) => connection,
        Err(error) => {
            return Err(invalid_backup(source, "open snapshot source", error));
        }
    };
    let mut connection =
        OwnedSqliteConnectionGuard::new_cancellable(connection, deadline_state.clone());
    install_open_deadline_handler(&mut connection, deadline_state.clone()).await?;
    if let Err(error) = verify_sqlite_connection_identity(&mut connection).await {
        let primary = invalid_backup(source, "verify opened snapshot identity", error);
        let close = connection
            .close()
            .await
            .map_err(|close| invalid_backup(source, "close changed snapshot source", close));
        return Err(match close {
            Ok(()) => primary,
            Err(cleanup) => append_operation_cleanup(
                "SQLite snapshot materialization",
                primary,
                format!("connection close failed: {cleanup}"),
            ),
        });
    }
    if let Err(error) = verify_path_identity(source, source_file) {
        let close = connection
            .close()
            .await
            .map_err(|close| invalid_backup(source, "close changed snapshot source", close));
        return Err(match close {
            Ok(()) => error,
            Err(cleanup) => append_operation_cleanup(
                "SQLite snapshot materialization",
                error,
                format!("connection close failed: {cleanup}"),
            ),
        });
    }
    let snapshot = sqlx::query("VACUUM main INTO ?")
        .bind(destination_text)
        .execute(&mut *connection)
        .await
        .map(|_| ())
        .map_err(|error| {
            OpenDeadlineState::deadline_or_error(
                deadline_state.as_deref(),
                invalid_backup(source, "materialize source snapshot", error),
            )
        });
    let sqlite_identity = verify_sqlite_connection_identity(&mut connection)
        .await
        .map_err(|error| invalid_backup(source, "reverify snapshot identity", error));
    let close = connection
        .close()
        .await
        .map_err(|error| invalid_backup(source, "close snapshot source", error));
    let result = match (snapshot, sqlite_identity, close) {
        (Err(error), _, _) | (Ok(()), Err(error), _) | (Ok(()), Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(()), Ok(())) => Ok(()),
    };
    let identity = verify_path_identity(source, source_file);
    let sidecar_identity = verify_path_identity(&wal_path, &wal_file)
        .and_then(|()| verify_path_identity(&shm_path, &shm_file));
    let journal_identity = match path_entry_exists(&journal_path) {
        Ok(false) => Ok(()),
        Ok(true) => Err(StateError::InvalidPath {
            path: source.to_owned(),
            reason: "snapshot source gained a rollback journal during inspection",
        }),
        Err(error) => Err(error),
    };
    match (result, identity, sidecar_identity, journal_identity) {
        (Err(error), _, _, _) => Err(cleanup_failed_snapshot(destination, error)),
        (Ok(()), Err(error), _, _)
        | (Ok(()), Ok(()), Err(error), _)
        | (Ok(()), Ok(()), Ok(()), Err(error)) => Err(cleanup_failed_snapshot(destination, error)),
        (Ok(()), Ok(()), Ok(()), Ok(())) => secure_private_snapshot_file(destination),
    }
}

async fn materialize_pinned_main_snapshot(
    source: &Path,
    source_file: &File,
    destination: &Path,
    sidecars: [&Path; 3],
    expected_digest: Option<&[u8]>,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<(), StateError> {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

    let before = file_digest_with_deadline(source_file, deadline_state.as_deref())?;
    if let Some(expected_digest) = expected_digest
        && before != expected_digest
    {
        return Err(StateError::InvalidBackup {
            path: source.to_owned(),
            reason: "sealed snapshot bytes changed before pinned copy".to_owned(),
        });
    }
    let pinned_copy = pinned_copy_temporary_path(destination)?;
    ensure_database_artifacts_absent(&pinned_copy)?;
    let mut pinned_copy_guard = SnapshotCleanupGuard::new(&pinned_copy);
    let mut input = source_file
        .try_clone()
        .map_err(|error| file_error("clone pinned snapshot source", source, error))?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(|error| file_error("seek pinned snapshot source", source, error))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&pinned_copy)
        .map_err(|error| file_error("create pinned snapshot copy", &pinned_copy, error))?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if let Some(deadline_state) = deadline_state.as_deref()
            && !deadline_state.permits_sqlite_work()
        {
            drop((input, output));
            return Err(cleanup_failed_snapshot(
                &pinned_copy,
                deadline_state.timeout_error(),
            ));
        }
        let read = input
            .read(&mut buffer)
            .map_err(|error| file_error("read pinned snapshot source", source, error))?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(|error| file_error("write pinned snapshot copy", &pinned_copy, error))?;
    }
    output
        .sync_all()
        .map_err(|error| file_error("sync pinned snapshot copy", &pinned_copy, error))?;
    drop((input, output));
    secure_private_snapshot_file(&pinned_copy)?;
    let source_validation = verify_path_identity(source, source_file).and_then(|()| {
        let after = file_digest_with_deadline(source_file, deadline_state.as_deref())?;
        if after != before {
            return Err(StateError::InvalidPath {
                path: source.to_owned(),
                reason: "snapshot source changed while copying its pinned handle",
            });
        }
        if let Some(expected_digest) = expected_digest
            && after != expected_digest
        {
            return Err(StateError::InvalidBackup {
                path: source.to_owned(),
                reason: "sealed snapshot bytes changed during pinned copy".to_owned(),
            });
        }
        for sidecar in sidecars {
            if path_entry_exists(sidecar)? {
                return Err(StateError::InvalidPath {
                    path: source.to_owned(),
                    reason: "snapshot source gained a journal or WAL artifact while copying",
                });
            }
        }
        Ok(())
    });
    if let Err(error) = source_validation {
        return Err(cleanup_failed_snapshot(&pinned_copy, error));
    }
    let copied_file = File::open(&pinned_copy)
        .map_err(|error| file_error("open completed pinned snapshot copy", &pinned_copy, error))?;
    pinned_copy_guard.bind_file(&copied_file)?;
    if file_digest_with_deadline(&copied_file, deadline_state.as_deref())? != before {
        return Err(cleanup_failed_snapshot(
            &pinned_copy,
            StateError::InvalidPath {
                path: source.to_owned(),
                reason: "completed pinned snapshot copy does not match the stable source",
            },
        ));
    }
    drop(copied_file);

    let destination_text = destination
        .to_str()
        .ok_or_else(|| StateError::InvalidPath {
            path: destination.to_owned(),
            reason: "snapshot path must be valid Unicode",
        })?;
    let options = SqliteConnectOptions::new()
        .filename(&pinned_copy)
        .read_only(true)
        .create_if_missing(false)
        .foreign_keys(true)
        .immutable(true);
    let connection = match SqliteConnection::connect_with(&options).await {
        Ok(connection) => connection,
        Err(error) => {
            return Err(cleanup_failed_snapshot(
                &pinned_copy,
                invalid_backup(source, "open pinned snapshot copy", error),
            ));
        }
    };
    let mut connection =
        OwnedSqliteConnectionGuard::new_cancellable(connection, deadline_state.clone());
    install_open_deadline_handler(&mut connection, deadline_state.clone()).await?;
    let snapshot = sqlx::query("VACUUM main INTO ?")
        .bind(destination_text)
        .execute(&mut *connection)
        .await
        .map(|_| ())
        .map_err(|error| {
            OpenDeadlineState::deadline_or_error(
                deadline_state.as_deref(),
                invalid_backup(source, "vacuum pinned snapshot copy", error),
            )
        });
    let close = connection
        .close()
        .await
        .map_err(|error| invalid_backup(source, "close pinned snapshot copy", error));
    let cleanup = remove_snapshot_artifacts(&pinned_copy);
    if cleanup.is_ok() {
        pinned_copy_guard.disarm();
    }
    let mut failure = None;
    for (label, result) in [
        ("VACUUM", snapshot),
        ("connection close", close),
        ("pinned-copy cleanup", cleanup),
    ] {
        if let Err(error) = result {
            failure = Some(match failure {
                Some(primary) => append_operation_cleanup(
                    "SQLite pinned snapshot materialization",
                    primary,
                    format!("{label} failed: {error}"),
                ),
                None => error,
            });
        }
    }
    if let Some(error) = failure {
        Err(cleanup_failed_snapshot(destination, error))
    } else {
        secure_private_snapshot_file(destination)
    }
}

fn pinned_copy_temporary_path(destination: &Path) -> Result<PathBuf, StateError> {
    snapshot_temporary_path(destination, "pinned-source")
}

fn file_digest_with_deadline(
    file: &File,
    deadline_state: Option<&OpenDeadlineState>,
) -> Result<Vec<u8>, StateError> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let path = Path::new("<open database handle>");
    let mut file = file
        .try_clone()
        .map_err(|error| file_error("clone database handle for digest", path, error))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| file_error("seek database handle for digest", path, error))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if let Some(deadline_state) = deadline_state
            && !deadline_state.permits_sqlite_work()
        {
            return Err(deadline_state.timeout_error());
        }
        let read = file
            .read(&mut buffer)
            .map_err(|error| file_error("read database handle for digest", path, error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().to_vec())
}

fn migration_checksum(sql: &str) -> String {
    let normalized = sql.replace("\r\n", "\n").replace('\r', "\n");
    let digest = Sha256::digest(normalized.as_bytes());
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn destructive_backup_path(path: &Path, from: i64, to: i64) -> PathBuf {
    let mut backup = path.as_os_str().to_owned();
    backup.push(format!(".pre-migration-v{from}-to-v{to}.bak"));
    PathBuf::from(backup)
}

#[cfg(unix)]
fn trusted_backup_manifest(
    snapshot: &PinnedSnapshot,
    deadline_state: Option<&OpenDeadlineState>,
) -> Result<String, StateError> {
    trusted_backup_manifest_for_digest(
        snapshot,
        &file_digest_with_deadline(&snapshot.file, deadline_state)?,
    )
}

#[cfg(unix)]
fn trusted_backup_manifest_for_digest(
    snapshot: &PinnedSnapshot,
    digest: &[u8],
) -> Result<String, StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = snapshot
        .file
        .metadata()
        .map_err(|error| file_error("inspect sealed backup identity", &snapshot.path, error))?;
    Ok(format!(
        "{BACKUP_SEAL_MAGIC}\nunix:{}:{}\n{}",
        metadata.dev(),
        metadata.ino(),
        hex_encode(digest)
    ))
}

#[cfg(windows)]
fn trusted_backup_manifest(
    snapshot: &PinnedSnapshot,
    deadline_state: Option<&OpenDeadlineState>,
) -> Result<String, StateError> {
    trusted_backup_manifest_for_digest(
        snapshot,
        &file_digest_with_deadline(&snapshot.file, deadline_state)?,
    )
}

#[cfg(windows)]
fn trusted_backup_manifest_for_digest(
    snapshot: &PinnedSnapshot,
    digest: &[u8],
) -> Result<String, StateError> {
    let identity =
        claw_sqlite_file_control::windows_file_identity(&snapshot.file).map_err(|error| {
            StateError::InvalidBackup {
                path: snapshot.path.clone(),
                reason: format!("capture Windows backup identity: {error}"),
            }
        })?;
    Ok(format!(
        "{BACKUP_SEAL_MAGIC}\nwindows:{}\n{}",
        hex_encode(&identity),
        hex_encode(digest)
    ))
}

#[cfg(all(not(unix), not(windows)))]
fn trusted_backup_manifest(
    snapshot: &PinnedSnapshot,
    _deadline_state: Option<&OpenDeadlineState>,
) -> Result<String, StateError> {
    Err(StateError::BackupNotPortable {
        path: snapshot.path.clone(),
        reason: "this platform has no authenticated backup-seal provider",
    })
}

#[cfg(all(not(unix), not(windows)))]
fn trusted_backup_manifest_for_digest(
    snapshot: &PinnedSnapshot,
    _digest: &[u8],
) -> Result<String, StateError> {
    Err(StateError::BackupNotPortable {
        path: snapshot.path.clone(),
        reason: "this platform has no authenticated backup-seal provider",
    })
}

struct TrustedBackupSeal {
    #[cfg(unix)]
    path: PathBuf,
    #[cfg(unix)]
    file: File,
}

#[cfg(unix)]
struct SealCreationGuard {
    temporary: PathBuf,
    published: PathBuf,
    armed: bool,
}

#[cfg(unix)]
impl SealCreationGuard {
    fn new(temporary: PathBuf, published: PathBuf) -> Self {
        Self {
            temporary,
            published,
            armed: true,
        }
    }

    fn cleanup(&mut self) -> Result<(), StateError> {
        let mut failure = None;
        for path in [&self.temporary, &self.published] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) if failure.is_none() => {
                    failure = Some(file_error("remove incomplete backup seal", path, error));
                }
                Err(_) => {}
            }
        }
        if let Err(error) = sync_parent_directory(&self.published)
            && failure.is_none()
        {
            failure = Some(error);
        }
        self.armed = false;
        failure.map_or(Ok(()), Err)
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for SealCreationGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cleanup();
        }
    }
}

impl TrustedBackupSeal {
    fn cleanup(self) -> Result<(), StateError> {
        #[cfg(unix)]
        {
            verify_path_identity(&self.path, &self.file)?;
            drop(self.file);
            std::fs::remove_file(&self.path).map_err(|error| {
                file_error("remove unused trusted backup seal", &self.path, error)
            })?;
            sync_parent_directory(&self.path)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn create_trusted_backup_seal(
    snapshot: &PinnedSnapshot,
    deadline_state: Option<&OpenDeadlineState>,
) -> Result<TrustedBackupSeal, StateError> {
    use xattr::FileExt as _;

    snapshot.verify()?;
    let seal_id = writer_owner()?;
    let seal_path =
        private_lock_root_for(&snapshot.path)?.join(format!("backup-seal-{seal_id}.record"));
    let temporary = seal_path.with_file_name(format!(".backup-seal-publish-{}", writer_owner()?));
    let mut guard = SealCreationGuard::new(temporary.clone(), seal_path.clone());
    let mut record = open_private_lock_file(&temporary, PrivateLockOpen::CreateNew)?;
    let result = (|| {
        let manifest = trusted_backup_manifest(snapshot, deadline_state)?;
        initialize_or_validate_lock_contents(&temporary, &mut record, &manifest, true)?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &temporary,
            rustix::fs::CWD,
            &seal_path,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            file_error(
                "publish trusted backup seal",
                &seal_path,
                std::io::Error::from(error),
            )
        })?;
        verify_path_identity(&seal_path, &record)?;
        sync_parent_directory(&seal_path)?;

        let writable = open_existing_file_no_follow_writable(&snapshot.path)?;
        if !files_share_identity_from_handles_portable(&snapshot.file, &writable)? {
            return Err(StateError::InvalidBackup {
                path: snapshot.path.clone(),
                reason: "snapshot changed before trusted seal attachment".to_owned(),
            });
        }
        writable
            .set_xattr(UNIX_BACKUP_SEAL_XATTR, seal_id.as_bytes())
            .map_err(|error| {
                file_error("attach trusted backup seal index", &snapshot.path, error)
            })?;
        writable
            .sync_all()
            .map_err(|error| file_error("sync trusted backup seal index", &snapshot.path, error))?;
        snapshot.verify()
    })();
    if let Err(primary) = result {
        drop(record);
        return match guard.cleanup() {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(StateError::OperationCleanupFailed {
                operation: "trusted backup seal",
                primary: Box::new(primary),
                cleanup: cleanup.to_string(),
            }),
        };
    }
    guard.disarm();
    Ok(TrustedBackupSeal {
        path: seal_path,
        file: record,
    })
}

#[cfg(windows)]
fn windows_backup_seal_path(path: &Path) -> PathBuf {
    let mut seal = path.as_os_str().to_owned();
    seal.push(":gta-claw-backup-seal");
    PathBuf::from(seal)
}

#[cfg(windows)]
fn create_trusted_backup_seal(
    snapshot: &PinnedSnapshot,
    deadline_state: Option<&OpenDeadlineState>,
) -> Result<TrustedBackupSeal, StateError> {
    use std::io::Write as _;

    snapshot.verify()?;
    let protected = claw_sqlite_file_control::protect_for_current_windows_user(
        trusted_backup_manifest(snapshot, deadline_state)?.as_bytes(),
    )
    .map_err(|error| StateError::InvalidBackup {
        path: snapshot.path.clone(),
        reason: format!("protect Windows backup seal: {error}"),
    })?;
    let seal_path = windows_backup_seal_path(&snapshot.path);
    let mut seal = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&seal_path)
        .map_err(|error| file_error("create protected Windows backup seal", &seal_path, error))?;
    seal.write_all(&protected)
        .and_then(|()| seal.sync_all())
        .map_err(|error| file_error("persist protected Windows backup seal", &seal_path, error))?;
    snapshot.verify()?;
    Ok(TrustedBackupSeal {})
}

#[cfg(all(not(unix), not(windows)))]
fn create_trusted_backup_seal(
    snapshot: &PinnedSnapshot,
    _deadline_state: Option<&OpenDeadlineState>,
) -> Result<TrustedBackupSeal, StateError> {
    Err(StateError::BackupNotPortable {
        path: snapshot.path.clone(),
        reason: "this platform has no authenticated backup-seal provider",
    })
}

#[cfg(unix)]
fn validate_trusted_backup_seal(
    snapshot: &PinnedSnapshot,
    deadline_state: Option<&OpenDeadlineState>,
) -> Result<Vec<u8>, StateError> {
    use std::io::Read as _;
    use xattr::FileExt as _;

    snapshot.verify()?;
    let seal_id = snapshot
        .file
        .get_xattr(UNIX_BACKUP_SEAL_XATTR)
        .map_err(|error| file_error("read trusted backup seal index", &snapshot.path, error))?
        .ok_or_else(|| StateError::BackupNotPortable {
            path: snapshot.path.clone(),
            reason: "no local trusted seal is attached",
        })?;
    let seal_id = std::str::from_utf8(&seal_id)
        .ok()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .ok_or_else(|| StateError::InvalidBackup {
            path: snapshot.path.clone(),
            reason: "trusted backup seal index has an invalid format".to_owned(),
        })?;
    let seal_path =
        private_lock_root_for(&snapshot.path)?.join(format!("backup-seal-{seal_id}.record"));
    let mut record =
        open_private_lock_file(&seal_path, PrivateLockOpen::Existing).map_err(|_| {
            StateError::BackupNotPortable {
                path: snapshot.path.clone(),
                reason: "the local trusted seal record is unavailable",
            }
        })?;
    if record
        .metadata()
        .map_err(|error| file_error("inspect trusted backup seal record", &seal_path, error))?
        .len()
        > 16 * 1024
    {
        return Err(StateError::InvalidBackup {
            path: snapshot.path.clone(),
            reason: "trusted backup seal record exceeds the maximum size".to_owned(),
        });
    }
    let mut actual = Vec::with_capacity(16 * 1024 + 1);
    (&mut record)
        .take(16 * 1024 + 1)
        .read_to_end(&mut actual)
        .map_err(|error| file_error("read trusted backup seal record", &seal_path, error))?;
    if actual.len() > 16 * 1024 {
        return Err(StateError::InvalidBackup {
            path: snapshot.path.clone(),
            reason: "trusted backup seal record exceeds the maximum size".to_owned(),
        });
    }
    let actual = String::from_utf8(actual).map_err(|_| StateError::InvalidBackup {
        path: snapshot.path.clone(),
        reason: "trusted backup seal record is not valid UTF-8".to_owned(),
    })?;
    let authenticated_digest = file_digest_with_deadline(&snapshot.file, deadline_state)?;
    let expected = trusted_backup_manifest_for_digest(snapshot, &authenticated_digest)?;
    verify_path_identity(&seal_path, &record)?;
    snapshot.verify()?;
    if actual != expected {
        return Err(StateError::InvalidBackup {
            path: snapshot.path.clone(),
            reason: "trusted backup seal does not match the pinned snapshot identity and digest"
                .to_owned(),
        });
    }
    Ok(authenticated_digest)
}

#[cfg(windows)]
fn validate_trusted_backup_seal(
    snapshot: &PinnedSnapshot,
    deadline_state: Option<&OpenDeadlineState>,
) -> Result<Vec<u8>, StateError> {
    use std::io::Read as _;

    snapshot.verify()?;
    let seal_path = windows_backup_seal_path(&snapshot.path);
    let seal = File::open(&seal_path).map_err(|_| StateError::BackupNotPortable {
        path: snapshot.path.clone(),
        reason: "no current-user protected backup seal is attached",
    })?;
    let length = seal
        .metadata()
        .map_err(|error| file_error("inspect protected Windows backup seal", &seal_path, error))?
        .len();
    if length == 0 || length > 16 * 1024 {
        return Err(StateError::InvalidBackup {
            path: snapshot.path.clone(),
            reason: "protected Windows backup seal has an invalid size".to_owned(),
        });
    }
    let mut protected = Vec::with_capacity(16 * 1024 + 1);
    seal.take(16 * 1024 + 1)
        .read_to_end(&mut protected)
        .map_err(|error| file_error("read protected Windows backup seal", &seal_path, error))?;
    if protected.len() > 16 * 1024 {
        return Err(StateError::InvalidBackup {
            path: snapshot.path.clone(),
            reason: "protected Windows backup seal exceeds the maximum size".to_owned(),
        });
    }
    let actual =
        claw_sqlite_file_control::unprotect_for_current_windows_user(&protected).map_err(|_| {
            StateError::BackupNotPortable {
                path: snapshot.path.clone(),
                reason: "backup seal belongs to a different Windows user or machine",
            }
        })?;
    let authenticated_digest = file_digest_with_deadline(&snapshot.file, deadline_state)?;
    let expected = trusted_backup_manifest_for_digest(snapshot, &authenticated_digest)?;
    snapshot.verify()?;
    if actual != expected.as_bytes() {
        return Err(StateError::InvalidBackup {
            path: snapshot.path.clone(),
            reason: "protected backup seal does not match the pinned snapshot identity and digest"
                .to_owned(),
        });
    }
    Ok(authenticated_digest)
}

#[cfg(all(not(unix), not(windows)))]
fn validate_trusted_backup_seal(
    snapshot: &PinnedSnapshot,
    _deadline_state: Option<&OpenDeadlineState>,
) -> Result<Vec<u8>, StateError> {
    Err(StateError::BackupNotPortable {
        path: snapshot.path.clone(),
        reason: "this platform has no authenticated backup-seal provider",
    })
}

async fn backup_pool(
    pool: &SqlitePool,
    destination: &Path,
    validation_mode: BackupValidationMode,
    deadline: tokio::time::Instant,
    timeout_ms: u64,
    operational_identity: Option<OperationalIdentity<'_>>,
) -> Result<(), StateError> {
    let timed_out = || StateError::OperationTimedOut {
        operation: "SQLite backup",
        timeout_ms,
    };
    let deadline_state = Arc::new(OpenDeadlineState {
        deadline: deadline.into_std(),
        timeout_ms,
        operation: "SQLite backup",
        busy_timeout: MAX_CONFIGURED_TIMEOUT,
        expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        finished: std::sync::atomic::AtomicBool::new(false),
        final_commit_state: std::sync::atomic::AtomicU8::new(0),
    });
    ensure_database_artifacts_absent(destination)?;
    let destination_directory = pin_private_directory(destination)?;
    let temporary = snapshot_temporary_path(destination, "backup")?;
    let temporary_directory = pin_private_directory(&temporary)?;
    ensure_database_artifacts_absent(&temporary)?;
    let mut temporary_guard = SnapshotCleanupGuard::new_pinned(&temporary, &temporary_directory)?;
    #[cfg(test)]
    if take_publication_failpoint(&CREATE_BACKUP_TEMP_BEFORE_VACUUM, destination) {
        use std::io::Write as _;

        let mut occupied = open_database_file(&temporary)?;
        occupied
            .write_all(b"occupied")
            .and_then(|()| occupied.sync_all())
            .map_err(|error| file_error("inject occupied backup temporary", &temporary, error))?;
    }
    let temporary_text = temporary
        .to_str()
        .ok_or_else(|| StateError::InvalidPath {
            path: temporary.clone(),
            reason: "backup path must be valid Unicode",
        })?
        .to_owned();
    let mut connection = match tokio::time::timeout_at(deadline, pool.acquire()).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            return Err(cleanup_failed_snapshot(
                &temporary,
                database("acquire bounded backup connection", error),
            ));
        }
        Err(_) => return Err(cleanup_failed_snapshot(&temporary, timed_out())),
    };
    let restore_busy_timeout_ms = sqlx::query_scalar::<_, i64>("PRAGMA busy_timeout")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| database("read backup source busy timeout", error))?;
    let restore_busy_timeout =
        Duration::from_millis(u64::try_from(restore_busy_timeout_ms).map_err(|_| {
            StateError::InvalidValue {
                field: "SQLite busy timeout",
                reason: "must be a non-negative millisecond value",
            }
        })?);
    let mut cancellation_guard = OperationCancellationGuard::new(Arc::clone(&deadline_state));
    #[cfg(test)]
    let execution_gate = BACKUP_CAPTURE_TEST_BARRIER
        .lock()
        .expect("backup capture test barrier lock poisoned")
        .remove(destination);
    #[cfg(not(test))]
    let execution_gate = None;
    let vacuum = claw_sqlite_file_control::vacuum_pool_into_with_deadline(
        connection,
        temporary_text,
        deadline,
        Arc::clone(&deadline_state.expired),
        Arc::clone(&deadline_state.cancelled),
        execution_gate,
        restore_busy_timeout,
    )
    .await
    .map_err(|error| database("create consistent SQLite backup", error));
    let (connection, vacuum) = match vacuum {
        Ok(result) => result,
        Err(error) => {
            #[cfg(test)]
            if take_publication_failpoint(&FAIL_BACKUP_HANDLER_RESET, destination) {
                return Err(cleanup_failed_snapshot(
                    &temporary,
                    StateError::OperationCleanupFailed {
                        operation: "SQLite backup",
                        primary: Box::new(error),
                        cleanup: "reset bounded backup progress handler failed: injected backup progress-handler reset failure".to_owned(),
                    },
                ));
            }
            return Err(cleanup_failed_snapshot(&temporary, error));
        }
    };
    let mut connection =
        BackupConnectionGuard::new_cancellable(connection, Arc::clone(&deadline_state));
    let sqlite_identity = verify_sqlite_connection_identity(&mut connection)
        .await
        .map_err(|error| database("reverify backup source SQLite identity", error));
    let source_identity = sqlite_identity.and_then(|()| {
        operational_identity
            .map(OperationalIdentity::verify)
            .unwrap_or(Ok(()))
    });
    if let Err(error) = source_identity {
        connection.discard().await;
        return Err(cleanup_failed_snapshot(&temporary, error));
    }
    let vacuum = Ok(vacuum);
    let reset_handler = async {
        #[cfg(test)]
        if take_publication_failpoint(&FAIL_BACKUP_HANDLER_RESET, destination) {
            return Err(sqlx::Error::Protocol(
                "injected backup progress-handler reset failure".to_owned(),
            ));
        }
        let mut handle = connection.lock_handle().await?;
        handle.set_progress_handler(0, || true);
        Ok::<(), sqlx::Error>(())
    }
    .await;
    if let Err(error) = reset_handler {
        connection.discard().await;
        let cleanup = database("reset bounded backup progress handler", error);
        let primary = match vacuum {
            Err(primary) => Some(primary),
            Ok(claw_sqlite_file_control::VacuumDeadlineOutcome::TimedOut) => Some(timed_out()),
            Ok(claw_sqlite_file_control::VacuumDeadlineOutcome::Completed) => None,
        };
        let failure = if let Some(primary) = primary {
            StateError::OperationCleanupFailed {
                operation: "SQLite backup",
                primary: Box::new(primary),
                cleanup: cleanup.to_string(),
            }
        } else {
            cleanup
        };
        return Err(cleanup_failed_snapshot(&temporary, failure));
    }
    connection.mark_reusable();
    drop(connection);
    let vacuum = vacuum.map_err(|error| cleanup_failed_snapshot(&temporary, error))?;
    match vacuum {
        claw_sqlite_file_control::VacuumDeadlineOutcome::Completed => {}
        claw_sqlite_file_control::VacuumDeadlineOutcome::TimedOut => {
            return Err(cleanup_failed_snapshot(&temporary, timed_out()));
        }
    }
    if let Err(error) = secure_private_snapshot_file(&temporary) {
        return Err(cleanup_failed_snapshot(&temporary, error));
    }
    let pinned = match PinnedSnapshot::open(&temporary) {
        Ok(pinned) => pinned,
        Err(error) => return Err(cleanup_failed_snapshot(&temporary, error)),
    };
    temporary_guard.bind_file(&pinned.file)?;
    #[cfg(test)]
    if tokio::time::timeout_at(
        deadline,
        wait_at_snapshot_test_barrier(destination, &temporary),
    )
    .await
    .is_err()
    {
        return Err(cleanup_pinned_or_error(
            "SQLite backup",
            pinned,
            timed_out(),
        ));
    }
    let preparation = async {
        mark_backup_provenance(&pinned, Some(Arc::clone(&deadline_state))).await?;
        validate_snapshot_marker_pinned(&pinned, Some(Arc::clone(&deadline_state))).await?;
        validate_backup_pinned(&pinned, validation_mode, Some(Arc::clone(&deadline_state)))
            .await
            .map(|_| ())?;
        initialize_restored_store_identity(&temporary, &pinned.file, destination)
    }
    .await;
    let mut identity_guard = match preparation {
        Ok(guard) => guard,
        Err(error) => {
            let error = if tokio::time::Instant::now() >= deadline {
                timed_out()
            } else {
                error
            };
            return Err(cleanup_pinned_or_error("SQLite backup", pinned, error));
        }
    };
    if tokio::time::Instant::now() >= deadline {
        let error = cleanup_identity_or_error("SQLite backup", &mut identity_guard, timed_out());
        return Err(cleanup_pinned_or_error("SQLite backup", pinned, error));
    }
    let seal = match create_trusted_backup_seal(&pinned, Some(deadline_state.as_ref())) {
        Ok(seal) => seal,
        Err(error) => {
            let error = cleanup_identity_or_error("SQLite backup", &mut identity_guard, error);
            return Err(match pinned.cleanup() {
                Ok(()) => error,
                Err(cleanup) => append_operation_cleanup(
                    "SQLite backup",
                    error,
                    format!("snapshot cleanup failed: {cleanup}"),
                ),
            });
        }
    };
    if tokio::time::Instant::now() >= deadline {
        let error = match seal.cleanup() {
            Ok(()) => timed_out(),
            Err(cleanup) => append_operation_cleanup(
                "SQLite backup",
                timed_out(),
                format!("seal cleanup failed: {cleanup}"),
            ),
        };
        let error = cleanup_identity_or_error("SQLite backup", &mut identity_guard, error);
        return Err(cleanup_pinned_or_error("SQLite backup", pinned, error));
    }
    if let Err(error) = pinned.sync() {
        let error = match seal.cleanup() {
            Ok(()) => error,
            Err(cleanup) => append_operation_cleanup(
                "SQLite backup",
                error,
                format!("seal cleanup failed: {cleanup}"),
            ),
        };
        let error = cleanup_identity_or_error("SQLite backup", &mut identity_guard, error);
        return Err(cleanup_pinned_or_error("SQLite backup", pinned, error));
    }
    if tokio::time::Instant::now() >= deadline {
        let error = match seal.cleanup() {
            Ok(()) => timed_out(),
            Err(cleanup) => append_operation_cleanup(
                "SQLite backup",
                timed_out(),
                format!("seal cleanup failed: {cleanup}"),
            ),
        };
        let error = cleanup_identity_or_error("SQLite backup", &mut identity_guard, error);
        return Err(cleanup_pinned_or_error("SQLite backup", pinned, error));
    }
    let published = match publish_snapshot(
        pinned,
        destination,
        "SQLite backup",
        Some((deadline, timeout_ms)),
        &destination_directory,
    ) {
        Ok(()) => Ok(()),
        Err(error @ StateError::PublicationUncertain { .. }) => {
            identity_guard.disarm();
            Err(cleanup_failed_snapshot(&temporary, error))
        }
        Err(error) => {
            let error = match seal.cleanup() {
                Ok(()) => error,
                Err(cleanup) => append_operation_cleanup(
                    "SQLite backup publication",
                    error,
                    format!("seal cleanup failed: {cleanup}"),
                ),
            };
            let error =
                cleanup_identity_or_error("SQLite backup publication", &mut identity_guard, error);
            Err(cleanup_failed_snapshot(&temporary, error))
        }
    };
    #[cfg(test)]
    if published.is_ok() {
        wait_at_published_handoff_test_barrier(destination).await;
    }
    if published.is_ok()
        && let Err(error) = validate_published_snapshot_handoff(destination)
    {
        identity_guard.disarm();
        cancellation_guard.disarm();
        temporary_guard.disarm();
        return Err(StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: format!("published backup failed final identity/sidecar validation: {error}"),
        });
    }
    if published.is_ok() {
        identity_guard.disarm();
        cancellation_guard.disarm();
        temporary_guard.disarm();
    }
    published
}

fn cleanup_failed_snapshot(path: &Path, error: StateError) -> StateError {
    match remove_snapshot_artifacts(path) {
        Ok(()) => error,
        Err(cleanup_error) => match error {
            StateError::PublicationUncertain {
                path: destination,
                reason,
            } => StateError::PublicationUncertain {
                path: destination,
                reason: format!("{reason}; temporary cleanup failed: {cleanup_error}"),
            },
            StateError::OperationCleanupFailed {
                operation,
                primary,
                cleanup,
            } => StateError::OperationCleanupFailed {
                operation,
                primary,
                cleanup: format!("{cleanup}; temporary artifact cleanup failed: {cleanup_error}"),
            },
            primary => append_operation_cleanup(
                "SQLite snapshot",
                primary,
                format!("temporary artifact cleanup failed: {cleanup_error}"),
            ),
        },
    }
}

fn append_operation_cleanup(
    operation: &'static str,
    error: StateError,
    additional_cleanup: String,
) -> StateError {
    match error {
        StateError::OperationCleanupFailed {
            operation,
            primary,
            cleanup,
        } => StateError::OperationCleanupFailed {
            operation,
            primary,
            cleanup: format!("{cleanup}; {additional_cleanup}"),
        },
        primary => StateError::OperationCleanupFailed {
            operation,
            primary: Box::new(primary),
            cleanup: additional_cleanup,
        },
    }
}

fn cleanup_pinned_or_error(
    operation: &'static str,
    pinned: PinnedSnapshot,
    error: StateError,
) -> StateError {
    match pinned.cleanup() {
        Ok(()) => error,
        Err(cleanup) => append_operation_cleanup(
            operation,
            error,
            format!("snapshot cleanup failed: {cleanup}"),
        ),
    }
}

async fn mark_backup_provenance(
    snapshot: &PinnedSnapshot,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<(), StateError> {
    let path = &snapshot.path;
    snapshot.verify()?;
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .foreign_keys(true);
    let connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| invalid_backup(path, "open backup for provenance", error))?;
    let mut connection =
        OwnedSqliteConnectionGuard::new_cancellable(connection, deadline_state.clone());
    install_open_deadline_handler(&mut connection, deadline_state).await?;
    snapshot.verify()?;
    install_sqlite_commit_guard(&mut connection)
        .await
        .map_err(|error| invalid_backup(path, "guard backup provenance commit", error))?;
    let result = async {
        sqlx::query("DELETE FROM claw_writer_lock")
            .execute(&mut *connection)
            .await
            .map_err(|error| invalid_backup(path, "clear backup writer owner", error))?;
        sqlx::query(
            "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
             VALUES (1, ?, 0)",
        )
        .bind(SNAPSHOT_PROVENANCE_OWNER)
        .execute(&mut *connection)
        .await
        .map_err(|error| invalid_backup(path, "mark backup provenance", error))?;
        Ok(())
    }
    .await;
    let close = connection
        .close()
        .await
        .map_err(|error| invalid_backup(path, "close provenance-marked backup", error));
    match (result, close) {
        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => snapshot.verify(),
    }
}

async fn validate_standalone_snapshot_source(path: &Path) -> Result<Vec<u8>, StateError> {
    let snapshot = PinnedSnapshot::open(path)?;
    validate_standalone_snapshot_source_pinned(&snapshot, None).await
}

async fn validate_standalone_snapshot_source_pinned(
    snapshot: &PinnedSnapshot,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<Vec<u8>, StateError> {
    validate_snapshot_marker_pinned(snapshot, deadline_state.clone()).await?;
    validate_trusted_backup_seal(snapshot, deadline_state.as_deref())
}

async fn validate_snapshot_marker_pinned(
    snapshot: &PinnedSnapshot,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<(), StateError> {
    let path = &snapshot.path;
    snapshot.verify()?;
    for sidecar in [
        sqlite_sidecar(path, "-wal"),
        sqlite_sidecar(path, "-shm"),
        sqlite_sidecar(path, "-journal"),
    ] {
        match std::fs::symlink_metadata(&sidecar) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StateError::InvalidPath {
                    path: sidecar,
                    reason: "symbolic-link SQLite sidecars are not supported",
                });
            }
            Ok(_) => {
                return Err(StateError::InvalidBackup {
                    path: path.to_owned(),
                    reason: format!(
                        "standalone snapshot source has sidecar {}",
                        sidecar.display()
                    ),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(file_error(
                    "inspect standalone snapshot sidecar",
                    &sidecar,
                    error,
                ));
            }
        }
    }
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .create_if_missing(false)
        .immutable(true);
    let connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| invalid_backup(path, "open standalone snapshot provenance", error))?;
    let mut connection =
        OwnedSqliteConnectionGuard::new_cancellable(connection, deadline_state.clone());
    install_open_deadline_handler(&mut connection, deadline_state.clone()).await?;
    let provenance = sqlx::query_scalar::<_, String>(
        "SELECT owner FROM claw_writer_lock
         WHERE singleton = 1 AND acquired_at_ms = 0",
    )
    .fetch_optional(&mut *connection)
    .await
    .map_err(|error| {
        OpenDeadlineState::deadline_or_error(
            deadline_state.as_deref(),
            invalid_backup(path, "read standalone snapshot provenance", error),
        )
    });
    let close = connection
        .close()
        .await
        .map_err(|error| invalid_backup(path, "close standalone snapshot provenance", error));
    let provenance = match (provenance, close) {
        (Err(error), _) | (Ok(_), Err(error)) => return Err(error),
        (Ok(provenance), Ok(())) => provenance,
    };
    if provenance.as_deref() != Some(SNAPSHOT_PROVENANCE_OWNER) {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: "restore source is not a verified standalone snapshot".to_owned(),
        });
    }
    snapshot.verify()
}

async fn clear_backup_writer_lock(snapshot: &PinnedSnapshot) -> Result<(), StateError> {
    let path = &snapshot.path;
    snapshot.verify()?;
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .foreign_keys(true);
    let connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| invalid_backup(path, "open backup for lock cleanup", error))?;
    let mut connection = OwnedSqliteConnectionGuard::new(connection);
    snapshot.verify()?;
    install_sqlite_commit_guard(&mut connection)
        .await
        .map_err(|error| invalid_backup(path, "guard backup lock cleanup", error))?;
    sqlx::query("DELETE FROM claw_writer_lock")
        .execute(&mut *connection)
        .await
        .map_err(|error| invalid_backup(path, "clear backup writer lock", error))?;
    connection
        .close()
        .await
        .map_err(|error| invalid_backup(path, "close cleaned backup", error))?;
    snapshot.verify()
}

async fn validate_backup(path: &Path, mode: BackupValidationMode) -> Result<i64, StateError> {
    let snapshot = PinnedSnapshot::open(path)?;
    validate_backup_pinned(&snapshot, mode, None).await
}

async fn validate_backup_pinned(
    snapshot: &PinnedSnapshot,
    mode: BackupValidationMode,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<i64, StateError> {
    let path = &snapshot.path;
    snapshot.verify()?;
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .create_if_missing(false)
        .foreign_keys(true);
    let connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| StateError::InvalidBackup {
            path: path.to_owned(),
            reason: DatabaseFailureText::render("open backup", error),
        })?;
    let mut connection =
        OwnedSqliteConnectionGuard::new_cancellable(connection, deadline_state.clone());
    install_open_deadline_handler(&mut connection, deadline_state.clone()).await?;
    let result = validate_backup_connection(path, &mut connection, mode)
        .await
        .map_err(|error| OpenDeadlineState::deadline_or_error(deadline_state.as_deref(), error));
    let close = connection
        .close()
        .await
        .map_err(|error| invalid_backup(path, "close backup", error));
    match (result, close) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(version), Ok(())) => {
            snapshot.verify()?;
            Ok(version)
        }
    }
}

async fn validate_backup_connection(
    path: &Path,
    connection: &mut SqliteConnection,
    mode: BackupValidationMode,
) -> Result<i64, StateError> {
    let check = sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| invalid_backup(path, "check backup integrity", error))?;
    if check.as_slice() != ["ok"] {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: check.join("; "),
        });
    }
    let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| invalid_backup(path, "read backup application id", error))?;
    if application_id != APPLICATION_ID {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: "application id does not match GTA Claw".to_owned(),
        });
    }
    let version = validate_migration_history_connection(connection, false)
        .await
        .map_err(|error| invalid_backup_state(path, error))?;
    let required_version = match mode {
        BackupValidationMode::LatestSource => Some(LATEST_SCHEMA_VERSION),
        BackupValidationMode::SupportedRestorePrefix => None,
        BackupValidationMode::ExactVersion(version) => Some(version),
    };
    if matches!(mode, BackupValidationMode::SupportedRestorePrefix) && version == 0 {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: "schema version zero is not a restorable migration prefix".to_owned(),
        });
    }
    if let Some(required_version) = required_version
        && version != required_version
    {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: format!(
                "schema version {version} does not match required version {required_version}"
            ),
        });
    }
    let user_version = sqlx::query_scalar::<_, i64>("PRAGMA user_version")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| invalid_backup(path, "read backup user version", error))?;
    if user_version != version {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: format!(
                "SQLite user_version {user_version} does not match migration version {version}"
            ),
        });
    }
    let foreign_key_violations =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pragma_foreign_key_check")
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| invalid_backup(path, "check backup foreign keys", error))?;
    if foreign_key_violations != 0 {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: format!("contains {foreign_key_violations} foreign-key violations"),
        });
    }
    Ok(version)
}

struct DatabaseFailureText;

impl DatabaseFailureText {
    fn render(operation: &'static str, error: sqlx::Error) -> String {
        crate::DatabaseFailure::from_sqlx(operation, error).to_string()
    }
}

fn invalid_backup(path: &Path, operation: &'static str, error: sqlx::Error) -> StateError {
    StateError::InvalidBackup {
        path: path.to_owned(),
        reason: DatabaseFailureText::render(operation, error),
    }
}

fn invalid_backup_state(path: &Path, error: StateError) -> StateError {
    StateError::InvalidBackup {
        path: path.to_owned(),
        reason: error.to_string(),
    }
}

async fn schema_version(pool: &SqlitePool) -> Result<i64, StateError> {
    sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM claw_schema_migrations")
        .fetch_one(pool)
        .await
        .map_err(|error| database("read schema version", error))
}

async fn migration_health_errors_connection(
    connection: &mut SqliteConnection,
) -> Result<Vec<String>, StateError> {
    match validate_migration_history_connection(connection, true).await {
        Ok(_) => Ok(Vec::new()),
        Err(
            error @ (StateError::MigrationChecksumDrift { .. }
            | StateError::NewerSchema { .. }
            | StateError::InvalidMigrationHistory { .. }),
        ) => Ok(vec![error.to_string()]),
        Err(error) => Err(error),
    }
}

fn file_error(operation: &'static str, path: &Path, error: std::io::Error) -> StateError {
    StateError::FileSystem {
        operation,
        path: path.to_owned(),
        message: error.to_string(),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::Path;

    use sqlx::{Connection as _, Row as _, SqliteConnection, SqlitePool};

    #[cfg(unix)]
    use super::verify_sqlite_connection_identity;
    use super::{
        FAIL_AFTER_PUBLICATION, PinnedSnapshot, StateStore, create_trusted_backup_seal, database,
        inspection_temporary_path, materialize_sqlite_snapshot, migration_checksum,
        open_existing_file_no_follow, remove_snapshot_artifacts,
    };
    use crate::StateError;

    pub(crate) fn pool(store: &StateStore) -> &SqlitePool {
        &store.pool
    }

    #[cfg(windows)]
    pub(crate) fn lock_path(store: &StateStore) -> &Path {
        &store.lock_path
    }

    pub(crate) fn trust_existing_sidecars(path: &Path) {
        let path = super::resolve_database_path(path).expect("resolve sidecar fixture database");
        let database_file =
            super::open_existing_file_no_follow(&path).expect("open sidecar fixture database");
        #[cfg(unix)]
        let generation = {
            use xattr::FileExt as _;

            database_file
                .get_xattr(super::UNIX_LOCK_IDENTITY_XATTR)
                .expect("read sidecar fixture generation")
                .expect("sidecar fixture generation exists")
        };
        #[cfg(windows)]
        let generation = {
            let lock_path = super::lock_path_for(&path);
            let lock_file = super::open_windows_file_no_follow(&lock_path, false, false)
                .expect("open sidecar fixture lock");
            super::verify_windows_lock_binding(&path, &database_file, &lock_path, &lock_file, None)
                .expect("read sidecar fixture lock generation")
        };
        #[cfg(all(not(unix), not(windows)))]
        let generation = Vec::new();
        super::secure_sqlite_sidecars(&path, Some(&generation))
            .expect("trust explicitly constructed sidecar fixture");
    }

    pub(crate) fn owner(store: &StateStore) -> &str {
        &store.owner
    }

    #[cfg(unix)]
    pub(crate) fn private_lock_root(path: &Path) -> std::path::PathBuf {
        super::private_lock_root_for(path).expect("resolve canonical private lock root")
    }

    #[cfg(unix)]
    pub(crate) fn writer_lock_records(
        path: &Path,
    ) -> std::collections::BTreeSet<std::path::PathBuf> {
        let root = private_lock_root(path);
        std::fs::read_dir(root)
            .expect("read isolated writer-lock root")
            .map(|entry| entry.expect("read writer-lock entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("dev-") && name.ends_with(".lock"))
            })
            .collect()
    }

    pub(crate) fn checksum(sql: &str) -> String {
        migration_checksum(sql)
    }

    pub(crate) fn initialize_store_identity_fixture(path: &Path) {
        let path = super::resolve_database_path(path).expect("resolve store identity fixture path");
        let database_file =
            super::open_database_file(&path).expect("open store identity fixture database");
        let (_lock_path, lock_file, process_identity) =
            super::acquire_store_lock(&path, &database_file, true)
                .expect("initialize store identity fixture");
        std::fs::File::unlock(&lock_file).expect("unlock store identity fixture");
        drop((lock_file, process_identity, database_file));
    }

    pub(crate) fn fail_after_publication_once(destination: &Path) {
        let destination =
            super::resolve_database_path(destination).expect("resolve publication failpoint path");
        FAIL_AFTER_PUBLICATION
            .lock()
            .expect("publication failpoint lock poisoned")
            .insert(destination);
    }

    pub(crate) fn fail_final_connection_close_once(path: &Path, timeout: bool) {
        let path = super::resolve_database_path(path)
            .expect("resolve final connection close failure path");
        super::FINAL_CONNECTION_CLOSE_FAILURES
            .lock()
            .expect("final connection close failures lock poisoned")
            .insert(
                path,
                if timeout {
                    super::FinalConnectionCloseFailure::Timeout
                } else {
                    super::FinalConnectionCloseFailure::Error
                },
            );
    }

    pub(crate) fn reseal_backup_fixture(path: &Path) {
        let path = super::resolve_database_path(path).expect("resolve backup fixture path");
        #[cfg(unix)]
        {
            use xattr::FileExt as _;

            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .expect("open Unix backup fixture for resealing");
            if file
                .get_xattr(super::UNIX_BACKUP_SEAL_XATTR)
                .expect("inspect prior Unix backup seal index")
                .is_some()
            {
                file.remove_xattr(super::UNIX_BACKUP_SEAL_XATTR)
                    .expect("remove prior Unix backup seal index");
            }
        }
        #[cfg(windows)]
        {
            secure_windows_file_fixture(&path);
            let seal_path = super::windows_backup_seal_path(&path);
            match std::fs::remove_file(&seal_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("remove prior Windows backup seal: {error}"),
            }
        }
        let snapshot = PinnedSnapshot::open(&path).expect("pin backup fixture for resealing");
        create_trusted_backup_seal(&snapshot, None).expect("create trusted backup fixture seal");
    }

    pub(crate) fn remove_backup_fixture_seal(path: &Path) {
        let path = super::resolve_database_path(path).expect("resolve sealed fixture path");
        #[cfg(unix)]
        {
            use xattr::FileExt as _;

            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .expect("open Unix backup fixture for seal cleanup");
            let seal_id = file
                .get_xattr(super::UNIX_BACKUP_SEAL_XATTR)
                .expect("read Unix backup fixture seal")
                .expect("Unix backup fixture seal exists");
            file.remove_xattr(super::UNIX_BACKUP_SEAL_XATTR)
                .expect("remove Unix backup fixture seal index");
            let seal_id =
                std::str::from_utf8(&seal_id).expect("Unix backup fixture seal id is UTF-8");
            let seal_path = super::private_lock_root_for(&path)
                .expect("resolve private seal root")
                .join(format!("backup-seal-{seal_id}.record"));
            std::fs::remove_file(&seal_path).expect("remove Unix backup fixture seal record");
            super::sync_parent_directory(&seal_path)
                .expect("sync removed Unix backup fixture seal");
        }
        #[cfg(windows)]
        std::fs::remove_file(super::windows_backup_seal_path(&path))
            .expect("remove Windows backup fixture seal");
    }

    pub(crate) fn create_competing_destination_once(destination: &Path) {
        let destination =
            super::resolve_database_path(destination).expect("resolve publication race path");
        super::CREATE_DESTINATION_BEFORE_PUBLICATION
            .lock()
            .expect("publication race lock poisoned")
            .insert(destination);
    }

    pub(crate) fn fail_backup_vacuum_once(destination: &Path) {
        let destination =
            super::resolve_database_path(destination).expect("resolve backup failure path");
        super::CREATE_BACKUP_TEMP_BEFORE_VACUUM
            .lock()
            .expect("backup failure lock poisoned")
            .insert(destination);
    }

    pub(crate) fn fail_backup_handler_reset_once(destination: &Path) {
        let destination =
            super::resolve_database_path(destination).expect("resolve backup reset failure path");
        super::FAIL_BACKUP_HANDLER_RESET
            .lock()
            .expect("backup reset failure lock poisoned")
            .insert(destination);
    }

    pub(crate) async fn expired_vacuum_does_not_start(
        store: &StateStore,
        destination: &Path,
    ) -> claw_sqlite_file_control::VacuumDeadlineOutcome {
        let connection = store
            .pool
            .acquire()
            .await
            .expect("acquire vacuum test connection");
        claw_sqlite_file_control::vacuum_pool_into_with_deadline(
            connection,
            destination
                .to_str()
                .expect("vacuum test destination is Unicode")
                .to_owned(),
            tokio::time::Instant::now() - std::time::Duration::from_millis(1),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            None,
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("expired vacuum returns a typed outcome")
        .1
    }

    pub(crate) fn set_migration_barrier(
        path: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let path = super::resolve_database_path(path).expect("resolve migration barrier path");
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        super::MIGRATION_TEST_BARRIER
            .lock()
            .expect("migration test barrier lock poisoned")
            .insert(
                path,
                super::MigrationTestBarrier {
                    entered: std::sync::Arc::clone(&entered),
                    release: std::sync::Arc::clone(&release),
                },
            );
        (entered, release)
    }

    pub(crate) fn set_open_initialization_barrier(
        path: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let path =
            super::resolve_database_path(path).expect("resolve open initialization barrier path");
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        super::OPEN_INITIALIZATION_TEST_BARRIER
            .lock()
            .expect("open initialization test barrier lock poisoned")
            .insert(
                path,
                super::MigrationTestBarrier {
                    entered: std::sync::Arc::clone(&entered),
                    release: std::sync::Arc::clone(&release),
                },
            );
        (entered, release)
    }

    pub(crate) fn set_open_precommit_barrier(
        path: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let path = super::resolve_database_path(path).expect("resolve open precommit barrier path");
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        super::OPEN_PRECOMMIT_TEST_BARRIER
            .lock()
            .expect("open precommit test barrier lock poisoned")
            .insert(
                path,
                super::MigrationTestBarrier {
                    entered: std::sync::Arc::clone(&entered),
                    release: std::sync::Arc::clone(&release),
                },
            );
        (entered, release)
    }

    pub(crate) fn set_open_postcommit_barrier(
        path: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let path =
            super::resolve_database_path(path).expect("resolve open postcommit barrier path");
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        super::OPEN_POSTCOMMIT_TEST_BARRIER
            .lock()
            .expect("open postcommit test barrier lock poisoned")
            .insert(
                path,
                super::MigrationTestBarrier {
                    entered: std::sync::Arc::clone(&entered),
                    release: std::sync::Arc::clone(&release),
                },
            );
        (entered, release)
    }

    #[cfg(unix)]
    pub(crate) fn set_checkpoint_barrier(
        path: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let path = super::resolve_database_path(path).expect("resolve checkpoint barrier path");
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        super::CHECKPOINT_TEST_BARRIER
            .lock()
            .expect("checkpoint test barrier lock poisoned")
            .insert(
                path,
                super::MigrationTestBarrier {
                    entered: std::sync::Arc::clone(&entered),
                    release: std::sync::Arc::clone(&release),
                },
            );
        (entered, release)
    }

    pub(crate) fn invalidate_writer_generation(store: &super::StateStore) {
        store
            .writer_generation
            .store(0, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn restore_writer_generation(store: &super::StateStore) {
        store
            .writer_generation
            .store(1, std::sync::atomic::Ordering::Release);
    }

    #[cfg(windows)]
    pub(crate) fn state_directory_is_private(path: &Path) -> bool {
        super::open_windows_directory_no_follow(path)
            .and_then(|file| super::validate_pinned_state_directory(path, &file))
            .is_ok()
    }

    #[cfg(windows)]
    pub(crate) fn secure_windows_file_fixture(path: &Path) {
        let file =
            super::open_windows_security_file(path).expect("open Windows fixture security handle");
        claw_sqlite_file_control::secure_new_windows_file(&file)
            .expect("protect Windows fixture security descriptor");
        super::validate_private_database_file(path, &file)
            .expect("validate protected Windows fixture");
    }

    #[cfg(unix)]
    pub(crate) fn clear_migration_barrier(path: &Path) {
        let path = super::resolve_database_path(path).expect("resolve migration barrier path");
        super::MIGRATION_TEST_BARRIER
            .lock()
            .expect("migration test barrier lock poisoned")
            .remove(&path);
    }

    pub(crate) fn set_snapshot_barrier(
        destination: &Path,
    ) -> (
        std::sync::Arc<std::sync::Mutex<Option<std::path::PathBuf>>>,
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let destination =
            super::resolve_database_path(destination).expect("resolve snapshot barrier path");
        let temporary = std::sync::Arc::new(std::sync::Mutex::new(None));
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        super::SNAPSHOT_TEST_BARRIER
            .lock()
            .expect("snapshot test barrier lock poisoned")
            .insert(
                destination,
                super::SnapshotTestBarrier {
                    temporary: std::sync::Arc::clone(&temporary),
                    entered: std::sync::Arc::clone(&entered),
                    release: std::sync::Arc::clone(&release),
                },
            );
        (temporary, entered, release)
    }

    pub(crate) fn set_published_handoff_barrier(
        destination: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let destination = super::resolve_database_path(destination)
            .expect("resolve published handoff barrier path");
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        super::PUBLISHED_HANDOFF_TEST_BARRIER
            .lock()
            .expect("published handoff test barrier lock poisoned")
            .insert(
                destination,
                super::MigrationTestBarrier {
                    entered: std::sync::Arc::clone(&entered),
                    release: std::sync::Arc::clone(&release),
                },
            );
        (entered, release)
    }

    pub(crate) fn set_backup_capture_barrier(
        destination: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        let destination =
            super::resolve_database_path(destination).expect("resolve backup capture barrier path");
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        super::BACKUP_CAPTURE_TEST_BARRIER
            .lock()
            .expect("backup capture test barrier lock poisoned")
            .insert(
                destination,
                std::sync::Arc::new(claw_sqlite_file_control::VacuumExecutionGate::new(
                    std::sync::Arc::clone(&entered),
                    std::sync::Arc::clone(&release),
                )),
            );
        (entered, release)
    }

    pub(crate) fn clear_snapshot_barrier(destination: &Path) {
        let destination =
            super::resolve_database_path(destination).expect("resolve snapshot barrier path");
        super::SNAPSHOT_TEST_BARRIER
            .lock()
            .expect("snapshot test barrier lock poisoned")
            .remove(&destination);
    }

    #[cfg(windows)]
    pub(crate) fn fail_windows_source_removal_once(destination: &Path) {
        let destination =
            super::resolve_database_path(destination).expect("resolve publication failpoint path");
        super::FAIL_WINDOWS_SOURCE_REMOVAL
            .lock()
            .expect("publication failpoint lock poisoned")
            .insert(destination);
    }

    pub(crate) async fn journal_mode(path: &Path) -> Result<String, StateError> {
        let database_file = open_existing_file_no_follow(path)?;
        let temporary = inspection_temporary_path(path)?;
        materialize_sqlite_snapshot(path, &database_file, &temporary, None, None).await?;
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&temporary)
            .read_only(true)
            .create_if_missing(false);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .map_err(|error| database("open journal inspection", error))?;
        let result = sqlx::query("PRAGMA journal_mode")
            .fetch_one(&mut connection)
            .await
            .map(|row| row.get(0))
            .map_err(|error| database("read journal mode", error));
        let close = connection
            .close()
            .await
            .map_err(|error| database("close journal inspection", error));
        let cleanup = remove_snapshot_artifacts(&temporary);
        match (result, close, cleanup) {
            (Err(error), _, _) | (Ok(_), Err(error), _) | (Ok(_), Ok(()), Err(error)) => Err(error),
            (Ok(mode), Ok(()), Ok(())) => Ok(mode),
        }
    }

    #[cfg(unix)]
    pub(crate) async fn sqlite_identity_is_valid(connection: &mut SqliteConnection) -> bool {
        verify_sqlite_connection_identity(connection).await.is_ok()
    }
}

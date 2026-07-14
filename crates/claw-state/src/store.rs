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

use crate::error::database;
use crate::{
    AuthenticationRepository, DeviceRepository, SessionRepository, StateError, TaskRepository,
};

const APPLICATION_ID: i64 = 0x4754_4143;
const LATEST_SCHEMA_VERSION: i64 = 1;
const SNAPSHOT_PROVENANCE_OWNER: &str = "gta-claw-standalone-snapshot-v1";
#[cfg(unix)]
const UNIX_LOCK_IDENTITY_XATTR: &str = "user.gta-claw.writer-lock-path";
#[cfg(unix)]
const UNIX_BACKUP_SEAL_XATTR: &str = "user.gta-claw.backup-seal-id";
#[cfg(unix)]
const UNIX_SIDECAR_GENERATION_XATTR: &str = "user.gta-claw.sidecar-generation";
const BACKUP_SEAL_MAGIC: &str = "gta-claw-backup-seal-v1";
const MAX_CONFIGURED_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(test)]
static FAIL_AFTER_PUBLICATION: Mutex<Option<PathBuf>> = Mutex::new(None);
#[cfg(test)]
static CREATE_DESTINATION_BEFORE_PUBLICATION: Mutex<Option<PathBuf>> = Mutex::new(None);
#[cfg(all(test, windows))]
static FAIL_WINDOWS_SOURCE_REMOVAL: Mutex<Option<PathBuf>> = Mutex::new(None);
#[cfg(test)]
static MIGRATION_TEST_BARRIER: Mutex<Option<MigrationTestBarrier>> = Mutex::new(None);
#[cfg(test)]
static SNAPSHOT_TEST_BARRIER: Mutex<Option<SnapshotTestBarrier>> = Mutex::new(None);
#[cfg(test)]
static FINAL_CONNECTION_CLOSE_FAILURES: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, FinalConnectionCloseFailure>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
struct MigrationTestBarrier {
    path: PathBuf,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
struct SnapshotTestBarrier {
    destination: PathBuf,
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

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial",
    sql: include_str!("../migrations/0001_initial.sql"),
    destructive: false,
}];

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
    cancelled: std::sync::atomic::AtomicBool,
    finished: std::sync::atomic::AtomicBool,
}

impl OpenDeadlineState {
    fn permits_sqlite_work(&self) -> bool {
        self.finished.load(std::sync::atomic::Ordering::Acquire)
            || (!self.cancelled.load(std::sync::atomic::Ordering::Acquire)
                && std::time::Instant::now() < self.deadline)
    }

    fn timeout_error(&self) -> StateError {
        StateError::OperationTimedOut {
            operation: "state store open",
            timeout_ms: self.timeout_ms,
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
        handle.set_progress_handler(1_000, move || deadline_state.permits_sqlite_work());
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
        let deadline_state = Arc::new(OpenDeadlineState {
            deadline: deadline.into_std(),
            timeout_ms,
            cancelled: std::sync::atomic::AtomicBool::new(false),
            finished: std::sync::atomic::AtomicBool::new(false),
        });
        let task_state = Arc::clone(&deadline_state);
        let mut task = tokio::spawn(async move { Self::open_inner(config, task_state).await });
        tokio::select! {
            result = &mut task => {
                let result = result.map_err(|error| StateError::InvalidValue {
                    field: "state store open task",
                    reason: if error.is_cancelled() {
                        "was cancelled unexpectedly"
                    } else {
                        "failed unexpectedly"
                    },
                })?;
                if result.is_ok() {
                    deadline_state
                        .finished
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                result
            }
            () = tokio::time::sleep_until(deadline) => {
                deadline_state
                    .cancelled
                    .store(true, std::sync::atomic::Ordering::Release);
                task.abort();
                let _ = task.await;
                Err(StateError::OperationTimedOut {
                    operation: "state store open",
                    timeout_ms,
                })
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

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(config.busy_timeout)
            .synchronous(config.synchronous.sqlx());
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
        let connect_deadline_state = Arc::clone(&deadline_state);
        let acquire_path = verified_path.clone();
        let acquire_parent_path = verified_parent_path.clone();
        let acquire_parent = Arc::clone(&verified_parent);
        let acquire_file = Arc::clone(&verified_file);
        let acquire_lock_path = verified_lock_path.clone();
        let acquire_lock_file = Arc::clone(&verified_lock_file);
        let acquire_lock_identity = verified_lock_identity.clone();
        let acquire_writer_generation = Arc::clone(&verified_writer_generation);
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
                let deadline_state = Arc::clone(&connect_deadline_state);
                Box::pin(async move {
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
                    initialize_connection_sidecars(connection).await?;
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
                    .await
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
                        .and_then(|()| validate_sqlite_sidecars(&path, lock_identity.as_deref()))
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
            let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
                .fetch_one(&mut *connection)
                .await?;
            if !matches!(application_id, 0 | APPLICATION_ID) {
                return Err(sqlx::Error::Protocol(
                    "database application identity changed before sidecar initialization"
                        .to_owned(),
                ));
            }
            sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut *connection)
                .await?;
            let result = async {
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
                sqlx::query("COMMIT").execute(&mut *connection).await?;
                Ok::<(), sqlx::Error>(())
            }
            .await;
            if result.is_err() {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
            }
            result
        }

        let mut recovered_writer = None;
        let writer_table_existed = matches!(
            locked_state,
            InspectedDatabase::Existing { schema_version } if schema_version >= 1
        );
        if writer_table_existed {
            recovered_writer = claim_application_lock(&pool, &owner).await?;
        }
        if let Err(error) = initialize_database(&pool, &path, locked_state).await {
            if writer_table_existed {
                restore_application_lock(&pool, &owner, recovered_writer.as_ref()).await?;
            }
            pool.close().await;
            return Err(error);
        }
        if !writer_table_existed {
            recovered_writer = claim_application_lock(&pool, &owner).await?;
        }
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
        backup_pool(
            &self.pool,
            &destination,
            expected_version,
            deadline,
            timeout_ms,
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
        let backup = resolve_snapshot_source_path(backup.as_ref())?;
        let backup_file = open_existing_file_no_follow(&backup)?;
        verify_path_identity(&backup, &backup_file)?;
        reject_hard_link(&backup, &backup_file)?;
        let backup_snapshot = PinnedSnapshot::from_file(&backup, backup_file)?;
        let sealed_digest = validate_standalone_snapshot_source_pinned(&backup_snapshot).await?;
        let requested_destination = destination.as_ref();
        ensure_database_artifacts_absent(requested_destination)?;
        let destination = resolve_database_path(requested_destination)?;
        ensure_database_artifacts_absent(&destination)?;
        let destination_directory = pin_private_directory(&destination)?;
        let temporary = snapshot_temporary_path(&destination, "restore")?;
        snapshot_database(
            &backup,
            &backup_snapshot.file,
            &temporary,
            Some(&sealed_digest),
        )
        .await?;
        let pinned = match PinnedSnapshot::open(&temporary) {
            Ok(pinned) => pinned,
            Err(error) => return Err(cleanup_failed_snapshot(&temporary, error)),
        };
        if let Err(error) = validate_snapshot_marker_pinned(&pinned, None).await {
            return Err(pinned.cleanup().err().unwrap_or(error));
        }
        if let Err(error) = clear_backup_writer_lock(&pinned).await {
            return Err(pinned.cleanup().err().unwrap_or(error));
        }
        if let Err(error) = validate_backup_pinned(&pinned, None, None).await {
            return Err(pinned.cleanup().err().unwrap_or(error));
        }
        if let Err(error) = initialize_restored_store_identity(&temporary, &pinned.file) {
            return Err(pinned.cleanup().err().unwrap_or(error));
        }
        if let Err(error) = pinned.sync() {
            return Err(pinned.cleanup().err().unwrap_or(error));
        }
        if let Err(error) = publish_snapshot(pinned, &destination, None, &destination_directory) {
            return Err(cleanup_failed_snapshot(&temporary, error));
        }
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
        let row = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&self.pool)
            .await
            .map_err(|error| database("checkpoint SQLite WAL", error))?;
        Ok(CheckpointReport {
            busy: row.get(0),
            log_frames: row.get(1),
            checkpointed_frames: row.get(2),
        })
    }

    /// Checkpoints, closes all pooled connections, and releases the writer lock.
    pub async fn close(self) -> Result<CheckpointReport, StateError> {
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
        let application_lock_released = if let Some(connection) = connection.as_mut() {
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
fn initialize_restored_store_identity(path: &Path, expected_file: &File) -> Result<(), StateError> {
    let file = open_database_file(path)?;
    if !files_share_identity_from_handles_portable(expected_file, &file)? {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "restored snapshot changed before identity initialization",
        });
    }
    verify_path_identity(path, &file)?;
    let (_lock_path, lock_file, process_identity) = acquire_store_lock(path, &file, true)?;
    File::unlock(&lock_file)
        .map_err(|error| file_error("release restored database identity lock", path, error))?;
    drop((lock_file, process_identity));
    Ok(())
}

#[cfg(not(unix))]
fn initialize_restored_store_identity(
    _path: &Path,
    _expected_file: &File,
) -> Result<(), StateError> {
    Ok(())
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
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| file_error("inspect snapshot source directory", path, error))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
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

#[cfg(unix)]
fn validate_state_directory(path: &Path) -> Result<(), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| file_error("inspect state directory security", path, error))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "state directory must be owned by the service, mode 0700, and non-symlink",
        });
    }
    Ok(())
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
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
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
        options.create_new(true);
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
    Ok(file)
}

#[cfg(unix)]
fn validate_private_database_file(path: &Path, file: &File) -> Result<(), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| file_error("inspect state database security", path, error))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
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
    let file = open_existing_file_no_follow_writable(path)?;
    validate_private_database_file(path, &file)
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
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || !matches!(mode, 0o400 | 0o600)
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
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
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
    let file_name = destination
        .file_name()
        .ok_or_else(|| StateError::InvalidPath {
            path: destination.to_owned(),
            reason: "snapshot destination must include a file name",
        })?
        .to_string_lossy();
    Ok(
        default_private_lock_root()?
            .join(format!(".{file_name}.{}.{purpose}-tmp", writer_owner()?)),
    )
}

#[cfg(not(unix))]
fn snapshot_temporary_path(destination: &Path, purpose: &str) -> Result<PathBuf, StateError> {
    let owner = writer_owner()?;
    let file_name = destination
        .file_name()
        .ok_or_else(|| StateError::InvalidPath {
            path: destination.to_owned(),
            reason: "restore destination must include a file name",
        })?
        .to_string_lossy();
    Ok(destination.with_file_name(format!(".{file_name}.{owner}.{purpose}-tmp")))
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
    validate_sqlite_sidecars(database, Some(&generation))
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
    File::unlock(&lock_file)
        .map_err(|error| file_error("release preflight Windows writer lock", &lock_path, error))?;
    validate_sqlite_sidecars(database, Some(&generation))
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
fn secure_sqlite_sidecars(database: &Path, generation: Option<&[u8]>) -> Result<(), StateError> {
    use std::io::{Read as _, Write as _};

    let generation = generation.ok_or_else(|| StateError::InvalidPath {
        path: database.to_owned(),
        reason: "sidecar generation is unavailable",
    })?;
    for sidecar in sqlite_mutable_sidecars(database) {
        if !path_entry_exists(&sidecar)? {
            continue;
        }
        let file = open_existing_file_no_follow_writable(&sidecar)?;
        validate_private_database_file(&sidecar, &file)?;
        let generation_path = sidecar_generation_path(&sidecar);
        match OpenOptions::new().read(true).open(&generation_path) {
            Ok(mut metadata) => {
                let mut current = Vec::new();
                metadata.read_to_end(&mut current).map_err(|error| {
                    file_error("read SQLite sidecar generation", &sidecar, error)
                })?;
                if current != generation {
                    return Err(StateError::InvalidPath {
                        path: sidecar,
                        reason: "SQLite sidecar belongs to a different database generation",
                    });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut metadata = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&generation_path)
                    .map_err(|error| {
                        file_error("create SQLite sidecar generation", &sidecar, error)
                    })?;
                metadata
                    .write_all(generation)
                    .and_then(|()| metadata.sync_all())
                    .map_err(|error| {
                        file_error("persist SQLite sidecar generation", &sidecar, error)
                    })?;
            }
            Err(error) => {
                return Err(file_error(
                    "open SQLite sidecar generation",
                    &sidecar,
                    error,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_sqlite_sidecars(database: &Path, generation: Option<&[u8]>) -> Result<(), StateError> {
    use std::io::Read as _;

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
        let mut metadata = match File::open(sidecar_generation_path(&sidecar)) {
            Ok(metadata) => metadata,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && !path_entry_exists(&sidecar)? =>
            {
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(StateError::InvalidPath {
                    path: sidecar,
                    reason: "SQLite sidecar generation is missing",
                });
            }
            Err(error) => {
                return Err(file_error(
                    "open SQLite sidecar generation",
                    &sidecar,
                    error,
                ));
            }
        };
        let mut current = Vec::new();
        metadata
            .read_to_end(&mut current)
            .map_err(|error| file_error("read SQLite sidecar generation", &sidecar, error))?;
        if current != generation {
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
    armed: bool,
}

impl SnapshotCleanupGuard {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SnapshotCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        for artifact in database_artifacts(&self.path) {
            loop {
                match std::fs::remove_file(&artifact) {
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
            verify_path_identity(&wal_path, &wal_file)?;
            drop(wal_file);
            std::fs::remove_file(&wal_path).map_err(|cleanup| {
                file_error(
                    "release failed destination WAL reservation",
                    &wal_path,
                    cleanup,
                )
            })?;
            return if path_entry_exists(&shm_path)? {
                Err(StateError::BackupDestinationExists { path: shm_path })
            } else {
                Err(file_error("reserve destination SHM", &shm_path, error))
            };
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
            verify_path_identity(&wal_path, &wal_file)?;
            verify_path_identity(&shm_path, &shm_file)?;
            drop((wal_file, shm_file));
            for reservation in [&wal_path, &shm_path] {
                std::fs::remove_file(reservation).map_err(|cleanup| {
                    file_error(
                        "release failed destination sidecar reservation",
                        reservation,
                        cleanup,
                    )
                })?;
            }
            return if path_entry_exists(&journal_path)? {
                Err(StateError::BackupDestinationExists { path: journal_path })
            } else {
                Err(file_error(
                    "reserve destination journal",
                    &journal_path,
                    error,
                ))
            };
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
    publication_deadline: Option<(tokio::time::Instant, u64)>,
    destination_directory: &PinnedPrivateDirectory,
) -> Result<(), StateError> {
    if let Err(error) = source.verify() {
        return Err(source.cleanup().err().unwrap_or(error));
    }
    if let Err(error) =
        verify_directory_path_identity(&destination_directory.path, &destination_directory.file)
    {
        return Err(source.cleanup().err().unwrap_or(error));
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
        reservations.release()?;
        return Err(StateError::OperationTimedOut {
            operation: "SQLite backup",
            timeout_ms,
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
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| file_error("inspect pinned state directory", path, error))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
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
        let metadata = std::fs::symlink_metadata(ancestor)
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
    prepare_windows_published_identity(source, destination)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    std::fs::hard_link(source, destination)
}

#[cfg(test)]
fn take_publication_failpoint(failpoint: &Mutex<Option<PathBuf>>, destination: &Path) -> bool {
    let mut configured = failpoint
        .lock()
        .expect("publication failpoint lock poisoned");
    if configured.as_deref() == Some(destination) {
        configured.take();
        true
    } else {
        false
    }
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

#[cfg(windows)]
fn prepare_windows_published_identity(source: &Path, destination: &Path) -> Result<(), StateError> {
    use std::io::{Seek as _, SeekFrom, Write as _};

    const PREFIX: &str = "gta-claw-writer-v1\n";

    let identity_path = writer_identity_path_for(source);
    let mut identity_file = acquire_writer_lock(&identity_path)?;
    let identity = format!("{PREFIX}{}", destination.display());
    identity_file
        .seek(SeekFrom::Start(0))
        .and_then(|_| identity_file.set_len(0))
        .and_then(|_| identity_file.write_all(identity.as_bytes()))
        .and_then(|_| identity_file.sync_all())
        .map_err(|error| {
            file_error("persist published database identity", &identity_path, error)
        })?;
    File::unlock(&identity_file)
        .map_err(|error| file_error("release published database identity", &identity_path, error))
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
        default_private_lock_root()?.join(format!("create-{}.lock", migration_checksum(&contents)));
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

#[cfg(unix)]
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

#[cfg(unix)]
fn validate_private_lock_directory(path: &Path) -> Result<(), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| file_error("inspect private writer-lock directory", path, error))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
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
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            if matches!(error.raw_os_error(), Some(32) | Some(33)) {
                StateError::StoreLocked {
                    path: path.to_owned(),
                }
            } else {
                file_error("open writer lock", path, error)
            }
        })?;
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
    let lock_path = default_private_lock_root()?.join(format!(
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
        let primary = file_error(
            "publish persistent writer-lock inode",
            &lock_path,
            error.into(),
        );
        verify_path_identity(&lock_temporary, &lock_file)?;
        File::unlock(&lock_file).map_err(|unlock| {
            file_error(
                "release failed temporary writer lock",
                &lock_temporary,
                unlock,
            )
        })?;
        drop(lock_file);
        std::fs::remove_file(&lock_temporary).map_err(|cleanup| {
            file_error(
                "remove failed temporary writer lock",
                &lock_temporary,
                cleanup,
            )
        })?;
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
            let primary = file_error("persist database lock identity", path, error.into());
            verify_path_identity(&lock_path, &lock_file)?;
            File::unlock(&lock_file).map_err(|unlock| {
                file_error("release failed unpublished writer lock", &lock_path, unlock)
            })?;
            drop(lock_file);
            std::fs::remove_file(&lock_path).map_err(|cleanup| {
                file_error(
                    "remove failed unreferenced writer lock",
                    &lock_path,
                    cleanup,
                )
            })?;
            sync_parent_directory(&lock_path)?;
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
    if parent != default_private_lock_root()? {
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
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
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
            if let Ok(canonical_stored) = std::fs::canonicalize(&stored) {
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
            } else if path_entry_exists(&sqlite_sidecar(&stored, "-wal"))?
                || path_entry_exists(&sqlite_sidecar(&stored, "-shm"))?
            {
                return Err(StateError::InvalidPath {
                    path: database.to_owned(),
                    reason: "database was moved without its SQLite sidecars",
                });
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
                    (Err(error), _) => Err(error),
                    (Ok(_), Err(error)) => Err(error),
                    (Ok(inspected), Ok(())) => Ok(inspected),
                };
            }
            Err(error) if attempt < 2 && is_transient_sidecar_change(path, &error) => {
                remove_snapshot_artifacts(&temporary)?;
                cleanup_guard.disarm();
            }
            Err(error) => {
                remove_snapshot_artifacts(&temporary)?;
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
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| database("inspect state database read-only", error))?;
    install_open_deadline_handler(&mut connection, deadline_state).await?;
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
    let owner = writer_owner()?;
    let file_name = database
        .file_name()
        .ok_or_else(|| StateError::InvalidPath {
            path: database.to_owned(),
            reason: "database path must include a file name",
        })?
        .to_string_lossy();
    Ok(database.with_file_name(format!(".{file_name}.{owner}.inspect-tmp")))
}

async fn initialize_database(
    pool: &SqlitePool,
    path: &Path,
    inspected: InspectedDatabase,
) -> Result<(), StateError> {
    if inspected == InspectedDatabase::Fresh {
        initialize_fresh_database(pool).await?;
        return Ok(());
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
    apply_migrations(pool, path).await
}

async fn initialize_fresh_database(pool: &SqlitePool) -> Result<(), StateError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| database("begin state database bootstrap", error))?;
    let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| database("revalidate bootstrap application id", error))?;
    let existing_objects = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| database("revalidate bootstrap schema emptiness", error))?;
    if application_id != 0 || existing_objects != 0 {
        return Err(StateError::InvalidMigrationHistory {
            reason: "fresh database ownership or schema changed before bootstrap".to_owned(),
        });
    }
    sqlx::query("PRAGMA application_id = 1196704067")
        .execute(&mut *transaction)
        .await
        .map_err(|error| database("set SQLite application id", error))?;
    sqlx::query(MIGRATION_TABLE_SQL)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database("create migration table", error))?;
    for migration in MIGRATIONS {
        sqlx::raw_sql(migration.sql)
            .execute(&mut *transaction)
            .await
            .map_err(|error| database("apply bootstrap migration", error))?;
        sqlx::query(
            "INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
             VALUES (?, ?, ?, CAST(unixepoch('subsec') * 1000 AS INTEGER))",
        )
        .bind(migration.version)
        .bind(migration.name)
        .bind(migration_checksum(migration.sql))
        .execute(&mut *transaction)
        .await
        .map_err(|error| database("record bootstrap migration", error))?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| database("commit state database bootstrap", error))
}

async fn claim_application_lock(
    pool: &SqlitePool,
    owner: &str,
) -> Result<Option<RecoveredWriterLock>, StateError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| database("begin application writer claim", error))?;
    let previous = sqlx::query(
        "SELECT owner, acquired_at_ms
         FROM claw_writer_lock
         WHERE singleton = 1",
    )
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| database("read previous application writer", error))?
    .map(|row| RecoveredWriterLock {
        previous_owner: row.get("owner"),
        previous_acquired_at_ms: row.get("acquired_at_ms"),
    });
    sqlx::query(
        "DELETE FROM claw_writer_lock
         WHERE singleton = 1",
    )
    .execute(&mut *transaction)
    .await
    .map_err(|error| database("clear stale application writer", error))?;
    sqlx::query(
        "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
         VALUES (1, ?, CAST(unixepoch('subsec') * 1000 AS INTEGER))",
    )
    .bind(owner)
    .execute(&mut *transaction)
    .await
    .map_err(|error| database("claim application writer lock", error))?;
    transaction
        .commit()
        .await
        .map_err(|error| database("commit application writer claim", error))?;
    Ok(previous)
}

async fn restore_application_lock(
    pool: &SqlitePool,
    owner: &str,
    previous: Option<&RecoveredWriterLock>,
) -> Result<(), StateError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| database("begin application writer restore", error))?;
    let released = sqlx::query("DELETE FROM claw_writer_lock WHERE singleton = 1 AND owner = ?")
        .bind(owner)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database("release failed application writer", error))?;
    if released.rows_affected() != 1 {
        return Err(StateError::InvalidMigrationHistory {
            reason: "application writer lock ownership changed unexpectedly".to_owned(),
        });
    }
    if let Some(previous) = previous {
        sqlx::query(
            "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
             VALUES (1, ?, ?)",
        )
        .bind(&previous.previous_owner)
        .bind(previous.previous_acquired_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database("restore previous application writer", error))?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| database("commit application writer restore", error))
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
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| database("open expected schema database", error))?;
    let build = async {
        sqlx::query(MIGRATION_TABLE_SQL)
            .execute(&mut connection)
            .await
            .map_err(|error| database("create expected migration table", error))?;
        for migration in MIGRATIONS {
            if migration.version > version {
                break;
            }
            sqlx::raw_sql(migration.sql)
                .execute(&mut connection)
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

async fn apply_migrations(pool: &SqlitePool, path: &Path) -> Result<(), StateError> {
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

    let mut connection = pool
        .acquire()
        .await
        .map_err(|error| database("acquire transactional migration connection", error))?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *connection)
        .await
        .map_err(|error| database("begin immediate schema migration", error))?;
    #[cfg(test)]
    wait_at_migration_test_barrier(path).await;
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
        validate_migration_history_connection(&mut connection, true).await?;
        sqlx::query("COMMIT")
            .execute(&mut *connection)
            .await
            .map_err(|error| database("commit schema migration", error))?;
        Ok(())
    }
    .await;
    if let Err(error) = migration_result {
        sqlx::query("ROLLBACK")
            .execute(&mut *connection)
            .await
            .map_err(|rollback| database("rollback failed schema migration", rollback))?;
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
async fn wait_at_migration_test_barrier(path: &Path) {
    let barrier = MIGRATION_TEST_BARRIER
        .lock()
        .expect("migration test barrier lock poisoned")
        .as_ref()
        .filter(|configured| configured.path == path)
        .map(|configured| {
            (
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        release.notified().await;
        MIGRATION_TEST_BARRIER
            .lock()
            .expect("migration test barrier lock poisoned")
            .take();
    }
}

#[cfg(test)]
async fn wait_at_snapshot_test_barrier(destination: &Path, temporary: &Path) {
    let barrier = SNAPSHOT_TEST_BARRIER
        .lock()
        .expect("snapshot test barrier lock poisoned")
        .as_ref()
        .filter(|configured| configured.destination == destination)
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
            .take();
    }
}

async fn ensure_destructive_backup(
    pool: &SqlitePool,
    destination: &Path,
    expected_version: i64,
) -> Result<(), StateError> {
    if path_entry_exists(destination)? {
        validate_standalone_snapshot_source(destination).await?;
        return validate_backup(destination, Some(expected_version))
            .await
            .map(|_| ());
    }
    backup_pool(
        pool,
        destination,
        expected_version,
        tokio::time::Instant::now() + MAX_CONFIGURED_TIMEOUT,
        u64::try_from(MAX_CONFIGURED_TIMEOUT.as_millis())
            .expect("maximum configured timeout fits u64"),
    )
    .await
}

async fn snapshot_database(
    source: &Path,
    source_file: &File,
    destination: &Path,
    expected_digest: Option<&[u8]>,
) -> Result<(), StateError> {
    materialize_sqlite_snapshot(source, source_file, destination, expected_digest, None).await
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
        && file_digest(source_file)? != expected_digest
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
    let mut connection = match SqliteConnection::connect_with(&options).await {
        Ok(connection) => connection,
        Err(error) => {
            return Err(invalid_backup(source, "open snapshot source", error));
        }
    };
    install_open_deadline_handler(&mut connection, deadline_state).await?;
    if let Err(error) = verify_sqlite_connection_identity(&mut connection).await {
        connection
            .close()
            .await
            .map_err(|close| invalid_backup(source, "close changed snapshot source", close))?;
        return Err(invalid_backup(
            source,
            "verify opened snapshot identity",
            error,
        ));
    }
    if let Err(error) = verify_path_identity(source, source_file) {
        connection
            .close()
            .await
            .map_err(|close| invalid_backup(source, "close changed snapshot source", close))?;
        return Err(error);
    }
    let snapshot = sqlx::query("VACUUM main INTO ?")
        .bind(destination_text)
        .execute(&mut connection)
        .await
        .map(|_| ())
        .map_err(|error| invalid_backup(source, "materialize source snapshot", error));
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
    let mut connection = match SqliteConnection::connect_with(&options).await {
        Ok(connection) => connection,
        Err(error) => {
            return Err(cleanup_failed_snapshot(
                &pinned_copy,
                invalid_backup(source, "open pinned snapshot copy", error),
            ));
        }
    };
    install_open_deadline_handler(&mut connection, deadline_state).await?;
    let snapshot = sqlx::query("VACUUM main INTO ?")
        .bind(destination_text)
        .execute(&mut connection)
        .await
        .map(|_| ())
        .map_err(|error| invalid_backup(source, "vacuum pinned snapshot copy", error));
    let close = connection
        .close()
        .await
        .map_err(|error| invalid_backup(source, "close pinned snapshot copy", error));
    let cleanup = remove_snapshot_artifacts(&pinned_copy);
    if cleanup.is_ok() {
        pinned_copy_guard.disarm();
    }
    match (snapshot, close, cleanup) {
        (Err(error), _, _) | (Ok(()), Err(error), _) | (Ok(()), Ok(()), Err(error)) => {
            Err(cleanup_failed_snapshot(destination, error))
        }
        (Ok(()), Ok(()), Ok(())) => secure_private_snapshot_file(destination),
    }
}

#[cfg(unix)]
fn pinned_copy_temporary_path(_destination: &Path) -> Result<PathBuf, StateError> {
    Ok(default_private_lock_root()?.join(format!("snapshot-{}.sqlite", writer_owner()?)))
}

#[cfg(not(unix))]
fn pinned_copy_temporary_path(destination: &Path) -> Result<PathBuf, StateError> {
    snapshot_temporary_path(destination, "pinned-source")
}

fn file_digest(file: &File) -> Result<Vec<u8>, StateError> {
    file_digest_with_deadline(file, None)
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
fn trusted_backup_manifest(snapshot: &PinnedSnapshot) -> Result<String, StateError> {
    trusted_backup_manifest_for_digest(snapshot, &file_digest(&snapshot.file)?)
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
fn trusted_backup_manifest(snapshot: &PinnedSnapshot) -> Result<String, StateError> {
    trusted_backup_manifest_for_digest(snapshot, &file_digest(&snapshot.file)?)
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
fn trusted_backup_manifest(snapshot: &PinnedSnapshot) -> Result<String, StateError> {
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
fn create_trusted_backup_seal(snapshot: &PinnedSnapshot) -> Result<TrustedBackupSeal, StateError> {
    use xattr::FileExt as _;

    snapshot.verify()?;
    let seal_id = writer_owner()?;
    let seal_path = default_private_lock_root()?.join(format!("backup-seal-{seal_id}.record"));
    let temporary = seal_path.with_file_name(format!(".backup-seal-publish-{}", writer_owner()?));
    let mut record = open_private_lock_file(&temporary, PrivateLockOpen::CreateNew)?;
    let manifest = trusted_backup_manifest(snapshot)?;
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
    if let Err(error) = writable.set_xattr(UNIX_BACKUP_SEAL_XATTR, seal_id.as_bytes()) {
        verify_path_identity(&seal_path, &record)?;
        drop(record);
        std::fs::remove_file(&seal_path)
            .map_err(|cleanup| file_error("remove unattached backup seal", &seal_path, cleanup))?;
        sync_parent_directory(&seal_path)?;
        return Err(file_error(
            "attach trusted backup seal index",
            &snapshot.path,
            error,
        ));
    }
    writable
        .sync_all()
        .map_err(|error| file_error("sync trusted backup seal index", &snapshot.path, error))?;
    snapshot.verify()?;
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
fn create_trusted_backup_seal(snapshot: &PinnedSnapshot) -> Result<TrustedBackupSeal, StateError> {
    use std::io::Write as _;

    snapshot.verify()?;
    let protected = claw_sqlite_file_control::protect_for_current_windows_user(
        trusted_backup_manifest(snapshot)?.as_bytes(),
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
fn create_trusted_backup_seal(snapshot: &PinnedSnapshot) -> Result<TrustedBackupSeal, StateError> {
    Err(StateError::BackupNotPortable {
        path: snapshot.path.clone(),
        reason: "this platform has no authenticated backup-seal provider",
    })
}

#[cfg(unix)]
fn validate_trusted_backup_seal(snapshot: &PinnedSnapshot) -> Result<Vec<u8>, StateError> {
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
    let seal_path = default_private_lock_root()?.join(format!("backup-seal-{seal_id}.record"));
    let mut record =
        open_private_lock_file(&seal_path, PrivateLockOpen::Existing).map_err(|_| {
            StateError::BackupNotPortable {
                path: snapshot.path.clone(),
                reason: "the local trusted seal record is unavailable",
            }
        })?;
    let actual = read_lock_contents(&seal_path, &mut record)?;
    let authenticated_digest = file_digest(&snapshot.file)?;
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
fn validate_trusted_backup_seal(snapshot: &PinnedSnapshot) -> Result<Vec<u8>, StateError> {
    use std::io::Read as _;

    snapshot.verify()?;
    let seal_path = windows_backup_seal_path(&snapshot.path);
    let mut seal = File::open(&seal_path).map_err(|_| StateError::BackupNotPortable {
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
    let mut protected = Vec::with_capacity(length as usize);
    seal.read_to_end(&mut protected)
        .map_err(|error| file_error("read protected Windows backup seal", &seal_path, error))?;
    let actual =
        claw_sqlite_file_control::unprotect_for_current_windows_user(&protected).map_err(|_| {
            StateError::BackupNotPortable {
                path: snapshot.path.clone(),
                reason: "backup seal belongs to a different Windows user or machine",
            }
        })?;
    let authenticated_digest = file_digest(&snapshot.file)?;
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
fn validate_trusted_backup_seal(snapshot: &PinnedSnapshot) -> Result<Vec<u8>, StateError> {
    Err(StateError::BackupNotPortable {
        path: snapshot.path.clone(),
        reason: "this platform has no authenticated backup-seal provider",
    })
}

async fn backup_pool(
    pool: &SqlitePool,
    destination: &Path,
    expected_version: i64,
    deadline: tokio::time::Instant,
    timeout_ms: u64,
) -> Result<(), StateError> {
    let timed_out = || StateError::OperationTimedOut {
        operation: "SQLite backup",
        timeout_ms,
    };
    let deadline_state = Arc::new(OpenDeadlineState {
        deadline: deadline.into_std(),
        timeout_ms,
        cancelled: std::sync::atomic::AtomicBool::new(false),
        finished: std::sync::atomic::AtomicBool::new(false),
    });
    ensure_database_artifacts_absent(destination)?;
    let destination_directory = pin_private_directory(destination)?;
    let temporary = snapshot_temporary_path(destination, "backup")?;
    ensure_database_artifacts_absent(&temporary)?;
    let temporary_text = temporary.to_str().ok_or_else(|| StateError::InvalidPath {
        path: temporary.clone(),
        reason: "backup path must be valid Unicode",
    })?;
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
    {
        let mut handle = connection
            .lock_handle()
            .await
            .map_err(|error| database("lock bounded backup connection", error))?;
        let deadline_state = Arc::clone(&deadline_state);
        handle.set_progress_handler(1_000, move || deadline_state.permits_sqlite_work());
    }
    let vacuum = claw_sqlite_file_control::vacuum_into_with_deadline(
        &mut connection,
        temporary_text,
        deadline,
    )
    .await
    .map_err(|error| database("create consistent SQLite backup", error))?;
    {
        let mut handle = connection
            .lock_handle()
            .await
            .map_err(|error| database("unlock bounded backup connection", error))?;
        handle.set_progress_handler(0, || true);
    }
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
    #[cfg(test)]
    if tokio::time::timeout_at(
        deadline,
        wait_at_snapshot_test_barrier(destination, &temporary),
    )
    .await
    .is_err()
    {
        return Err(pinned.cleanup().err().unwrap_or_else(timed_out));
    }
    let preparation = async {
        mark_backup_provenance(&pinned, Some(Arc::clone(&deadline_state))).await?;
        validate_snapshot_marker_pinned(&pinned, Some(Arc::clone(&deadline_state))).await?;
        validate_backup_pinned(
            &pinned,
            Some(expected_version),
            Some(Arc::clone(&deadline_state)),
        )
        .await
        .map(|_| ())?;
        initialize_restored_store_identity(&temporary, &pinned.file)
    }
    .await;
    match preparation {
        Ok(()) => {}
        Err(error) => {
            let error = if tokio::time::Instant::now() >= deadline {
                timed_out()
            } else {
                error
            };
            return Err(pinned.cleanup().err().unwrap_or(error));
        }
    }
    if tokio::time::Instant::now() >= deadline {
        return Err(pinned.cleanup().err().unwrap_or_else(timed_out));
    }
    let seal = match create_trusted_backup_seal(&pinned) {
        Ok(seal) => seal,
        Err(error) => {
            return Err(pinned.cleanup().err().unwrap_or(error));
        }
    };
    if tokio::time::Instant::now() >= deadline {
        let seal_cleanup = seal.cleanup();
        let error = seal_cleanup.err().unwrap_or_else(timed_out);
        return Err(pinned.cleanup().err().unwrap_or(error));
    }
    if let Err(error) = pinned.sync() {
        let seal_cleanup = seal.cleanup();
        let error = seal_cleanup.err().unwrap_or(error);
        return Err(pinned.cleanup().err().unwrap_or(error));
    }
    if tokio::time::Instant::now() >= deadline {
        let seal_cleanup = seal.cleanup();
        let error = seal_cleanup.err().unwrap_or_else(timed_out);
        return Err(pinned.cleanup().err().unwrap_or(error));
    }
    match publish_snapshot(
        pinned,
        destination,
        Some((deadline, timeout_ms)),
        &destination_directory,
    ) {
        Ok(()) => Ok(()),
        Err(error @ StateError::PublicationUncertain { .. }) => {
            Err(cleanup_failed_snapshot(&temporary, error))
        }
        Err(error) => {
            let seal_cleanup = seal.cleanup();
            Err(cleanup_failed_snapshot(
                &temporary,
                seal_cleanup.err().unwrap_or(error),
            ))
        }
    }
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
            _ => cleanup_error,
        },
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
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| invalid_backup(path, "open backup for provenance", error))?;
    install_open_deadline_handler(&mut connection, deadline_state).await?;
    snapshot.verify()?;
    install_sqlite_commit_guard(&mut connection)
        .await
        .map_err(|error| invalid_backup(path, "guard backup provenance commit", error))?;
    let result = async {
        sqlx::query("DELETE FROM claw_writer_lock")
            .execute(&mut connection)
            .await
            .map_err(|error| invalid_backup(path, "clear backup writer owner", error))?;
        sqlx::query(
            "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
             VALUES (1, ?, 0)",
        )
        .bind(SNAPSHOT_PROVENANCE_OWNER)
        .execute(&mut connection)
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
    validate_standalone_snapshot_source_pinned(&snapshot).await
}

async fn validate_standalone_snapshot_source_pinned(
    snapshot: &PinnedSnapshot,
) -> Result<Vec<u8>, StateError> {
    validate_snapshot_marker_pinned(snapshot, None).await?;
    validate_trusted_backup_seal(snapshot)
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
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| invalid_backup(path, "open standalone snapshot provenance", error))?;
    install_open_deadline_handler(&mut connection, deadline_state).await?;
    let provenance = sqlx::query_scalar::<_, String>(
        "SELECT owner FROM claw_writer_lock
         WHERE singleton = 1 AND acquired_at_ms = 0",
    )
    .fetch_optional(&mut connection)
    .await
    .map_err(|error| invalid_backup(path, "read standalone snapshot provenance", error));
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
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| invalid_backup(path, "open backup for lock cleanup", error))?;
    snapshot.verify()?;
    install_sqlite_commit_guard(&mut connection)
        .await
        .map_err(|error| invalid_backup(path, "guard backup lock cleanup", error))?;
    sqlx::query("DELETE FROM claw_writer_lock")
        .execute(&mut connection)
        .await
        .map_err(|error| invalid_backup(path, "clear backup writer lock", error))?;
    connection
        .close()
        .await
        .map_err(|error| invalid_backup(path, "close cleaned backup", error))?;
    snapshot.verify()
}

async fn validate_backup(path: &Path, expected_version: Option<i64>) -> Result<i64, StateError> {
    let snapshot = PinnedSnapshot::open(path)?;
    validate_backup_pinned(&snapshot, expected_version, None).await
}

async fn validate_backup_pinned(
    snapshot: &PinnedSnapshot,
    expected_version: Option<i64>,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<i64, StateError> {
    let path = &snapshot.path;
    snapshot.verify()?;
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .create_if_missing(false)
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| StateError::InvalidBackup {
            path: path.to_owned(),
            reason: DatabaseFailureText::render("open backup", error),
        })?;
    install_open_deadline_handler(&mut connection, deadline_state).await?;
    let result = validate_backup_connection(path, &mut connection, expected_version).await;
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
    expected_version: Option<i64>,
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
    let required_version = expected_version.unwrap_or(LATEST_SCHEMA_VERSION);
    if version != required_version {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: format!(
                "schema version {version} does not match required version {required_version}"
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
    pub(crate) fn private_lock_root() -> std::path::PathBuf {
        super::default_private_lock_root().expect("resolve canonical private lock root")
    }

    pub(crate) fn checksum(sql: &str) -> String {
        migration_checksum(sql)
    }

    pub(crate) fn fail_after_publication_once(destination: &Path) {
        let destination =
            super::resolve_database_path(destination).expect("resolve publication failpoint path");
        *FAIL_AFTER_PUBLICATION
            .lock()
            .expect("publication failpoint lock poisoned") = Some(destination);
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
            let seal_path = super::windows_backup_seal_path(&path);
            match std::fs::remove_file(&seal_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("remove prior Windows backup seal: {error}"),
            }
        }
        let snapshot = PinnedSnapshot::open(&path).expect("pin backup fixture for resealing");
        create_trusted_backup_seal(&snapshot).expect("create trusted backup fixture seal");
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
            let seal_path = super::default_private_lock_root()
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
        *super::CREATE_DESTINATION_BEFORE_PUBLICATION
            .lock()
            .expect("publication race lock poisoned") = Some(destination);
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
        *super::MIGRATION_TEST_BARRIER
            .lock()
            .expect("migration test barrier lock poisoned") = Some(super::MigrationTestBarrier {
            path,
            entered: std::sync::Arc::clone(&entered),
            release: std::sync::Arc::clone(&release),
        });
        (entered, release)
    }

    pub(crate) fn invalidate_writer_generation(store: &super::StateStore) {
        store
            .writer_generation
            .store(0, std::sync::atomic::Ordering::Release);
    }

    #[cfg(unix)]
    pub(crate) fn clear_migration_barrier() {
        super::MIGRATION_TEST_BARRIER
            .lock()
            .expect("migration test barrier lock poisoned")
            .take();
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
        *super::SNAPSHOT_TEST_BARRIER
            .lock()
            .expect("snapshot test barrier lock poisoned") = Some(super::SnapshotTestBarrier {
            destination,
            temporary: std::sync::Arc::clone(&temporary),
            entered: std::sync::Arc::clone(&entered),
            release: std::sync::Arc::clone(&release),
        });
        (temporary, entered, release)
    }

    pub(crate) fn clear_snapshot_barrier() {
        super::SNAPSHOT_TEST_BARRIER
            .lock()
            .expect("snapshot test barrier lock poisoned")
            .take();
    }

    #[cfg(windows)]
    pub(crate) fn fail_windows_source_removal_once(destination: &Path) {
        let destination =
            super::resolve_database_path(destination).expect("resolve publication failpoint path");
        *super::FAIL_WINDOWS_SOURCE_REMOVAL
            .lock()
            .expect("publication failpoint lock poisoned") = Some(destination);
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

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Connection, Row, SqliteConnection, SqlitePool};

use crate::error::database;
use crate::{
    AuthenticationRepository, DeviceRepository, SessionRepository, StateError, TaskRepository,
};

const APPLICATION_ID: i64 = 0x4754_4143;
const LATEST_SCHEMA_VERSION: i64 = 1;
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

const LATEST_SCHEMA_OBJECTS: &[(&str, &str, &str)] = &[
    (
        "index",
        "authentication_records_device_order",
        "authentication_records",
    ),
    ("index", "tasks_session_order", "tasks"),
    ("table", "authentication_records", "authentication_records"),
    ("table", "claw_schema_migrations", "claw_schema_migrations"),
    ("table", "claw_writer_lock", "claw_writer_lock"),
    ("table", "devices", "devices"),
    ("table", "sessions", "sessions"),
    ("table", "tasks", "tasks"),
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
    synchronous: SynchronousPolicy,
}

impl StoreConfig {
    /// Creates a production-oriented configuration for an explicit file.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_connections: 4,
            busy_timeout: Duration::from_secs(5),
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
        self.schema_version == self.supported_schema_version
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
    lock_path: PathBuf,
    owner: String,
    recovered_writer: Option<RecoveredWriterLock>,
    pool: SqlitePool,
    lock_file: File,
    max_connections: u32,
}

impl StateStore {
    /// Opens an explicit on-disk database, acquires its writer lock, and migrates forward.
    pub async fn open(config: StoreConfig) -> Result<Self, StateError> {
        validate_config(&config)?;
        let path = resolve_database_path(&config.path)?;
        ensure_database_file(&path)?;
        reject_hard_link(&path)?;
        inspect_database(&path, false).await?;
        prepare_windows_database_identity(&path)?;
        let lock_path = lock_path_for(&path);
        let lock_file = acquire_writer_lock(&lock_path)?;
        let owner = writer_owner()?;
        let locked_state = inspect_database(&path, false).await?;

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(config.busy_timeout)
            .synchronous(config.synchronous.sqlx());
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(config.max_connections)
            .connect_with(options)
            .await
            .map_err(|error| database("open state database", error))?;

        let mut recovered_writer = None;
        if matches!(locked_state, InspectedDatabase::Existing { .. }) {
            recovered_writer = claim_application_lock(&pool, &owner).await?;
        }
        if let Err(error) = initialize_database(&pool, &path, locked_state).await {
            if matches!(locked_state, InspectedDatabase::Existing { .. }) {
                restore_application_lock(&pool, &owner, recovered_writer.as_ref()).await?;
            }
            pool.close().await;
            return Err(error);
        }
        if matches!(locked_state, InspectedDatabase::Fresh) {
            recovered_writer = claim_application_lock(&pool, &owner).await?;
        }
        Ok(Self {
            path,
            lock_path,
            owner,
            recovered_writer,
            pool,
            lock_file,
            max_connections: config.max_connections,
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
        SessionRepository::new(&self.pool)
    }

    /// Returns the device repository.
    #[must_use]
    pub fn devices(&self) -> DeviceRepository<'_> {
        DeviceRepository::new(&self.pool)
    }

    /// Returns the authentication repository.
    #[must_use]
    pub fn authentications(&self) -> AuthenticationRepository<'_> {
        AuthenticationRepository::new(&self.pool)
    }

    /// Returns the task repository.
    #[must_use]
    pub fn tasks(&self) -> TaskRepository<'_> {
        TaskRepository::new(&self.pool)
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

    /// Creates a same-version, transactionally consistent standalone snapshot.
    pub async fn backup_to(&self, destination: impl AsRef<Path>) -> Result<(), StateError> {
        let requested_destination = destination.as_ref();
        ensure_database_artifacts_absent(requested_destination)?;
        let destination = resolve_database_path(requested_destination)?;
        let expected_version = schema_version(&self.pool).await?;
        backup_pool(&self.pool, &destination, expected_version).await
    }

    /// Restores a validated standalone backup to a destination that does not yet exist.
    pub async fn restore_backup(
        backup: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<(), StateError> {
        let backup = backup.as_ref();
        let requested_destination = destination.as_ref();
        ensure_database_artifacts_absent(requested_destination)?;
        let destination = resolve_database_path(requested_destination)?;
        ensure_database_artifacts_absent(&destination)?;
        let temporary = snapshot_temporary_path(&destination, "restore")?;
        snapshot_database(backup, &temporary).await?;
        if let Err(error) = clear_backup_writer_lock(&temporary).await {
            remove_snapshot_artifacts(&temporary)?;
            return Err(error);
        }
        if let Err(error) = validate_backup(&temporary, None).await {
            remove_snapshot_artifacts(&temporary)?;
            return Err(error);
        }
        if let Err(error) = OpenOptions::new()
            .write(true)
            .open(&temporary)
            .and_then(|file| file.sync_all())
        {
            remove_snapshot_artifacts(&temporary)?;
            return Err(file_error("sync restored snapshot", &temporary, error));
        }
        if let Err(error) = publish_snapshot(&temporary, &destination) {
            return Err(cleanup_failed_snapshot(&temporary, error));
        }
        Ok(())
    }

    /// Runs SQLite structural and referential integrity checks.
    pub async fn health(&self) -> Result<HealthReport, StateError> {
        let results = sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| database("run SQLite integrity check", error))?;
        let integrity_errors = results
            .into_iter()
            .filter(|result| result != "ok")
            .collect();
        let foreign_key_violations =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pragma_foreign_key_check")
                .fetch_one(&self.pool)
                .await
                .map_err(|error| database("run foreign key check", error))?;
        Ok(HealthReport {
            schema_version: schema_version(&self.pool).await?,
            supported_schema_version: LATEST_SCHEMA_VERSION,
            integrity_errors,
            foreign_key_violations,
            migration_errors: migration_health_errors(&self.pool).await?,
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
        let checkpoint = self.checkpoint().await?;
        release_application_lock(&self.pool, &self.owner).await?;
        self.pool.close().await;
        File::unlock(&self.lock_file)
            .map_err(|error| file_error("release writer lock", &self.lock_path, error))?;
        Ok(checkpoint)
    }
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
    if !(1..=16).contains(&config.max_connections) {
        return Err(StateError::InvalidValue {
            field: "maximum connections",
            reason: "must be between 1 and 16",
        });
    }
    if config.busy_timeout.is_zero() {
        return Err(StateError::InvalidValue {
            field: "busy timeout",
            reason: "must be greater than zero",
        });
    }
    Ok(())
}

fn resolve_database_path(path: &Path) -> Result<PathBuf, StateError> {
    if path.exists() {
        return std::fs::canonicalize(path)
            .map_err(|error| file_error("canonicalize state database", path, error));
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

fn ensure_database_file(path: &Path) -> Result<(), StateError> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map(|_| ())
        .map_err(|error| file_error("open state database file", path, error))
}

#[cfg(unix)]
fn reject_hard_link(path: &Path) -> Result<(), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    if path.exists()
        && std::fs::metadata(path)
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
fn reject_hard_link(_path: &Path) -> Result<(), StateError> {
    Ok(())
}

fn writer_owner() -> Result<String, StateError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StateError::InvalidValue {
            field: "system clock",
            reason: "must not precede the Unix epoch",
        })?
        .as_nanos();
    Ok(format!("process-{}-{timestamp}", std::process::id()))
}

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

fn database_artifacts(database: &Path) -> [PathBuf; 3] {
    [
        database.to_owned(),
        sqlite_sidecar(database, "-wal"),
        sqlite_sidecar(database, "-shm"),
    ]
}

fn ensure_database_artifacts_absent(database: &Path) -> Result<(), StateError> {
    for collision in database_artifacts(database) {
        if collision.exists() {
            return Err(StateError::BackupDestinationExists { path: collision });
        }
    }
    Ok(())
}

fn publish_snapshot(source: &Path, destination: &Path) -> Result<(), StateError> {
    ensure_database_artifacts_absent(destination)?;
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))]
    let published = rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from);
    #[cfg(windows)]
    let published = publish_windows_snapshot(source, destination);
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
        for collision in database_artifacts(destination) {
            if collision.exists() {
                return Err(StateError::BackupDestinationExists { path: collision });
            }
        }
        return Err(file_error(
            "publish SQLite snapshot without replacement",
            destination,
            error,
        ));
    }
    sync_parent_directory(destination)
}

#[cfg(windows)]
fn publish_windows_snapshot(source: &Path, destination: &Path) -> std::io::Result<()> {
    prepare_windows_published_identity(source, destination)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    std::fs::hard_link(source, destination)?;
    std::fs::remove_file(source)
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

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), StateError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| file_error("sync restore directory", parent, error))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), StateError> {
    Ok(())
}

fn lock_path_for(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_owned();
    path.push(".writer.lock");
    PathBuf::from(path)
}

#[cfg(windows)]
fn writer_identity_path_for(database: &Path) -> PathBuf {
    // An NTFS alternate stream follows the file identity across hard-link names.
    let mut path = database.as_os_str().to_owned();
    path.push(":gta-claw-writer-identity");
    PathBuf::from(path)
}

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
                        Err(error) => {
                            return Err(file_error(
                                "open comparison writer identity",
                                &stored_identity_path,
                                error,
                            ));
                        }
                    }
                }
            } else if sqlite_sidecar(&stored, "-wal").exists()
                || sqlite_sidecar(&stored, "-shm").exists()
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
    require_latest: bool,
) -> Result<InspectedDatabase, StateError> {
    if std::fs::metadata(path)
        .map_err(|error| file_error("inspect state database", path, error))?
        .len()
        == 0
    {
        return Ok(InspectedDatabase::Fresh);
    }
    let temporary = copy_database_for_inspection(path)?;
    let result = inspect_database_snapshot(&temporary, require_latest).await;
    let cleanup = remove_snapshot_artifacts(&temporary);
    match (result, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(inspected), Ok(())) => Ok(inspected),
    }
}

fn copy_database_for_inspection(path: &Path) -> Result<PathBuf, StateError> {
    let temporary = inspection_temporary_path(path)?;
    std::fs::copy(path, &temporary)
        .map_err(|error| file_error("copy database for read-only inspection", path, error))?;
    let source_wal = sqlite_sidecar(path, "-wal");
    let temporary_wal = sqlite_sidecar(&temporary, "-wal");
    if source_wal.exists()
        && let Err(error) = std::fs::copy(&source_wal, &temporary_wal)
    {
        remove_snapshot_artifacts(&temporary)?;
        return Err(file_error(
            "copy database WAL for read-only inspection",
            &source_wal,
            error,
        ));
    }
    Ok(temporary)
}

async fn inspect_database_snapshot(
    path: &Path,
    require_latest: bool,
) -> Result<InspectedDatabase, StateError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .create_if_missing(false)
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| database("inspect state database read-only", error))?;
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

async fn release_application_lock(pool: &SqlitePool, owner: &str) -> Result<(), StateError> {
    let released = sqlx::query("DELETE FROM claw_writer_lock WHERE singleton = 1 AND owner = ?")
        .bind(owner)
        .execute(pool)
        .await
        .map_err(|error| database("release application writer lock", error))?;
    if released.rows_affected() != 1 {
        return Err(StateError::InvalidMigrationHistory {
            reason: "application writer lock ownership changed unexpectedly".to_owned(),
        });
    }
    Ok(())
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
    if current_version == LATEST_SCHEMA_VERSION {
        validate_latest_schema_objects(connection).await?;
    }
    if require_latest && current_version != LATEST_SCHEMA_VERSION {
        return Err(StateError::InvalidMigrationHistory {
            reason: format!(
                "schema version {current_version} is not the required version {LATEST_SCHEMA_VERSION}"
            ),
        });
    }
    Ok(current_version)
}

async fn validate_latest_schema_objects(
    connection: &mut SqliteConnection,
) -> Result<(), StateError> {
    let rows = sqlx::query(
        "SELECT type, name, tbl_name
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
           AND type IN ('index', 'table', 'trigger', 'view')
         ORDER BY type, name",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| database("read canonical schema objects", error))?;
    let mut actual = Vec::with_capacity(rows.len());
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
        actual.push((kind, name, table));
    }
    let expected = LATEST_SCHEMA_OBJECTS
        .iter()
        .map(|&(kind, name, table)| (kind.to_owned(), name.to_owned(), table.to_owned()))
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(StateError::InvalidMigrationHistory {
            reason: "database schema objects do not match the embedded migration history"
                .to_owned(),
        });
    }
    Ok(())
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
    let mut connection = pool
        .acquire()
        .await
        .map_err(|error| database("acquire migration inspection connection", error))?;
    let mut current_version = validate_migration_history_connection(&mut connection, false).await?;
    drop(connection);
    for migration in MIGRATIONS {
        if migration.version <= current_version {
            continue;
        }
        if migration.destructive {
            let destination = destructive_backup_path(path, current_version, migration.version);
            ensure_destructive_backup(pool, &destination, current_version).await?;
        }
        let mut transaction = pool
            .begin()
            .await
            .map_err(|error| database("begin schema migration", error))?;
        sqlx::raw_sql(migration.sql)
            .execute(&mut *transaction)
            .await
            .map_err(|error| database("apply schema migration", error))?;
        sqlx::query(
            "INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
             VALUES (?, ?, ?, CAST(unixepoch('subsec') * 1000 AS INTEGER))",
        )
        .bind(migration.version)
        .bind(migration.name)
        .bind(migration_checksum(migration.sql))
        .execute(&mut *transaction)
        .await
        .map_err(|error| database("record schema migration", error))?;
        transaction
            .commit()
            .await
            .map_err(|error| database("commit schema migration", error))?;
        current_version = migration.version;
    }
    Ok(())
}

async fn ensure_destructive_backup(
    pool: &SqlitePool,
    destination: &Path,
    expected_version: i64,
) -> Result<(), StateError> {
    if destination.exists() {
        return validate_backup(destination, Some(expected_version))
            .await
            .map(|_| ());
    }
    backup_pool(pool, destination, expected_version).await
}

async fn snapshot_database(source: &Path, destination: &Path) -> Result<(), StateError> {
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
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| invalid_backup(source, "open snapshot source", error))?;
    let snapshot = sqlx::query("VACUUM main INTO ?")
        .bind(destination_text)
        .execute(&mut connection)
        .await
        .map(|_| ())
        .map_err(|error| invalid_backup(source, "materialize source snapshot", error));
    let close = connection
        .close()
        .await
        .map_err(|error| invalid_backup(source, "close snapshot source", error));
    let result = match (snapshot, close) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    };
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(cleanup_failed_snapshot(destination, error)),
    }
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

async fn backup_pool(
    pool: &SqlitePool,
    destination: &Path,
    expected_version: i64,
) -> Result<(), StateError> {
    ensure_database_artifacts_absent(destination)?;
    let temporary = snapshot_temporary_path(destination, "backup")?;
    ensure_database_artifacts_absent(&temporary)?;
    let temporary_text = temporary.to_str().ok_or_else(|| StateError::InvalidPath {
        path: temporary.clone(),
        reason: "backup path must be valid Unicode",
    })?;
    if let Err(error) = sqlx::query("VACUUM main INTO ?")
        .bind(temporary_text)
        .execute(pool)
        .await
        .map_err(|error| database("create consistent SQLite backup", error))
    {
        return Err(cleanup_failed_snapshot(&temporary, error));
    }
    let result = async {
        clear_backup_writer_lock(&temporary).await?;
        validate_backup(&temporary, Some(expected_version))
            .await
            .map(|_| ())?;
        OpenOptions::new()
            .write(true)
            .open(&temporary)
            .and_then(|file| file.sync_all())
            .map_err(|error| file_error("sync SQLite backup", &temporary, error))?;
        publish_snapshot(&temporary, destination)
    }
    .await;
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(cleanup_failed_snapshot(&temporary, error)),
    }
}

fn cleanup_failed_snapshot(path: &Path, error: StateError) -> StateError {
    match remove_snapshot_artifacts(path) {
        Ok(()) => error,
        Err(cleanup_error) => cleanup_error,
    }
}

async fn clear_backup_writer_lock(path: &Path) -> Result<(), StateError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| invalid_backup(path, "open backup for lock cleanup", error))?;
    sqlx::query("DELETE FROM claw_writer_lock")
        .execute(&mut connection)
        .await
        .map_err(|error| invalid_backup(path, "clear backup writer lock", error))?;
    connection
        .close()
        .await
        .map_err(|error| invalid_backup(path, "close cleaned backup", error))
}

async fn validate_backup(path: &Path, expected_version: Option<i64>) -> Result<i64, StateError> {
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
    let result = validate_backup_connection(path, &mut connection, expected_version).await;
    let close = connection
        .close()
        .await
        .map_err(|error| invalid_backup(path, "close backup", error));
    match (result, close) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(version), Ok(())) => Ok(version),
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

async fn migration_health_errors(pool: &SqlitePool) -> Result<Vec<String>, StateError> {
    let mut connection = pool
        .acquire()
        .await
        .map_err(|error| database("acquire migration health connection", error))?;
    match validate_migration_history_connection(&mut connection, true).await {
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

    use super::{
        StateStore, copy_database_for_inspection, database, migration_checksum,
        remove_snapshot_artifacts,
    };
    use crate::StateError;

    pub(crate) fn pool(store: &StateStore) -> &SqlitePool {
        &store.pool
    }

    pub(crate) fn checksum(sql: &str) -> String {
        migration_checksum(sql)
    }

    pub(crate) async fn journal_mode(path: &Path) -> Result<String, StateError> {
        let temporary = copy_database_for_inspection(path)?;
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
}

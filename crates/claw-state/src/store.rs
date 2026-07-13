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
}

impl HealthReport {
    /// Returns whether the database is structurally sound and supported.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.schema_version == self.supported_schema_version
            && self.integrity_errors.is_empty()
            && self.foreign_key_violations == 0
    }
}

/// Exclusive writer access to one durable SQLite database.
pub struct StateStore {
    path: PathBuf,
    lock_path: PathBuf,
    lock_file: File,
    owner: String,
    pool: SqlitePool,
    max_connections: u32,
}

impl StateStore {
    /// Opens an explicit on-disk database, acquires its writer lock, and migrates forward.
    pub async fn open(config: StoreConfig) -> Result<Self, StateError> {
        validate_config(&config)?;
        let path = resolve_database_path(&config.path)?;
        reject_hard_link(&path)?;
        let lock_path = lock_path_for(&path);
        let lock_file = acquire_writer_lock(&lock_path)?;
        let owner = writer_owner()?;
        let lock_table_exists = preflight_database(&path, &lock_path).await?;

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

        if lock_table_exists {
            claim_application_lock(&pool, &owner, &lock_path).await?;
        }
        if let Err(error) = initialize_database(&pool, &path).await {
            if lock_table_exists {
                release_application_lock(&pool, &owner).await?;
            }
            pool.close().await;
            return Err(error);
        }
        if !lock_table_exists {
            claim_application_lock(&pool, &owner, &lock_path).await?;
        }
        Ok(Self {
            path,
            lock_path,
            lock_file,
            owner,
            pool,
            max_connections: config.max_connections,
        })
    }

    /// Returns the durable database path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
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
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(StateError::BackupDestinationExists {
                path: destination.to_owned(),
            });
        }
        let expected_version = schema_version(&self.pool).await?;
        backup_pool(&self.pool, destination, expected_version).await
    }

    /// Restores a validated standalone backup to a destination that does not yet exist.
    pub async fn restore_backup(
        backup: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<(), StateError> {
        let backup = backup.as_ref();
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(StateError::BackupDestinationExists {
                path: destination.to_owned(),
            });
        }
        validate_backup(backup, None).await?;
        let temporary = restore_temporary_path(destination)?;
        let mut source =
            File::open(backup).map_err(|error| file_error("open backup", backup, error))?;
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| file_error("create restored database", &temporary, error))?;
        if let Err(error) = std::io::copy(&mut source, &mut target) {
            drop(target);
            let _ = std::fs::remove_file(&temporary);
            return Err(file_error("copy restored database", &temporary, error));
        }
        if let Err(error) = target.sync_all() {
            drop(target);
            let _ = std::fs::remove_file(&temporary);
            return Err(file_error("sync restored database", &temporary, error));
        }
        drop(target);
        if let Err(error) = validate_backup(&temporary, None).await {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = std::fs::hard_link(&temporary, destination) {
            let _ = std::fs::remove_file(&temporary);
            return Err(file_error(
                "publish restored database without replacement",
                destination,
                error,
            ));
        }
        std::fs::remove_file(&temporary)
            .map_err(|error| file_error("remove restore temporary file", &temporary, error))?;
        sync_parent_directory(destination)
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

fn restore_temporary_path(destination: &Path) -> Result<PathBuf, StateError> {
    let owner = writer_owner()?;
    let file_name = destination
        .file_name()
        .ok_or_else(|| StateError::InvalidPath {
            path: destination.to_owned(),
            reason: "restore destination must include a file name",
        })?
        .to_string_lossy();
    Ok(destination.with_file_name(format!(".{file_name}.{owner}.restore-tmp")))
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

async fn preflight_database(path: &Path, lock_path: &Path) -> Result<bool, StateError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true);
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| database("preflight state database", error))?;
    let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
        .fetch_one(&mut connection)
        .await
        .map_err(|error| database("read SQLite application id", error))?;
    if application_id == 0 {
        let existing_objects = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'",
        )
        .fetch_one(&mut connection)
        .await
        .map_err(|error| database("inspect unclaimed SQLite database", error))?;
        if existing_objects != 0 {
            return Err(StateError::InvalidValue {
                field: "SQLite application id",
                reason: "unclaimed database is not empty",
            });
        }
        sqlx::query("PRAGMA application_id = 1196704067")
            .execute(&mut connection)
            .await
            .map_err(|error| database("set SQLite application id", error))?;
    } else if application_id != APPLICATION_ID {
        return Err(StateError::InvalidValue {
            field: "SQLite application id",
            reason: "database belongs to another application",
        });
    }
    let lock_table_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema
            WHERE type = 'table' AND name = 'claw_writer_lock'
        )",
    )
    .fetch_one(&mut connection)
    .await
    .map_err(|error| database("inspect application writer lock schema", error))?;
    if lock_table_exists {
        let lock_held = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM claw_writer_lock WHERE singleton = 1)",
        )
        .fetch_one(&mut connection)
        .await
        .map_err(|error| database("inspect application writer lock", error))?;
        if lock_held {
            return Err(StateError::StoreLocked {
                path: lock_path.to_owned(),
            });
        }
    }
    connection
        .close()
        .await
        .map_err(|error| database("close database preflight", error))?;
    Ok(lock_table_exists)
}

async fn initialize_database(pool: &SqlitePool, path: &Path) -> Result<(), StateError> {
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

    sqlx::query(MIGRATION_TABLE_SQL)
        .execute(pool)
        .await
        .map_err(|error| database("create migration table", error))?;
    apply_migrations(pool, path).await
}

async fn claim_application_lock(
    pool: &SqlitePool,
    owner: &str,
    lock_path: &Path,
) -> Result<(), StateError> {
    let result = sqlx::query(
        "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
         VALUES (1, ?, CAST(unixepoch('subsec') * 1000 AS INTEGER))",
    )
    .bind(owner)
    .execute(pool)
    .await;
    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(details))
            if details.message().contains("UNIQUE constraint failed") =>
        {
            Err(StateError::StoreLocked {
                path: lock_path.to_owned(),
            })
        }
        Err(error) => Err(database("claim application writer lock", error)),
    }
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

async fn apply_migrations(pool: &SqlitePool, path: &Path) -> Result<(), StateError> {
    let applied = sqlx::query(
        "SELECT version, name, checksum
         FROM claw_schema_migrations
         ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .map_err(|error| database("read migration history", error))?;

    for (index, row) in applied.iter().enumerate() {
        let version: i64 = row.get("version");
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
        let name: String = row.get("name");
        if name != migration.name {
            return Err(StateError::InvalidMigrationHistory {
                reason: format!(
                    "migration {version} is named {name}, expected {}",
                    migration.name
                ),
            });
        }
        let applied_checksum: String = row.get("checksum");
        let embedded_checksum = migration_checksum(migration.sql);
        if applied_checksum != embedded_checksum {
            return Err(StateError::MigrationChecksumDrift {
                version,
                applied: applied_checksum,
                embedded: embedded_checksum,
            });
        }
    }

    let mut current_version =
        i64::try_from(applied.len()).expect("applied migration count fits i64");
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
    if destination.exists() {
        return Err(StateError::BackupDestinationExists {
            path: destination.to_owned(),
        });
    }
    let destination_text = destination
        .to_str()
        .ok_or_else(|| StateError::InvalidPath {
            path: destination.to_owned(),
            reason: "backup path must be valid Unicode",
        })?;
    sqlx::query("VACUUM main INTO ?")
        .bind(destination_text)
        .execute(pool)
        .await
        .map_err(|error| database("create consistent SQLite backup", error))?;
    clear_backup_writer_lock(destination).await?;
    validate_backup(destination, Some(expected_version))
        .await
        .map(|_| ())
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
    let check = sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
        .fetch_all(&mut connection)
        .await
        .map_err(|error| invalid_backup(path, "check backup integrity", error))?;
    if check.as_slice() != ["ok"] {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: check.join("; "),
        });
    }
    let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
        .fetch_one(&mut connection)
        .await
        .map_err(|error| invalid_backup(path, "read backup application id", error))?;
    if application_id != APPLICATION_ID {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: "application id does not match GTA Claw".to_owned(),
        });
    }
    let version = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(MAX(version), 0) FROM claw_schema_migrations",
    )
    .fetch_one(&mut connection)
    .await
    .map_err(|error| invalid_backup(path, "read backup schema version", error))?;
    if expected_version.is_some_and(|expected| expected != version) {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: format!(
                "schema version {version} does not match source version {}",
                expected_version.expect("checked as some")
            ),
        });
    }
    connection
        .close()
        .await
        .map_err(|error| invalid_backup(path, "close backup", error))?;
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

async fn schema_version(pool: &SqlitePool) -> Result<i64, StateError> {
    sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM claw_schema_migrations")
        .fetch_one(pool)
        .await
        .map_err(|error| database("read schema version", error))
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
    use sqlx::SqlitePool;

    use super::{StateStore, migration_checksum};

    pub(crate) fn pool(store: &StateStore) -> &SqlitePool {
        &store.pool
    }

    pub(crate) fn checksum(sql: &str) -> String {
        migration_checksum(sql)
    }
}

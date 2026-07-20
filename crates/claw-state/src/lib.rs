//! Durable, explicit-path SQLite state for GTA Claw.
//!
//! This crate owns persistence mechanics only. It does not claim upstream
//! OpenClaw parity or wire a runtime to the stored records.

mod error;
mod model;
mod repository;
mod store;

pub use error::{DatabaseFailure, StateError};
pub use model::{
    AuthenticationId, AuthenticationRecord, AuthenticationStatus, DeviceId, DeviceRecord, Page,
    PageCursor, PageRequest, SessionRecord, SessionStatus, TaskId, TaskRecord, TaskStatus,
    TimestampMs,
};
pub use repository::{
    AuthenticationRepository, DeviceRepository, SessionRepository, TaskRepository,
};
pub use store::{
    CheckpointReport, HealthReport, RecoveredWriterLock, StateStore, StoreConfig, StoreSettings,
    SynchronousPolicy,
};

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs::{self, OpenOptions};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};
    #[cfg(windows)]
    use std::{
        collections::HashSet,
        sync::{LazyLock, Mutex},
    };

    use claw_domain::SessionId;
    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::{Connection, Executor, Row, SqliteConnection};
    use tempfile::TempDir;

    use super::*;
    use crate::store::test_support;

    #[cfg(windows)]
    static SECURED_TEST_DIRECTORIES: LazyLock<Mutex<HashSet<PathBuf>>> =
        LazyLock::new(|| Mutex::new(HashSet::new()));

    struct ChildGuard {
        child: Option<Child>,
    }

    impl ChildGuard {
        fn new(child: Child) -> Self {
            Self { child: Some(child) }
        }

        fn child_mut(&mut self) -> &mut Child {
            self.child.as_mut().expect("child guard still owns process")
        }

        #[cfg(unix)]
        fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
            self.child_mut().try_wait()
        }

        #[cfg(unix)]
        fn kill(&mut self) -> std::io::Result<()> {
            self.child_mut().kill()
        }

        #[cfg(unix)]
        fn wait(&mut self) -> std::io::Result<ExitStatus> {
            self.child
                .take()
                .expect("child guard still owns process")
                .wait()
        }

        fn kill_and_wait(mut self) -> std::io::Result<ExitStatus> {
            let mut child = self.child.take().expect("child guard still owns process");
            let kill = child.kill();
            let wait = child.wait();
            match (kill, wait) {
                (_, Ok(status)) => Ok(status),
                (Ok(()), Err(error)) | (Err(error), Err(_)) => Err(error),
            }
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = &mut self.child {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn database_path(directory: &TempDir, name: &str) -> PathBuf {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("secure Unix test state directory");
        }
        #[cfg(windows)]
        secure_windows_test_directory(directory.path());
        directory.path().join(name)
    }

    #[cfg(windows)]
    fn secure_windows_test_directory(path: &Path) {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_DAC, WRITE_OWNER,
        };

        let path = fs::canonicalize(path).expect("canonicalize Windows test state directory");
        let mut secured = SECURED_TEST_DIRECTORIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if secured.contains(&path) && test_support::state_directory_is_private(&path) {
            return;
        }
        secured.remove(&path);
        let directory = fs::OpenOptions::new()
            .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .expect("open Windows test directory for native security");
        claw_sqlite_file_control::secure_new_windows_file(&directory)
            .expect("apply native protected DACL to Windows test directory");
        assert!(
            test_support::state_directory_is_private(&path),
            "Windows test fixture must satisfy the production private-directory contract"
        );
        secured.insert(path);
    }

    fn make_private_file(_path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(_path, fs::Permissions::from_mode(0o600))
                .expect("make test database private");
        }
        #[cfg(windows)]
        test_support::secure_windows_file_fixture(_path);
    }

    #[cfg(unix)]
    fn create_private_empty_file(path: &Path) {
        fs::File::create(path).expect("create private empty test file");
        make_private_file(path);
    }

    fn sidecar(path: &Path, suffix: &str) -> PathBuf {
        let mut value: OsString = path.as_os_str().to_owned();
        value.push(suffix);
        PathBuf::from(value)
    }

    fn database_artifact_bytes(path: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        [
            path.to_owned(),
            sidecar(path, "-wal"),
            sidecar(path, "-shm"),
            sidecar(path, "-journal"),
        ]
        .into_iter()
        .map(|artifact| {
            let bytes = fs::read(&artifact).ok();
            (artifact, bytes)
        })
        .collect()
    }

    fn assert_database_artifacts_unchanged(
        before: &[(PathBuf, Option<Vec<u8>>)],
        after: &[(PathBuf, Option<Vec<u8>>)],
    ) {
        assert_eq!(before.len(), after.len());
        for ((before_path, before_bytes), (after_path, after_bytes)) in before.iter().zip(after) {
            assert_eq!(before_path, after_path);
            assert!(
                before_bytes == after_bytes,
                "database artifact changed: {} (before length {:?}, after length {:?})",
                before_path.display(),
                before_bytes.as_ref().map(Vec::len),
                after_bytes.as_ref().map(Vec::len)
            );
        }
    }

    async fn execute_direct(path: &Path, sql: &'static str) {
        let options = SqliteConnectOptions::new().filename(path);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("open database directly");
        sqlx::raw_sql(sql)
            .execute(&mut connection)
            .await
            .expect("execute direct SQL");
        connection.close().await.expect("close direct database");
    }

    async fn persisted_writer(path: &Path) -> Option<(String, i64)> {
        let options = SqliteConnectOptions::new().filename(path).read_only(true);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("inspect persisted writer");
        let row =
            sqlx::query("SELECT owner, acquired_at_ms FROM claw_writer_lock WHERE singleton = 1")
                .fetch_optional(&mut connection)
                .await
                .expect("read persisted writer");
        connection.close().await.expect("close writer inspection");
        row.map(|row| {
            use sqlx::Row as _;
            (row.get("owner"), row.get("acquired_at_ms"))
        })
    }

    #[cfg(unix)]
    fn set_unix_lock_identity(database: &Path, lock_path: &Path) {
        use std::os::unix::fs::MetadataExt as _;
        use xattr::FileExt as _;

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(database)
            .expect("open database for lock identity");
        let metadata = file.metadata().expect("read database identity");
        let encoded = format!(
            "v1\n{}\n{}\n{}",
            metadata.dev(),
            metadata.ino(),
            lock_path.display()
        );
        file.set_xattr("user.gta-claw.writer-lock-path", encoded.as_bytes())
            .expect("set database lock identity");
    }

    #[cfg(unix)]
    fn unix_lock_path(database: &Path) -> PathBuf {
        use xattr::FileExt as _;

        let file = fs::File::open(database).expect("open database lock identity");
        let value = file
            .get_xattr("user.gta-claw.writer-lock-path")
            .expect("read database lock identity")
            .expect("database lock identity exists");
        let value = String::from_utf8(value).expect("lock identity is UTF-8");
        let fields = value.lines().collect::<Vec<_>>();
        let path = match fields.first().copied() {
            Some("v1") => fields.get(3),
            Some("v2") => fields.get(6),
            version => panic!("unsupported test lock identity version: {version:?}"),
        }
        .expect("lock identity contains path");
        PathBuf::from(path)
    }

    #[cfg(unix)]
    fn unix_lock_file_name(database: &Path, token: &str) -> String {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = fs::metadata(database).expect("read database identity");
        format!("dev-{}-ino-{}-{token}.lock", metadata.dev(), metadata.ino())
    }

    async fn assert_restore_rejected(source: &Path, destination: &Path) {
        let error = StateStore::restore_backup(source, destination)
            .await
            .expect_err("invalid restore source is rejected");
        assert!(
            matches!(error, StateError::InvalidBackup { .. }),
            "unexpected restore error: {error:?}"
        );
        for artifact in [
            destination.to_owned(),
            sidecar(destination, "-wal"),
            sidecar(destination, "-shm"),
            sidecar(destination, "-journal"),
        ] {
            assert!(
                !artifact.exists(),
                "restore rejection left artifact {}",
                artifact.display()
            );
        }
    }

    fn schema_drift_cases() -> [(&'static str, &'static str); 4] {
        [
            (
                "foreign-key-definition",
                "PRAGMA foreign_keys = OFF;
                 DROP INDEX tasks_session_order;
                 DROP TABLE tasks;
                 CREATE TABLE tasks (
                    id TEXT PRIMARY KEY NOT NULL,
                    session_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (length(trim(kind)) > 0),
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')
                    ),
                    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
                    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
                    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1)
                 ) STRICT;
                 CREATE INDEX tasks_session_order ON tasks(session_id, created_at_ms, id)",
            ),
            (
                "column-definition",
                "ALTER TABLE tasks ADD COLUMN unexpected TEXT",
            ),
            (
                "constraint-definition",
                "PRAGMA foreign_keys = OFF;
                 DROP INDEX tasks_session_order;
                 DROP TABLE tasks;
                 CREATE TABLE tasks (
                    id TEXT PRIMARY KEY NOT NULL,
                    session_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (length(trim(kind)) > 0),
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
                    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
                    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                        ON UPDATE RESTRICT ON DELETE RESTRICT
                 ) STRICT;
                 CREATE INDEX tasks_session_order ON tasks(session_id, created_at_ms, id)",
            ),
            (
                "index-definition",
                "DROP INDEX tasks_session_order;
                 CREATE INDEX tasks_session_order ON tasks(session_id, id, created_at_ms)",
            ),
        ]
    }

    fn timestamp(value: i64) -> TimestampMs {
        TimestampMs::new(value).expect("test timestamp is valid")
    }

    fn session(id: &str, created_at: i64) -> SessionRecord {
        SessionRecord::new(
            SessionId::new(id).expect("test session id is valid"),
            timestamp(created_at),
        )
    }

    fn device(id: &str, created_at: i64) -> DeviceRecord {
        DeviceRecord::new(
            DeviceId::new(id).expect("test device id is valid"),
            format!("Device {id}"),
            timestamp(created_at),
        )
        .expect("test device is valid")
    }

    fn authentication(id: &str, device_id: &DeviceId, created_at: i64) -> AuthenticationRecord {
        AuthenticationRecord::pending(
            AuthenticationId::new(id).expect("test authentication id is valid"),
            device_id.clone(),
            "github",
            timestamp(created_at),
        )
        .expect("test authentication is valid")
    }

    fn task(id: &str, session_id: &SessionId, created_at: i64) -> TaskRecord {
        TaskRecord::new(
            TaskId::new(id).expect("test task id is valid"),
            session_id.clone(),
            "agent-turn",
            format!("payload-{id}"),
            timestamp(created_at),
        )
        .expect("test task is valid")
    }

    async fn open(path: &Path) -> StateStore {
        StateStore::open(StoreConfig::new(path))
            .await
            .expect("state store opens")
    }

    async fn wait_for_cleanup_absence(paths: &[&Path]) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while paths.iter().any(|path| match path.try_exists() {
                Ok(exists) => exists,
                Err(error) if matches!(error.raw_os_error(), Some(5) | Some(32) | Some(33)) => true,
                Err(error) => panic!("inspect cleanup artifact {}: {error}", path.display()),
            }) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached cleanup removes staging artifacts");
    }

    #[tokio::test]
    async fn fresh_database_applies_migrations_and_pragmas_on_unicode_path() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "状态 store.sqlite");
        let store = StateStore::open(
            StoreConfig::new(&path)
                .with_max_connections(1)
                .with_busy_timeout(Duration::from_millis(275))
                .with_synchronous(SynchronousPolicy::Full),
        )
        .await
        .expect("fresh database opens");

        let settings = store.settings().await.expect("settings can be read");
        assert_eq!(settings.journal_mode, "wal");
        assert!(settings.foreign_keys);
        assert_eq!(settings.busy_timeout_ms, 275);
        assert_eq!(settings.synchronous, 2);
        assert_eq!(settings.max_connections, 1);
        let health = store.health().await.expect("health can be read");
        assert!(health.is_healthy());
        assert!(path.is_file());
        store.close().await.expect("store closes cleanly");
    }

    #[tokio::test]
    async fn long_valid_database_name_reopens_without_oversized_inspection_path() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, &format!("{}.sqlite", "a".repeat(230)));
        let backup = database_path(&directory, &format!("{}.sqlite", "b".repeat(230)));
        let restored = database_path(&directory, &format!("{}.sqlite", "c".repeat(230)));
        open(&path)
            .await
            .close()
            .await
            .expect("long-name store closes");
        let reopened = open(&path).await;
        assert!(
            reopened
                .health()
                .await
                .expect("long-name health")
                .is_healthy()
        );
        reopened
            .backup_to(&backup)
            .await
            .expect("long-name backup succeeds");
        reopened
            .close()
            .await
            .expect("long-name reopened store closes");
        StateStore::restore_backup(&backup, &restored)
            .await
            .expect("long-name restore succeeds");
        open(&restored)
            .await
            .close()
            .await
            .expect("long-name restored store opens");
    }

    #[tokio::test]
    async fn canonical_version_zero_prefix_migrates_before_writer_claim() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "version-zero.sqlite");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("create version-zero database");
        sqlx::raw_sql(
            "PRAGMA application_id = 1196704067;
             CREATE TABLE IF NOT EXISTS claw_schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
                name TEXT NOT NULL,
                checksum TEXT NOT NULL CHECK (length(checksum) = 64),
                applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
             ) STRICT",
        )
        .execute(&mut connection)
        .await
        .expect("create canonical version-zero prefix");
        connection
            .close()
            .await
            .expect("close version-zero database");
        make_private_file(&path);

        let store = StateStore::open(StoreConfig::new(&path))
            .await
            .expect("version-zero prefix migrates");
        assert!(store.health().await.expect("migrated health").is_healthy());
        assert!(store.recovered_writer().is_none());
        store.close().await.expect("migrated store closes");
    }

    #[tokio::test]
    async fn version_one_store_upgrades_to_pagination_indexes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "version-one-upgrade.sqlite");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("create version-one database");
        sqlx::raw_sql(
            "PRAGMA application_id = 1196704067;
             CREATE TABLE claw_schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
                name TEXT NOT NULL,
                checksum TEXT NOT NULL CHECK (length(checksum) = 64),
                applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
             ) STRICT",
        )
        .execute(&mut connection)
        .await
        .expect("create version-one migration prefix");
        sqlx::raw_sql(include_str!("../migrations/0001_initial.sql"))
            .execute(&mut connection)
            .await
            .expect("apply immutable version-one schema");
        sqlx::query(
            "INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
             VALUES (1, 'initial', ?, 1)",
        )
        .bind(test_support::checksum(include_str!(
            "../migrations/0001_initial.sql"
        )))
        .execute(&mut connection)
        .await
        .expect("record immutable version-one migration");
        sqlx::query("PRAGMA user_version = 1")
            .execute(&mut connection)
            .await
            .expect("set version-one user version");
        connection.close().await.expect("close version-one seed");
        make_private_file(&path);
        test_support::initialize_store_identity_fixture(&path);

        let store = open(&path).await;
        let health = store.health().await.expect("upgraded store health");
        assert_eq!(health.schema_version, 2);
        assert!(health.is_healthy());
        for index in ["sessions_creation_order", "devices_creation_order"] {
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'index' AND name = ?",
                )
                .bind(index)
                .fetch_one(test_support::pool(&store))
                .await
                .expect("inspect pagination index"),
                1
            );
        }
        store.close().await.expect("upgraded store closes");
    }

    #[tokio::test]
    async fn sealed_version_one_backup_restores_then_migrates_forward() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let backup = database_path(&directory, "version-one-backup.sqlite");
        let destination = database_path(&directory, "version-one-restored.sqlite");
        let options = SqliteConnectOptions::new()
            .filename(&backup)
            .create_if_missing(true);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("create version-one backup");
        sqlx::raw_sql(
            "PRAGMA application_id = 1196704067;
             CREATE TABLE claw_schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
                name TEXT NOT NULL,
                checksum TEXT NOT NULL CHECK (length(checksum) = 64),
                applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
             ) STRICT",
        )
        .execute(&mut connection)
        .await
        .expect("create version-one backup prefix");
        sqlx::raw_sql(include_str!("../migrations/0001_initial.sql"))
            .execute(&mut connection)
            .await
            .expect("apply version-one backup schema");
        sqlx::query(
            "INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
             VALUES (1, 'initial', ?, 1)",
        )
        .bind(test_support::checksum(include_str!(
            "../migrations/0001_initial.sql"
        )))
        .execute(&mut connection)
        .await
        .expect("record version-one backup migration");
        sqlx::query("PRAGMA user_version = 1")
            .execute(&mut connection)
            .await
            .expect("set version-one backup user version");
        sqlx::query(
            "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
             VALUES (1, 'gta-claw-standalone-snapshot-v1', 0)",
        )
        .execute(&mut connection)
        .await
        .expect("mark version-one standalone snapshot");
        sqlx::query(
            "INSERT INTO sessions(id, status, created_at_ms, updated_at_ms, version)
             VALUES('version-one-record', 'active', 2, 2, 1)",
        )
        .execute(&mut connection)
        .await
        .expect("seed version-one backup record");
        connection.close().await.expect("close version-one backup");
        make_private_file(&backup);
        test_support::reseal_backup_fixture(&backup);

        StateStore::restore_backup(&backup, &destination)
            .await
            .expect("restore supported version-one backup");
        let restored = open(&destination).await;
        let health = restored.health().await.expect("restored migration health");
        assert_eq!(health.schema_version, 2);
        assert!(health.is_healthy());
        assert_eq!(
            restored
                .sessions()
                .get(&SessionId::new("version-one-record").expect("valid version-one id"))
                .await
                .expect("read restored version-one record")
                .map(|record| record.id),
            Some(SessionId::new("version-one-record").expect("valid version-one id"))
        );
        restored.close().await.expect("restored store closes");
    }

    #[tokio::test]
    async fn migration_transaction_excludes_external_schema_writer() {
        const OVERALL_TIMEOUT: Duration = Duration::from_secs(5);

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "migration-race.sqlite");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .busy_timeout(Duration::from_millis(50));
        let mut external = SqliteConnection::connect_with(&options)
            .await
            .expect("create migration race database");
        sqlx::raw_sql(
            "PRAGMA application_id = 1196704067;
             CREATE TABLE IF NOT EXISTS claw_schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
                name TEXT NOT NULL,
                checksum TEXT NOT NULL CHECK (length(checksum) = 64),
                applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
             ) STRICT",
        )
        .execute(&mut external)
        .await
        .expect("create version-zero migration race prefix");
        make_private_file(&path);
        let (entered, release) = test_support::set_migration_barrier(&path);
        let open_path = path.clone();
        let mut opener = Some(tokio::spawn(async move {
            StateStore::open(StoreConfig::new(open_path)).await
        }));
        let deadline = tokio::time::Instant::now() + OVERALL_TIMEOUT;
        let choreography = tokio::time::timeout_at(deadline, async {
            tokio::select! {
                () = entered.notified() => {}
                result = opener.as_mut().expect("migration opener exists") => {
                    opener = None;
                    let diagnostic = match result {
                        Ok(Ok(store)) => {
                            let close = store.close().await;
                            format!("opener succeeded early; close result: {close:?}")
                        }

                        Ok(Err(error)) => format!("opener failed early: {error}"),
                        Err(error) => format!("opener task failed early: {error}"),
                    };
                    return Err(diagnostic);
                }
            }

            let drift = external
                .execute("ALTER TABLE claw_schema_migrations ADD COLUMN rogue TEXT")
                .await;
            release.notify_one();
            let store = opener
                .take()
                .expect("migration opener remains after barrier")
                .await
                .map_err(|error| format!("migration opener task failed: {error}"))?
                .map_err(|error| format!("migration opener failed: {error}"))?;
            let drift = drift
                .expect_err("external schema drift must be rejected by the migration transaction");
            if drift.as_database_error().is_none() {
                return Err(format!(
                    "schema drift returned a non-database error: {drift}"
                ));
            }
            external
                .close()
                .await
                .map_err(|error| format!("close external writer: {error}"))?;
            if !store
                .health()
                .await
                .map_err(|error| format!("inspect migrated health: {error}"))?
                .is_healthy()
            {
                return Err("migrated store reported unhealthy".to_owned());
            }
            store
                .close()
                .await
                .map_err(|error| format!("close migrated store: {error}"))?;
            Ok::<(), String>(())
        })
        .await;
        release.notify_one();
        match choreography {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("{error}"),
            Err(_) => {
                let diagnostic = match opener.take() {
                    Some(opener) => {
                        opener.abort();
                        match opener.await {
                            Ok(Ok(store)) => {
                                let close = store.close().await;
                                format!("opener unexpectedly completed; close result: {close:?}")
                            }
                            Ok(Err(error)) => {
                                format!("opener failed while timing out: {error}")
                            }
                            Err(error) => format!("opener task stopped: {error}"),
                        }
                    }

                    None => "opener was already joined before a later stage timed out".to_owned(),
                };
                panic!("migration race exceeded the single five-second deadline; {diagnostic}");
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_open_aborts_migration_without_late_owner_claim() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "cancelled-open.sqlite");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("create cancelled-open database");
        sqlx::raw_sql(
            "PRAGMA application_id = 1196704067;
                 CREATE TABLE claw_schema_migrations (
                    version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
                    name TEXT NOT NULL,
                    checksum TEXT NOT NULL CHECK (length(checksum) = 64),
                    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
                 ) STRICT",
        )
        .execute(&mut connection)
        .await
        .expect("create cancelled-open migration prefix");
        sqlx::raw_sql(include_str!("../migrations/0001_initial.sql"))
            .execute(&mut connection)
            .await
            .expect("apply cancelled-open version-one schema");
        sqlx::query(
            "INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
             VALUES (1, 'initial', ?, 1)",
        )
        .bind(test_support::checksum(include_str!(
            "../migrations/0001_initial.sql"
        )))
        .execute(&mut connection)
        .await
        .expect("record cancelled-open version-one migration");
        sqlx::query(
            "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
             VALUES (1, 'pre-cancel-owner', 7)",
        )
        .execute(&mut connection)
        .await
        .expect("seed pre-cancel writer owner");
        connection.close().await.expect("close cancelled-open seed");
        make_private_file(&path);
        test_support::initialize_store_identity_fixture(&path);
        let (entered, _release) = test_support::set_migration_barrier(&path);
        let open_path = path.clone();
        let opener =
            tokio::spawn(async move { StateStore::open(StoreConfig::new(open_path)).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("open reaches transactional migration barrier");
        opener.abort();
        let cancellation = match opener.await {
            Err(error) => error,
            Ok(Ok(store)) => {
                let close = store.close().await;
                panic!("cancelled opener returned a store; close result: {close:?}");
            }
            Ok(Err(error)) => panic!("cancelled opener returned an error: {error}"),
        };
        assert!(cancellation.is_cancelled());
        test_support::clear_migration_barrier(&path);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let options = SqliteConnectOptions::new().filename(&path).read_only(true);
        let mut inspection = SqliteConnection::connect_with(&options)
            .await
            .expect("inspect cancelled open");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM claw_schema_migrations")
                .fetch_one(&mut inspection)
                .await
                .expect("read cancelled migration history"),
            1
        );
        assert_eq!(
            sqlx::query_as::<_, (String, i64)>(
                "SELECT owner, acquired_at_ms FROM claw_writer_lock WHERE singleton = 1",
            )
            .fetch_one(&mut inspection)
            .await
            .expect("read unchanged pre-cancel writer"),
            ("pre-cancel-owner".to_owned(), 7)
        );
        inspection
            .close()
            .await
            .expect("close cancellation inspection");
        let reopened = open(&path).await;
        assert_eq!(
            reopened.recovered_writer(),
            Some(&RecoveredWriterLock {
                previous_owner: "pre-cancel-owner".to_owned(),
                previous_acquired_at_ms: 7,
            })
        );
        reopened.close().await.expect("post-cancel store closes");
    }

    #[tokio::test]
    async fn unsafe_durations_and_relative_paths_fail_before_filesystem_access() {
        let missing_parent = std::env::temp_dir().join(format!(
            "claw-state-invalid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("current time")
                .as_nanos()
        ));
        let path = missing_parent.join("state.sqlite");
        for (field, config) in [
            (
                "busy timeout",
                StoreConfig::new(&path).with_busy_timeout(Duration::MAX),
            ),
            (
                "connection acquire timeout",
                StoreConfig::new(&path).with_acquire_timeout(Duration::MAX),
            ),
            (
                "open timeout",
                StoreConfig::new(&path).with_open_timeout(Duration::MAX),
            ),
            (
                "close timeout",
                StoreConfig::new(&path).with_close_timeout(Duration::MAX),
            ),
        ] {
            assert_eq!(
                StateStore::open(config)
                    .await
                    .err()
                    .expect("unsafe duration is rejected"),
                StateError::InvalidValue {
                    field,
                    reason: "exceeds the supported safe upper bound",
                }
            );
            assert!(!missing_parent.exists());
        }
        let relative = PathBuf::from("relative-state.sqlite");
        assert_eq!(
            StateStore::open(StoreConfig::new(&relative))
                .await
                .err()
                .expect("relative state path is rejected"),
            StateError::InvalidPath {
                path: relative,
                reason: "must be an absolute path inside a service-private directory",
            }
        );
    }

    #[tokio::test]
    async fn cleanup_admission_cannot_extend_the_open_deadline() {
        const CHILD_ENV: &str = "GTA_CLAW_OPEN_ADMISSION_DEADLINE_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            let executable = std::env::current_exe().expect("current state test executable");
            let status = Command::new(executable)
                .arg("--exact")
                .arg("tests::cleanup_admission_cannot_extend_the_open_deadline")
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .status()
                .expect("run isolated cleanup admission test");
            assert!(status.success(), "isolated cleanup admission test failed");
            return;
        }

        let owners = claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
            "state-open-admission-saturation",
            64,
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect("saturate bounded cleanup admission");
        let directory = tempfile::tempdir().expect("cleanup admission directory");
        let path = database_path(&directory, "cleanup-admission.sqlite");
        let started = std::time::Instant::now();
        let error = StateStore::open(
            StoreConfig::new(&path)
                .with_open_timeout(Duration::from_millis(200))
                .with_acquire_timeout(Duration::from_secs(5)),
        )
        .await
        .err()
        .expect("cleanup admission saturation reaches the open deadline");
        assert_eq!(
            error,
            StateError::OperationTimedOut {
                operation: "state store open",
                timeout_ms: 200,
            }
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "cleanup admission must not inherit the longer pool acquire timeout"
        );
        drop(owners);
    }

    #[tokio::test]
    async fn live_checkouts_do_not_reuse_the_expired_open_deadline() {
        let directory = tempfile::tempdir().expect("live checkout directory");
        let path = database_path(&directory, "live-checkout-deadline.sqlite");
        let store = StateStore::open(
            StoreConfig::new(&path)
                .with_open_timeout(Duration::from_secs(1))
                .with_acquire_timeout(Duration::from_secs(3)),
        )
        .await
        .expect("open live checkout fixture");
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        store
            .settings()
            .await
            .expect("live checkout uses configured acquire timeout");
        store.close().await.expect("close live checkout fixture");
    }

    #[tokio::test]
    async fn competing_sqlite_writer_cannot_extend_open_past_absolute_deadline() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "open-busy-deadline.sqlite");
        open(&path)
            .await
            .close()
            .await
            .expect("seed busy-deadline store");
        let (entered, release) = test_support::set_open_initialization_barrier(&path);
        let open_path = path.clone();
        let started = std::time::Instant::now();
        let opening = tokio::spawn(async move {
            StateStore::open(
                StoreConfig::new(&open_path)
                    .with_busy_timeout(Duration::from_secs(5))
                    .with_open_timeout(Duration::from_millis(300)),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("open reaches post-bootstrap initialization barrier");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(5));
        let mut blocker = SqliteConnection::connect_with(&options)
            .await
            .expect("open competing SQLite writer");
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut blocker)
            .await
            .expect("hold competing SQLite write transaction");
        release.notify_one();
        let error = opening
            .await
            .expect("deadline-bound open task joins")
            .err()
            .expect("competing writer reaches the absolute open deadline");
        assert_eq!(
            error,
            StateError::OperationTimedOut {
                operation: "state store open",
                timeout_ms: 300,
            }
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "configured SQLite busy timeout must not extend the overall open deadline"
        );
        sqlx::query("ROLLBACK")
            .execute(&mut blocker)
            .await
            .expect("release competing SQLite writer");
        blocker.close().await.expect("close competing writer");
        let reopened = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match StateStore::open(StoreConfig::new(&path)).await {
                    Ok(store) => break store,
                    Err(StateError::StoreLocked { .. } | StateError::FileSystem { .. }) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("post-timeout reopen failed: {error}"),
                }
            }
        })
        .await
        .expect("open timeout reaper releases writer ownership");
        reopened
            .close()
            .await
            .expect("store reopens after deadline contention");
    }

    #[tokio::test]
    async fn cancelling_open_at_final_commit_fence_rolls_back_schema_and_owner() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "cancelled-open-precommit.sqlite");
        let (entered, _release) = test_support::set_open_precommit_barrier(&path);
        let open_path = path.clone();
        let opener =
            tokio::spawn(async move { StateStore::open(StoreConfig::new(open_path)).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("fresh open reaches final commit fence");
        opener.abort();
        let cancellation = match opener.await {
            Err(error) => error,
            Ok(Ok(store)) => {
                let close = store.close().await;
                panic!("cancelled precommit open returned a store; close result: {close:?}");
            }
            Ok(Err(error)) => panic!("cancelled precommit open returned an error: {error}"),
        };
        assert!(cancellation.is_cancelled());

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .busy_timeout(Duration::from_millis(50));
        let mut inspection = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match SqliteConnection::connect_with(&options).await {
                    Ok(mut connection) => {
                        if sqlx::query("BEGIN IMMEDIATE")
                            .execute(&mut connection)
                            .await
                            .is_ok()
                        {
                            break connection;
                        }
                        let _ = connection.close().await;
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .expect("cancelled open releases its SQLite worker");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'claw_schema_migrations'"
            )
            .fetch_one(&mut inspection)
            .await
            .expect("inspect cancelled precommit schema"),
            0
        );
        sqlx::query("ROLLBACK")
            .execute(&mut inspection)
            .await
            .expect("release cancelled-open lifecycle fence");
        inspection
            .close()
            .await
            .expect("close cancelled precommit inspection");
        let reopened = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match StateStore::open(StoreConfig::new(&path)).await {
                    Ok(store) => break store,
                    Err(StateError::StoreLocked { .. } | StateError::FileSystem { .. }) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("fresh open after cancellation failed: {error}"),
                }
            }
        })
        .await
        .expect("cancelled open releases its OS writer lock");
        reopened
            .close()
            .await
            .expect("fresh open succeeds after precommit cancellation");
    }

    #[tokio::test]
    async fn cancelling_open_after_commit_closes_committed_owner_before_reopen() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "cancelled-open-postcommit.sqlite");
        let (entered, release) = test_support::set_open_postcommit_barrier(&path);
        let open_path = path.clone();
        let opener =
            tokio::spawn(async move { StateStore::open(StoreConfig::new(open_path)).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("open reaches committed-store delivery barrier");
        opener.abort();
        let cancellation = match opener.await {
            Err(error) => error,
            Ok(Ok(store)) => {
                let close = store.close().await;
                panic!("postcommit-cancelled open returned a store; close result: {close:?}");
            }
            Ok(Err(error)) => panic!("postcommit-cancelled open returned an error: {error}"),
        };
        assert!(cancellation.is_cancelled());
        release.notify_one();

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .busy_timeout(Duration::from_millis(50));
        let mut inspection = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(mut connection) = SqliteConnection::connect_with(&options).await {
                    let owner = sqlx::query_scalar::<_, Option<String>>(
                        "SELECT (SELECT owner FROM claw_writer_lock WHERE singleton = 1)",
                    )
                    .fetch_one(&mut connection)
                    .await;
                    if matches!(owner, Ok(None)) {
                        break connection;
                    }
                    let _ = connection.close().await;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("postcommit cancellation closes its delivered store");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA user_version")
                .fetch_one(&mut inspection)
                .await
                .expect("read committed postcancel schema"),
            2
        );
        assert_eq!(
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT (SELECT owner FROM claw_writer_lock WHERE singleton = 1)"
            )
            .fetch_one(&mut inspection)
            .await
            .expect("read released postcancel owner"),
            None
        );
        inspection
            .close()
            .await
            .expect("close postcommit cancellation inspection");
        let reopened = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match StateStore::open(StoreConfig::new(&path)).await {
                    Ok(store) => break store,
                    Err(StateError::StoreLocked { .. } | StateError::FileSystem { .. }) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("postcommit-cancelled reopen failed: {error}"),
                }
            }
        })
        .await
        .expect("postcommit cancellation releases OS writer lock");
        assert!(reopened.recovered_writer().is_none());
        reopened
            .close()
            .await
            .expect("postcommit-cancelled store reopens cleanly");
    }

    #[tokio::test]
    async fn open_timeout_after_commit_waits_for_claim_cleanup_before_return() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "timeout-after-commit.sqlite");
        let (entered, _release) = test_support::set_open_postcommit_barrier(&path);
        let open_path = path.clone();
        let opening = tokio::spawn(async move {
            StateStore::open(
                StoreConfig::new(open_path).with_open_timeout(Duration::from_millis(2_000)),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("open reaches postcommit timeout barrier");
        assert_eq!(
            opening
                .await
                .expect("postcommit timeout task joins")
                .err()
                .expect("postcommit open times out"),
            StateError::OperationTimedOut {
                operation: "state store open",
                timeout_ms: 2_000,
            }
        );
        let reopened = StateStore::open(StoreConfig::new(&path))
            .await
            .expect("timeout returned only after writer claim cleanup");
        assert!(reopened.recovered_writer().is_none());
        reopened
            .close()
            .await
            .expect("postcommit-timeout store closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn migration_timeout_rolls_back_without_late_mutation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "migration-timeout.sqlite");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("create migration timeout database");
        sqlx::raw_sql(
            "PRAGMA application_id = 1196704067;
                 CREATE TABLE IF NOT EXISTS claw_schema_migrations (
                    version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
                    name TEXT NOT NULL,
                    checksum TEXT NOT NULL CHECK (length(checksum) = 64),
                    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
                 ) STRICT",
        )
        .execute(&mut connection)
        .await
        .expect("create migration timeout prefix");
        connection.close().await.expect("close timeout prefix");
        make_private_file(&path);
        let (entered, release) = test_support::set_migration_barrier(&path);
        assert_eq!(
                StateStore::open(
                    StoreConfig::new(&path).with_open_timeout(Duration::from_millis(100)),
                )
                .await
                .err()
                .expect("gated migration reaches one overall timeout"),
                StateError::OperationTimedOut {
                    operation: "state store open",
                    timeout_ms: 100,
                }
            );
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("migration entered the deterministic gate");
        release.notify_one();
        test_support::clear_migration_barrier(&path);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let stable = database_artifact_bytes(&path);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_database_artifacts_unchanged(&stable, &database_artifact_bytes(&path));
        let reopened = open(&path).await;
        assert!(
            reopened
                .health()
                .await
                .expect("post-timeout health")
                .is_healthy()
        );
        reopened.close().await.expect("post-timeout store closes");

        let fresh_path = database_path(&directory, "fresh-migration-timeout.sqlite");
        let (entered, release) = test_support::set_migration_barrier(&fresh_path);
        assert_eq!(
            StateStore::open(
                StoreConfig::new(&fresh_path).with_open_timeout(Duration::from_millis(100)),
            )
            .await
            .err()
            .expect("fresh gated migration reaches one overall timeout"),
            StateError::OperationTimedOut {
                operation: "state store open",
                timeout_ms: 100,
            }
        );
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("fresh migration entered deterministic gate");
        release.notify_one();
        test_support::clear_migration_barrier(&fresh_path);
        let stable = database_artifact_bytes(&fresh_path);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_database_artifacts_unchanged(&stable, &database_artifact_bytes(&fresh_path));
        let reopened = open(&fresh_path).await;
        assert!(
            reopened
                .health()
                .await
                .expect("fresh post-timeout health")
                .is_healthy()
        );
        reopened
            .close()
            .await
            .expect("fresh post-timeout store closes");
    }

    #[tokio::test]
    async fn records_survive_close_and_reopen() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "persistent.sqlite");
        let store = open(&path).await;
        let session = session("session-1", 1_000);
        let device = device("device-1", 1_001);
        let authentication = authentication("auth-1", &device.id, 1_002);
        let task = task("task-1", &session.id, 1_003);

        store
            .sessions()
            .create(&session)
            .await
            .expect("create session");
        store
            .devices()
            .create_with_authentication(&device, &authentication)
            .await
            .expect("create device and authentication");
        store.tasks().create(&task).await.expect("create task");
        store.close().await.expect("first store closes");

        let reopened = open(&path).await;
        assert_eq!(
            reopened
                .sessions()
                .get(&session.id)
                .await
                .expect("read session"),
            Some(session)
        );
        assert_eq!(
            reopened
                .authentications()
                .get(&authentication.id)
                .await
                .expect("read authentication"),
            Some(authentication)
        );
        assert_eq!(
            reopened.tasks().get(&task.id).await.expect("read task"),
            Some(task)
        );
        reopened.close().await.expect("reopened store closes");
    }

    #[tokio::test]
    async fn compound_create_rolls_back_when_second_insert_fails() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "rollback.sqlite")).await;
        let existing_device = device("device-existing", 1);
        let existing_authentication = authentication("auth-shared", &existing_device.id, 2);
        store
            .devices()
            .create_with_authentication(&existing_device, &existing_authentication)
            .await
            .expect("seed records");

        let rolled_back_device = device("device-rolled-back", 3);
        let duplicate_authentication = authentication("auth-shared", &rolled_back_device.id, 4);
        let error = store
            .devices()
            .create_with_authentication(&rolled_back_device, &duplicate_authentication)
            .await
            .expect_err("duplicate authentication aborts transaction");
        assert!(matches!(
            error,
            StateError::AlreadyExists {
                entity: "authentication",
                ..
            }
        ));
        assert!(
            store
                .devices()
                .get(&rolled_back_device.id)
                .await
                .expect("read rolled-back device")
                .is_none()
        );
    }

    #[tokio::test]
    async fn duplicate_records_and_invalid_transitions_are_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "duplicates.sqlite")).await;
        let record = session("session-1", 10);
        store
            .sessions()
            .create(&record)
            .await
            .expect("create session");
        let duplicate = store
            .sessions()
            .create(&record)
            .await
            .expect_err("duplicate session fails");
        assert!(matches!(
            duplicate,
            StateError::AlreadyExists {
                entity: "session",
                ..
            }
        ));

        let archived = store
            .sessions()
            .update_status(&record.id, 1, SessionStatus::Archived, timestamp(11))
            .await
            .expect("archive session");
        let transition = store
            .sessions()
            .update_status(
                &record.id,
                archived.version,
                SessionStatus::Archived,
                timestamp(12),
            )
            .await
            .expect_err("duplicate archive transition fails");
        assert!(matches!(
            transition,
            StateError::InvalidTransition {
                entity: "session",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn rollback_cleanup_disruptions_never_panic_or_poison_the_pool() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = StateStore::open(
            StoreConfig::new(database_path(&directory, "rollback-cleanup.sqlite"))
                .with_max_connections(2),
        )
        .await
        .expect("rollback cleanup store opens");
        let duplicate = session("rollback-duplicate", 1);
        store
            .sessions()
            .create(&duplicate)
            .await
            .expect("seed duplicate session");
        let owner = test_support::owner(&store).to_owned();

        for mode in 1..=3 {
            crate::repository::test_support::disrupt_next_rollback_cleanup(&owner, mode);
            assert!(matches!(
                store.sessions().create(&duplicate).await,
                Err(StateError::AlreadyExists { .. })
            ));
            crate::repository::test_support::assert_rollback_cleanup_disruption_consumed(&owner);
            store
                .sessions()
                .create(&session(&format!("rollback-recovery-{mode}"), mode.into()))
                .await
                .expect("pool remains usable after injected rollback cleanup failure");
        }

        crate::repository::test_support::drop_transaction_without_runtime(test_support::pool(
            &store,
        ))
        .await;
        store
            .sessions()
            .create(&session("no-runtime-recovery", 10))
            .await
            .expect("pool remains usable after no-runtime transaction drop");
        store.close().await.expect("rollback cleanup store closes");
    }

    #[tokio::test]
    async fn rollback_cleanup_is_isolated_under_parallel_writes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let first = open(&database_path(&directory, "rollback-key-first.sqlite")).await;
        let second = open(&database_path(&directory, "rollback-key-second.sqlite")).await;
        let duplicate = session("rollback-key-duplicate", 1);
        first
            .sessions()
            .create(&duplicate)
            .await
            .expect("seed first duplicate");
        second
            .sessions()
            .create(&duplicate)
            .await
            .expect("seed second duplicate");
        assert!(matches!(
            second.sessions().create(&duplicate).await,
            Err(StateError::AlreadyExists { .. })
        ));
        let first_sessions = first.sessions();
        let second_sessions = second.sessions();
        let (first_error, second_error) = tokio::join!(
            first_sessions.create(&duplicate),
            second_sessions.create(&duplicate)
        );
        assert!(matches!(first_error, Err(StateError::AlreadyExists { .. })));
        assert!(matches!(
            second_error,
            Err(StateError::AlreadyExists { .. })
        ));
        first.close().await.expect("first keyed store closes");
        second.close().await.expect("second keyed store closes");
    }

    #[tokio::test]
    async fn malformed_persisted_text_returns_typed_error_without_panicking() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "malformed-text.sqlite")).await;
        sqlx::query(
            "INSERT INTO sessions(id, status, created_at_ms, updated_at_ms, version)
             VALUES(CAST(X'80' AS TEXT), 'active', 1, 1, 1)",
        )
        .execute(test_support::pool(&store))
        .await
        .expect("seed malformed persisted TEXT");
        assert_eq!(
            store
                .sessions()
                .list(&PageRequest::new(10, None).expect("valid malformed-text page"))
                .await
                .expect_err("malformed TEXT returns a typed error"),
            StateError::InvalidValue {
                field: "session id",
                reason: "persisted value is not supported",
            }
        );
        store.close().await.expect("malformed-text store closes");
    }

    #[tokio::test]
    async fn noncanonical_persisted_id_is_rejected_instead_of_trimmed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "noncanonical-id.sqlite")).await;
        sqlx::query(
            "INSERT INTO sessions(id, status, created_at_ms, updated_at_ms, version)
             VALUES('session-with-space ', 'active', 1, 1, 1)",
        )
        .execute(test_support::pool(&store))
        .await
        .expect("seed noncanonical persisted id");
        assert_eq!(
            store
                .sessions()
                .list(&PageRequest::new(10, None).expect("valid noncanonical-id page"))
                .await
                .expect_err("noncanonical persisted id is rejected"),
            StateError::InvalidValue {
                field: "session id",
                reason: "persisted value is not supported",
            }
        );
        store.close().await.expect("noncanonical-id store closes");
    }

    #[tokio::test]
    async fn impossible_persisted_timestamp_history_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "invalid-timestamps.sqlite")).await;
        let mut connection = test_support::pool(&store)
            .acquire()
            .await
            .expect("acquire timestamp tamper connection");
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *connection)
            .await
            .expect("disable check constraints for tamper fixture");
        sqlx::query(
            "INSERT INTO sessions(id, status, created_at_ms, updated_at_ms, version)
             VALUES('time-travel', 'active', 10, 9, 1)",
        )
        .execute(&mut *connection)
        .await
        .expect("seed impossible timestamp history");
        sqlx::query("PRAGMA ignore_check_constraints = OFF")
            .execute(&mut *connection)
            .await
            .expect("restore check constraints");
        drop(connection);
        assert_eq!(
            store
                .sessions()
                .list(&PageRequest::new(10, None).expect("valid timestamp page"))
                .await
                .expect_err("impossible timestamp history is rejected"),
            StateError::InvalidValue {
                field: "updated timestamp",
                reason: "must not precede the current timestamp",
            }
        );
        store
            .close()
            .await
            .expect("invalid-timestamps store closes");
    }

    #[tokio::test]
    async fn stale_task_update_returns_optimistic_conflict() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "optimistic.sqlite")).await;
        let session = session("session-1", 1);
        let task = task("task-1", &session.id, 2);
        store
            .sessions()
            .create(&session)
            .await
            .expect("create session");
        store.tasks().create(&task).await.expect("create task");
        store
            .tasks()
            .update_status(&task.id, 1, TaskStatus::Running, timestamp(3))
            .await
            .expect("start task");
        let stale = store
            .tasks()
            .update_status(&task.id, 1, TaskStatus::Cancelled, timestamp(4))
            .await
            .expect_err("stale update fails");
        assert_eq!(
            stale,
            StateError::OptimisticConflict {
                entity: "task",
                id: "task-1".to_owned(),
                expected_version: 1,
            }
        );
    }

    #[tokio::test]
    async fn repository_writes_reject_logical_database_identity_drift() {
        let directory = tempfile::tempdir().expect("temporary directory");

        let application_path = database_path(&directory, "application-drift.sqlite");
        let application_store = open(&application_path).await;
        execute_direct(&application_path, "PRAGMA application_id = 0").await;
        let application_record = session("application-drift", 1);
        let error = application_store
            .sessions()
            .create(&application_record)
            .await
            .expect_err("application-id drift rejects repository write");
        assert!(matches!(
            error,
            StateError::InvalidValue {
                field: "SQLite application id",
                ..
            }
        ));
        assert!(
            application_store
                .sessions()
                .get(&application_record.id)
                .await
                .expect("read rejected application-drift record")
                .is_none()
        );
        application_store
            .close()
            .await
            .expect("application-drift store releases ownership");

        let owner_path = database_path(&directory, "owner-drift.sqlite");
        let owner_store = open(&owner_path).await;
        execute_direct(
            &owner_path,
            "UPDATE claw_writer_lock SET owner = 'external-owner' WHERE singleton = 1",
        )
        .await;
        let owner_health = owner_store
            .health()
            .await
            .expect("inspect owner drift health");
        assert!(!owner_health.is_healthy());
        assert!(
            owner_health
                .migration_errors
                .iter()
                .any(|error| error.contains("application writer ownership"))
        );
        let owner_record = session("owner-drift", 1);
        let error = owner_store
            .sessions()
            .create(&owner_record)
            .await
            .expect_err("owner drift rejects repository write");
        assert!(
            matches!(error, StateError::InvalidMigrationHistory { .. }),
            "unexpected owner-drift error: {error:?}"
        );
        assert!(
            owner_store
                .sessions()
                .get(&owner_record.id)
                .await
                .expect("read rejected owner-drift record")
                .is_none()
        );
        let close = owner_store
            .close()
            .await
            .expect_err("owner drift is reported during close");
        assert!(matches!(
            close,
            StateError::CloseDegraded {
                application_lock_released: false,
                os_lock_released: true,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn task_requires_an_existing_session() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "foreign-key.sqlite")).await;
        let missing = SessionId::new("missing").expect("valid test id");
        let task = task("task-1", &missing, 1);
        let error = store
            .tasks()
            .create(&task)
            .await
            .expect_err("foreign key is enforced");
        assert_eq!(
            error,
            StateError::ForeignKeyViolation {
                entity: "session",
                id: "missing".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn task_rejects_an_archived_session() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "archived-task.sqlite")).await;
        let session = session("archived-session", 1);
        store
            .sessions()
            .create(&session)
            .await
            .expect("create session");
        store
            .sessions()
            .update_status(&session.id, 1, SessionStatus::Archived, timestamp(2))
            .await
            .expect("archive session");

        let error = store
            .tasks()
            .create(&task("rejected-task", &session.id, 3))
            .await
            .expect_err("archived session rejects task");
        assert_eq!(
            error,
            StateError::InactiveParent {
                entity: "session",
                id: "archived-session".to_owned(),
                state: "archived",
            }
        );
    }

    #[tokio::test]
    async fn archive_and_task_create_race_has_only_serializable_outcomes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "archive-race.sqlite")).await;
        for index in 0..10 {
            let session = session(&format!("archive-first-session-{index}"), index * 10 + 1);
            let task = task(
                &format!("archive-first-task-{index}"),
                &session.id,
                index * 10 + 2,
            );
            store
                .sessions()
                .create(&session)
                .await
                .expect("create archive-first session");
            let (entered, release) =
                crate::repository::test_support::set_commit_barrier(test_support::owner(&store));
            let sessions = store.sessions();
            let tasks = store.tasks();
            let (archived, created) = tokio::join!(
                sessions.update_status(
                    &session.id,
                    1,
                    SessionStatus::Archived,
                    timestamp(index * 10 + 3),
                ),
                async {
                    entered.notified().await;
                    let create = tasks.create(&task);
                    tokio::pin!(create);
                    tokio::select! {
                        biased;
                        result = &mut create => {
                            panic!("task creation completed before archive commit: {result:?}");
                        }
                        () = tokio::task::yield_now() => {}
                    }
                    release.notify_one();
                    create.await
                }
            );
            archived.expect("archive commits before blocked task creation");
            assert!(matches!(
                created,
                Err(StateError::InactiveParent {
                    entity: "session",
                    state: "archived",
                    ..
                })
            ));
            assert!(
                store
                    .tasks()
                    .get(&task.id)
                    .await
                    .expect("read rejected archive-first task")
                    .is_none()
            );
        }

        for index in 0..10 {
            let session = session(&format!("task-first-session-{index}"), index * 10 + 101);
            let task = task(
                &format!("task-first-task-{index}"),
                &session.id,
                index * 10 + 102,
            );
            store
                .sessions()
                .create(&session)
                .await
                .expect("create task-first session");
            let (entered, release) =
                crate::repository::test_support::set_commit_barrier(test_support::owner(&store));
            let sessions = store.sessions();
            let tasks = store.tasks();
            let (archived, created) = tokio::join!(
                async {
                    entered.notified().await;
                    release.notify_one();
                    sessions
                        .update_status(
                            &session.id,
                            1,
                            SessionStatus::Archived,
                            timestamp(index * 10 + 103),
                        )
                        .await
                },
                tasks.create(&task),
            );
            created.expect("task commits before archive begins");
            archived.expect("archive follows committed task");
            assert!(
                store
                    .tasks()
                    .get(&task.id)
                    .await
                    .expect("read committed task-first task")
                    .is_some()
            );
        }
    }

    #[tokio::test]
    async fn cursor_pagination_is_stable_for_equal_timestamps() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "pagination.sqlite")).await;
        for id in ["session-c", "session-a", "session-b"] {
            store
                .sessions()
                .create(&session(id, 100))
                .await
                .expect("create paginated session");
        }

        let first = store
            .sessions()
            .list(&PageRequest::new(2, None).expect("valid page"))
            .await
            .expect("first page");
        assert_eq!(
            first
                .items
                .iter()
                .map(|record| record.id.as_str())
                .collect::<Vec<_>>(),
            ["session-a", "session-b"]
        );
        let second = store
            .sessions()
            .list(&PageRequest::new(2, first.next).expect("valid continuation"))
            .await
            .expect("second page");
        assert_eq!(
            second
                .items
                .iter()
                .map(|record| record.id.as_str())
                .collect::<Vec<_>>(),
            ["session-c"]
        );
        assert!(second.next.is_none());
    }

    #[tokio::test]
    async fn pagination_queries_use_ordering_range_indexes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "pagination-plans.sqlite")).await;
        let plans = [
            (
                "EXPLAIN QUERY PLAN
                 SELECT id FROM sessions
                 WHERE (created_at_ms, id) > (?, ?)
                 ORDER BY created_at_ms, id LIMIT ?",
                "sessions_creation_order",
                false,
            ),
            (
                "EXPLAIN QUERY PLAN
                 SELECT id FROM devices
                 WHERE (created_at_ms, id) > (?, ?)
                 ORDER BY created_at_ms, id LIMIT ?",
                "devices_creation_order",
                false,
            ),
            (
                "EXPLAIN QUERY PLAN
                 SELECT id FROM authentication_records
                 WHERE device_id = ? AND (created_at_ms, id) > (?, ?)
                 ORDER BY created_at_ms, id LIMIT ?",
                "authentication_records_device_order",
                true,
            ),
            (
                "EXPLAIN QUERY PLAN
                 SELECT id FROM tasks
                 WHERE session_id = ? AND (created_at_ms, id) > (?, ?)
                 ORDER BY created_at_ms, id LIMIT ?",
                "tasks_session_order",
                true,
            ),
        ];
        for (sql, expected_index, scoped) in plans {
            let mut query = sqlx::query(sql);
            if scoped {
                query = query.bind("parent");
            }
            let details = query
                .bind(1_i64)
                .bind("cursor")
                .bind(10_i64)
                .fetch_all(test_support::pool(&store))
                .await
                .expect("inspect pagination query plan")
                .into_iter()
                .map(|row| row.get::<String, _>("detail"))
                .collect::<Vec<_>>()
                .join("; ");
            assert!(
                details.contains(expected_index) && details.contains("SEARCH"),
                "expected range search through {expected_index}, received {details}"
            );
        }
        store.close().await.expect("pagination plan store closes");
    }

    #[tokio::test]
    async fn busy_timeout_returns_a_database_failure_instead_of_hanging() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = StateStore::open(
            StoreConfig::new(database_path(&directory, "busy.sqlite"))
                .with_max_connections(2)
                .with_busy_timeout(Duration::from_millis(50))
                .with_acquire_timeout(Duration::from_secs(2)),
        )
        .await
        .expect("state store opens");
        let pool = test_support::pool(&store);
        let mut blocking_connection = pool.acquire().await.expect("acquire blocking connection");
        blocking_connection
            .execute("BEGIN IMMEDIATE")
            .await
            .expect("hold write transaction");

        let started = Instant::now();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            store.sessions().create(&session("blocked", 1)),
        )
        .await
        .expect("SQLite busy handling remains hard-bounded")
        .expect_err("concurrent SQLite writer times out");
        let StateError::Database(failure) = error else {
            panic!("expected a typed SQLite busy failure, received {error:?}");
        };
        assert_eq!(failure.operation(), "lock and verify application writer");
        assert_eq!(failure.code(), Some("5"));
        assert!(started.elapsed() < Duration::from_secs(1));
        blocking_connection
            .execute("ROLLBACK")
            .await
            .expect("release write transaction");
        drop(blocking_connection);
        store.close().await.expect("busy test store closes cleanly");
    }

    #[tokio::test]
    async fn open_deadline_does_not_truncate_live_busy_timeout() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "live-busy-timeout.sqlite");
        let store = StateStore::open(
            StoreConfig::new(&path)
                .with_open_timeout(Duration::from_millis(500))
                .with_busy_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("short-deadline store opens");
        assert_eq!(
            store
                .settings()
                .await
                .expect("read live busy timeout")
                .busy_timeout_ms,
            5_000
        );
        store.close().await.expect("short-deadline store closes");
    }

    #[tokio::test]
    async fn close_reports_busy_checkpoint_but_releases_all_ownership() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "busy-close.sqlite");
        let store =
            StateStore::open(StoreConfig::new(&path).with_busy_timeout(Duration::from_millis(50)))
                .await
                .expect("state store opens");
        store
            .sessions()
            .create(&session("busy-close-session", 1))
            .await
            .expect("create WAL-backed row");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .read_only(true)
            .busy_timeout(Duration::from_millis(50));
        let mut reader = SqliteConnection::connect_with(&options)
            .await
            .expect("open checkpoint-blocking reader");
        reader
            .execute("BEGIN")
            .await
            .expect("begin reader transaction");
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sessions")
            .fetch_one(&mut reader)
            .await
            .expect("establish reader snapshot");

        let error = tokio::time::timeout(Duration::from_secs(2), store.close())
            .await
            .expect("busy close completes within its bound")
            .expect_err("busy checkpoint degrades close");
        assert!(matches!(
            error,
            StateError::CloseDegraded {
                checkpoint_completed: false,
                application_lock_released: true,
                os_lock_released: true,
                ..
            }
        ));
        reader
            .execute("ROLLBACK")
            .await
            .expect("release reader snapshot");
        reader.close().await.expect("reader closes");

        let next = open(&path).await;
        assert!(next.recovered_writer().is_none());
        next.close().await.expect("next owner closes cleanly");
    }

    #[tokio::test]
    async fn final_connection_close_failures_never_report_clean_shutdown() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for (name, timeout, reason) in [
            (
                "error",
                false,
                "final connection close failed: injected test failure",
            ),
            (
                "timeout",
                true,
                "final connection close exceeded close deadline",
            ),
        ] {
            let path = database_path(&directory, &format!("final-close-{name}.sqlite"));
            let store = open(&path).await;
            test_support::fail_final_connection_close_once(&path, timeout);
            assert_eq!(
                store
                    .close()
                    .await
                    .expect_err("unobserved final connection close degrades shutdown"),
                StateError::CloseDegraded {
                    checkpoint_completed: true,
                    application_lock_released: true,
                    final_connection_closed: false,
                    pool_closed: false,
                    os_lock_released: true,
                    reason: reason.to_owned(),
                }
            );
            let reopened = open(&path).await;
            assert!(reopened.recovered_writer().is_none());
            reopened
                .close()
                .await
                .expect("degraded store reopens cleanly");
        }

        let clean_path = database_path(&directory, "final-close-clean.sqlite");
        open(&clean_path)
            .await
            .close()
            .await
            .expect("observed final connection close remains clean");
    }

    #[tokio::test]
    async fn migration_checksum_drift_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "checksum.sqlite");
        let store = open(&path).await;
        sqlx::query("UPDATE claw_schema_migrations SET checksum = ? WHERE version = 1")
            .bind("0".repeat(64))
            .execute(test_support::pool(&store))
            .await
            .expect("tamper migration checksum");
        store.close().await.expect("tampered store closes");
        execute_direct(
            &path,
            "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
             VALUES (1, 'drift-owner', 11)",
        )
        .await;
        let journal_before = test_support::journal_mode(&path)
            .await
            .expect("read journal mode before checksum rejection");
        let before = database_artifact_bytes(&path);

        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("checksum drift rejects reopen");
        assert!(matches!(
            error,
            StateError::MigrationChecksumDrift { version: 1, .. }
        ));
        assert_database_artifacts_unchanged(&before, &database_artifact_bytes(&path));
        assert_eq!(
            test_support::journal_mode(&path)
                .await
                .expect("read journal mode after checksum rejection"),
            journal_before
        );
        assert_eq!(
            persisted_writer(&path).await,
            Some(("drift-owner".to_owned(), 11))
        );
    }

    #[test]
    fn migration_checksums_are_independent_of_checkout_line_endings() {
        assert_eq!(
            test_support::checksum("SELECT 1;\r\nSELECT 2;\r\n"),
            test_support::checksum("SELECT 1;\nSELECT 2;\n")
        );
    }

    #[tokio::test]
    async fn newer_schema_is_never_downgraded() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "newer.sqlite");
        let store = open(&path).await;
        sqlx::query(
            "INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
             VALUES (3, 'future', ?, 1)",
        )
        .bind("f".repeat(64))
        .execute(test_support::pool(&store))
        .await
        .expect("insert future migration");
        store.close().await.expect("future store closes");
        execute_direct(
            &path,
            "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
             VALUES (1, 'newer-owner', 12)",
        )
        .await;
        let journal_before = test_support::journal_mode(&path)
            .await
            .expect("read journal mode before newer-schema rejection");
        let before = database_artifact_bytes(&path);

        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("newer schema rejects reopen");
        assert_eq!(
            error,
            StateError::NewerSchema {
                found: 3,
                supported: 2,
            }
        );
        assert_database_artifacts_unchanged(&before, &database_artifact_bytes(&path));
        assert_eq!(
            test_support::journal_mode(&path)
                .await
                .expect("read journal mode after newer-schema rejection"),
            journal_before
        );
        assert_eq!(
            persisted_writer(&path).await,
            Some(("newer-owner".to_owned(), 12))
        );
    }

    #[tokio::test]
    async fn migration_gap_is_rejected_without_mutation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "gap.sqlite");
        let store = open(&path).await;
        store.close().await.expect("seed store closes");
        execute_direct(
            &path,
            "DELETE FROM claw_schema_migrations;
             INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
             VALUES (2, 'gap', 'gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg', 1);
             INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
             VALUES (1, 'gap-owner', 13)",
        )
        .await;
        let journal_before = test_support::journal_mode(&path)
            .await
            .expect("read journal mode before migration-gap rejection");
        let before = database_artifact_bytes(&path);

        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("migration gap rejects reopen");
        assert!(matches!(error, StateError::InvalidMigrationHistory { .. }));
        assert_database_artifacts_unchanged(&before, &database_artifact_bytes(&path));
        assert_eq!(
            test_support::journal_mode(&path)
                .await
                .expect("read journal mode after migration-gap rejection"),
            journal_before
        );
        assert_eq!(
            persisted_writer(&path).await,
            Some(("gap-owner".to_owned(), 13))
        );
    }

    #[tokio::test]
    async fn empty_history_with_complete_schema_is_rejected_without_mutation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "empty-history.sqlite");
        open(&path).await.close().await.expect("seed store closes");
        execute_direct(&path, "DELETE FROM claw_schema_migrations").await;
        test_support::trust_existing_sidecars(&path);
        let journal_before = test_support::journal_mode(&path)
            .await
            .expect("read journal before empty-history rejection");
        test_support::trust_existing_sidecars(&path);
        let writer_before = persisted_writer(&path).await;
        test_support::trust_existing_sidecars(&path);
        let before = database_artifact_bytes(&path);

        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("complete schema with empty history is rejected");
        assert!(
            matches!(error, StateError::InvalidMigrationHistory { .. }),
            "unexpected empty-history error: {error:?}"
        );
        assert_database_artifacts_unchanged(&before, &database_artifact_bytes(&path));
        assert_eq!(
            test_support::journal_mode(&path)
                .await
                .expect("read journal after empty-history rejection"),
            journal_before
        );
        assert_eq!(persisted_writer(&path).await, writer_before);
    }

    #[tokio::test]
    async fn full_schema_definition_drift_is_rejected_without_mutation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for (name, sql) in schema_drift_cases() {
            let path = database_path(&directory, &format!("open-{name}.sqlite"));
            open(&path)
                .await
                .close()
                .await
                .expect("seed schema store closes");
            execute_direct(&path, sql).await;
            test_support::trust_existing_sidecars(&path);
            let journal_before = test_support::journal_mode(&path)
                .await
                .expect("read journal before schema rejection");
            test_support::trust_existing_sidecars(&path);
            let writer_before = persisted_writer(&path).await;
            test_support::trust_existing_sidecars(&path);
            let before = database_artifact_bytes(&path);

            let error = StateStore::open(StoreConfig::new(&path))
                .await
                .err()
                .expect("schema-definition drift rejects open");
            assert!(matches!(error, StateError::InvalidMigrationHistory { .. }));
            assert_database_artifacts_unchanged(&before, &database_artifact_bytes(&path));
            assert_eq!(
                test_support::journal_mode(&path)
                    .await
                    .expect("read journal after schema rejection"),
                journal_before
            );
            assert_eq!(persisted_writer(&path).await, writer_before);
        }
    }

    #[tokio::test]
    async fn health_reports_migration_name_and_checksum_drift() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "health-drift.sqlite");
        let store = open(&path).await;
        let original_checksum =
            sqlx::query_scalar::<_, String>("SELECT checksum FROM claw_schema_migrations")
                .fetch_one(test_support::pool(&store))
                .await
                .expect("read embedded checksum");
        sqlx::query("UPDATE claw_schema_migrations SET checksum = ? WHERE version = 1")
            .bind("0".repeat(64))
            .execute(test_support::pool(&store))
            .await
            .expect("tamper migration checksum");

        let health = store.health().await.expect("health report");
        assert!(!health.is_healthy());
        assert_eq!(health.migration_errors.len(), 1);
        assert!(health.migration_errors[0].contains("checksum drift"));

        sqlx::query(
            "UPDATE claw_schema_migrations
             SET name = 'renamed', checksum = ?
             WHERE version = 1",
        )
        .bind(original_checksum)
        .execute(test_support::pool(&store))
        .await
        .expect("tamper migration name");
        let health = store.health().await.expect("name drift health report");
        assert!(!health.is_healthy());
        assert_eq!(health.migration_errors.len(), 1);
        assert!(health.migration_errors[0].contains("is named renamed"));

        sqlx::raw_sql(
            "UPDATE claw_schema_migrations SET name = 'initial' WHERE version = 1;
             DROP TABLE tasks",
        )
        .execute(test_support::pool(&store))
        .await
        .expect("remove required schema object");
        let health = store.health().await.expect("schema drift health report");
        assert!(!health.is_healthy());
        assert_eq!(health.migration_errors.len(), 1);
        assert!(health.migration_errors[0].contains("schema definitions"));
        store.close().await.expect("drifted store closes");
    }

    #[tokio::test]
    async fn health_reports_full_schema_definition_drift() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for (name, sql) in schema_drift_cases() {
            let path = database_path(&directory, &format!("health-{name}.sqlite"));
            let store = open(&path).await;
            sqlx::raw_sql(sql)
                .execute(test_support::pool(&store))
                .await
                .expect("tamper full schema definition");
            let health = store.health().await.expect("schema drift health report");
            assert!(!health.is_healthy());
            assert_eq!(health.migration_errors.len(), 1);
            assert!(health.migration_errors[0].contains("schema definitions"));
            store.close().await.expect("drifted store closes");
        }
    }

    #[tokio::test]
    async fn health_reports_application_id_drift() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "health-application-id.sqlite")).await;
        sqlx::query("PRAGMA application_id = 0")
            .execute(test_support::pool(&store))
            .await
            .expect("tamper application id");

        let health = store.health().await.expect("application id health report");
        assert_eq!(health.application_id, 0);
        assert!(!health.is_healthy());
        store.close().await.expect("drifted store closes");
    }

    #[tokio::test]
    async fn health_reports_user_version_drift() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "user-version-health.sqlite");
        let store = open(&path).await;
        sqlx::query("PRAGMA user_version = 1")
            .execute(test_support::pool(&store))
            .await
            .expect("tamper SQLite user version");
        let health = store.health().await.expect("read user-version health");
        assert!(!health.is_healthy());
        assert!(
            health
                .migration_errors
                .iter()
                .any(|error| error.contains("user_version 1 does not match migration version 2"))
        );
        store
            .close()
            .await
            .expect("user-version drift store closes");
    }

    #[tokio::test]
    async fn nonempty_foreign_database_is_not_claimed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "foreign.sqlite");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("create foreign database");
        connection
            .execute("CREATE TABLE foreign_application_data(id INTEGER PRIMARY KEY)")
            .await
            .expect("create foreign schema");
        connection.close().await.expect("close foreign database");
        make_private_file(&path);

        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("foreign database is rejected");
        assert_eq!(
            error,
            StateError::InvalidValue {
                field: "SQLite application id",
                reason: "unclaimed database is not empty",
            }
        );
        let options = SqliteConnectOptions::new().filename(&path);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("reopen foreign database");
        let journal_mode = sqlx::query_scalar::<_, String>("PRAGMA journal_mode")
            .fetch_one(&mut connection)
            .await
            .expect("read foreign journal mode");
        assert_eq!(journal_mode, "delete");
        connection.close().await.expect("close foreign database");
    }

    #[tokio::test]
    async fn backup_and_restore_preserve_same_version_snapshot() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "source.sqlite");
        let backup_path = database_path(&directory, "snapshot backup.sqlite");
        let restored_path = database_path(&directory, "restored.sqlite");
        let source = open(&source_path).await;
        let record = session("session-in-backup", 1);
        source
            .sessions()
            .create(&record)
            .await
            .expect("create session");
        source.backup_to(&backup_path).await.expect("create backup");
        StateStore::restore_backup(&backup_path, &restored_path)
            .await
            .expect("restore backup");

        let restored = open(&restored_path).await;
        assert_eq!(
            restored
                .sessions()
                .get(&record.id)
                .await
                .expect("read restored session"),
            Some(record)
        );
        assert_eq!(
            source.health().await.expect("source health").schema_version,
            restored
                .health()
                .await
                .expect("restored health")
                .schema_version
        );
        restored.close().await.expect("restored store closes");
        source.close().await.expect("source store closes");
    }

    #[tokio::test]
    async fn published_backup_remains_writer_excluded_until_final_handoff() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "handoff-source.sqlite");
        let backup_path = database_path(&directory, "handoff-backup.sqlite");
        let restored_path = database_path(&directory, "handoff-restored.sqlite");
        let source = std::sync::Arc::new(open(&source_path).await);
        let (entered, release) = test_support::set_published_handoff_barrier(&backup_path);
        let backup_source = std::sync::Arc::clone(&source);
        let backup_destination = backup_path.clone();
        let backup =
            tokio::spawn(async move { backup_source.backup_to(&backup_destination).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("backup reaches final published handoff");
        let competing = StateStore::open(StoreConfig::new(&backup_path))
            .await
            .err()
            .expect("published backup remains writer-excluded");
        assert!(
            matches!(competing, StateError::StoreLocked { .. })
                || matches!(
                    competing,
                    StateError::InvalidBackup { ref reason, .. }
                        if reason.contains("restore_backup")
                )
        );
        assert!(!sidecar(&backup_path, "-wal").exists());
        assert!(!sidecar(&backup_path, "-shm").exists());
        release.notify_one();
        backup
            .await
            .expect("backup handoff task joins")
            .expect("backup handoff completes");
        StateStore::restore_backup(&backup_path, &restored_path)
            .await
            .expect("writer-excluded backup remains restorable");
        open(&restored_path)
            .await
            .close()
            .await
            .expect("handoff-restored store closes");
        std::sync::Arc::try_unwrap(source)
            .ok()
            .expect("backup handoff task releases source")
            .close()
            .await
            .expect("handoff source closes");
    }

    #[tokio::test]
    async fn opening_standalone_backup_is_rejected_without_invalidating_restore() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "sealed-open-source.sqlite");
        let backup_path = database_path(&directory, "sealed-open-backup.sqlite");
        let restored_path = database_path(&directory, "sealed-open-restored.sqlite");
        let source = open(&source_path).await;
        let record = session("sealed-open-record", 1);
        source
            .sessions()
            .create(&record)
            .await
            .expect("seed sealed-open source");
        source
            .backup_to(&backup_path)
            .await
            .expect("create sealed-open backup");
        let error = StateStore::open(StoreConfig::new(&backup_path))
            .await
            .err()
            .expect("standalone backup rejects live open");
        assert!(matches!(
            error,
            StateError::InvalidBackup { reason, .. }
                if reason.contains("restore_backup")
        ));
        StateStore::restore_backup(&backup_path, &restored_path)
            .await
            .expect("rejected live open preserves backup seal");
        let restored = open(&restored_path).await;
        assert_eq!(
            restored
                .sessions()
                .get(&record.id)
                .await
                .expect("read restored sealed-open record"),
            Some(record)
        );
        restored
            .close()
            .await
            .expect("sealed-open restored store closes");
        source.close().await.expect("sealed-open source closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restore_accepts_read_only_standalone_backup() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "read-only-source.sqlite");
        let backup_directory = directory.path().join("read-only-backup");
        fs::create_dir(&backup_directory).expect("create read-only backup directory");
        fs::set_permissions(&backup_directory, fs::Permissions::from_mode(0o700))
            .expect("make backup directory service-private");
        let backup_path = backup_directory.join("backup.sqlite");
        let destination = database_path(&directory, "read-only-restored.sqlite");
        let source = open(&source_path).await;
        source.backup_to(&backup_path).await.expect("create backup");
        source.close().await.expect("source store closes");
        fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o400))
            .expect("make backup read-only");

        StateStore::restore_backup(&backup_path, &destination)
            .await
            .expect("restore does not mutate read-only source");
        open(&destination)
            .await
            .close()
            .await
            .expect("restored store closes");
    }

    #[tokio::test]
    async fn post_publication_failure_reports_published_destination() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "publication-source.sqlite");
        let destination = database_path(&directory, "publication-destination.sqlite");
        let restored = database_path(&directory, "publication-restored.sqlite");
        let source = open(&source_path).await;
        test_support::fail_after_publication_once(&destination);

        let error = source
            .backup_to(&destination)
            .await
            .expect_err("injected publication failure is surfaced");
        assert!(
            matches!(error, StateError::PublicationUncertain { .. }),
            "unexpected publication failure: {error:?}"
        );
        assert!(destination.exists());
        assert!(!sidecar(&destination, "-wal").exists());
        assert!(!sidecar(&destination, "-shm").exists());
        assert!(!sidecar(&destination, "-journal").exists());
        StateStore::restore_backup(&destination, &restored)
            .await
            .expect("published destination remains restorable");
        open(&restored)
            .await
            .close()
            .await
            .expect("published destination remains valid");
        source.close().await.expect("source store closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn substituted_backup_temporary_never_mutates_victim() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "substitution-source.sqlite");
        let victim_path = database_path(&directory, "substitution-victim.sqlite");
        let destination = database_path(&directory, "substitution-destination.sqlite");
        let source = std::sync::Arc::new(open(&source_path).await);
        let victim = open(&victim_path).await;
        let victim_record = session("victim-session", 1);
        victim
            .sessions()
            .create(&victim_record)
            .await
            .expect("seed victim data");
        let owner_before = sqlx::query_scalar::<_, String>(
            "SELECT owner FROM claw_writer_lock WHERE singleton = 1",
        )
        .fetch_one(test_support::pool(&victim))
        .await
        .expect("read victim owner");

        let (temporary, entered, release) = test_support::set_snapshot_barrier(&destination);
        let backup_source = std::sync::Arc::clone(&source);
        let backup_destination = destination.clone();
        let mut backup =
            tokio::spawn(async move { backup_source.backup_to(&backup_destination).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("backup reaches pinned temporary barrier");
        let temporary = temporary
            .lock()
            .expect("snapshot temporary path lock poisoned")
            .clone()
            .expect("snapshot temporary path published");
        fs::remove_file(&temporary).expect("unlink pinned backup temporary");
        fs::hard_link(&victim_path, &temporary).expect("substitute victim hard link");
        release.notify_one();

        let backup_result = match tokio::time::timeout(Duration::from_secs(2), &mut backup).await {
            Ok(join) => join.expect("backup substitution task joins"),
            Err(_) => {
                backup.abort();
                let _ = backup.await;
                panic!("backup substitution regression exceeded two seconds");
            }
        };
        assert!(backup_result.is_err());
        assert!(
            temporary.exists(),
            "identity-bound cleanup must not delete the substituted victim link"
        );
        assert!(!destination.exists());
        let owner_after = sqlx::query_scalar::<_, String>(
            "SELECT owner FROM claw_writer_lock WHERE singleton = 1",
        )
        .fetch_one(test_support::pool(&victim))
        .await
        .expect("reread victim owner");
        assert_eq!(owner_after, owner_before);
        assert_eq!(
            victim
                .sessions()
                .get(&victim_record.id)
                .await
                .expect("read untouched victim data"),
            Some(victim_record)
        );
        victim.close().await.expect("victim closes");
        let source = std::sync::Arc::try_unwrap(source)
            .unwrap_or_else(|_| panic!("backup task retained source"));
        source.close().await.expect("source closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_restore_removes_unpublished_writer_lock_record() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "lock-cleanup-source.sqlite");
        let backup_path = database_path(&directory, "lock-cleanup-backup.sqlite");
        let destination = database_path(&directory, "lock-cleanup-destination.sqlite");
        let source = open(&source_path).await;
        source
            .backup_to(&backup_path)
            .await
            .expect("create restore source");
        let before = test_support::writer_lock_records(&destination);
        test_support::create_competing_destination_once(&destination);
        assert!(
            StateStore::restore_backup(&backup_path, &destination)
                .await
                .is_err()
        );
        assert_eq!(
            test_support::writer_lock_records(&destination),
            before,
            "failed restore must not leak a persistent writer-lock record"
        );
        source.close().await.expect("source closes");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn preexisting_partial_windows_sidecar_generation_is_not_adopted() {
        use std::io::Write as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "partial-generation.sqlite");
        let saved_wal = database_path(&directory, "saved-wal");
        let saved_shm = database_path(&directory, "saved-shm");
        let store = open(&path).await;
        store
            .sessions()
            .create(&session("partial-generation-row", 1))
            .await
            .expect("create WAL content");
        fs::copy(sidecar(&path, "-wal"), &saved_wal).expect("save WAL");
        fs::copy(sidecar(&path, "-shm"), &saved_shm).expect("save SHM");
        store.close().await.expect("source closes");
        fs::copy(&saved_wal, sidecar(&path, "-wal")).expect("restore WAL fixture");
        fs::copy(&saved_shm, sidecar(&path, "-shm")).expect("restore SHM fixture");
        test_support::secure_windows_file_fixture(&sidecar(&path, "-wal"));
        test_support::secure_windows_file_fixture(&sidecar(&path, "-shm"));
        let mut generation_path = sidecar(&path, "-wal").as_os_str().to_owned();
        generation_path.push(":gta-claw-generation");
        let generation_path = PathBuf::from(generation_path);
        fs::File::create(&generation_path)
            .and_then(|mut file| file.write_all(b"partial"))
            .expect("create partial generation ADS");

        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("partial preexisting generation is rejected");
        assert!(matches!(
            error,
            StateError::InvalidPath {
                reason: "SQLite sidecar generation is incomplete",
                ..
            }
        ));
        assert_eq!(
            fs::read(&generation_path).expect("read unchanged partial ADS"),
            b"partial"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backup_parent_replacement_aborts_and_cleans_pinned_staging() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "parent-pinned-source.sqlite");
        let source = std::sync::Arc::new(open(&source_path).await);
        let destination_parent = directory.path().join("private-backups");
        fs::create_dir(&destination_parent).expect("create private backup directory");
        fs::set_permissions(&destination_parent, fs::Permissions::from_mode(0o700))
            .expect("secure private backup directory");
        let moved_parent = directory.path().join("private-backups-moved");
        let destination = destination_parent.join("snapshot.sqlite");
        let (temporary, entered, release) = test_support::set_snapshot_barrier(&destination);
        let backup_source = std::sync::Arc::clone(&source);
        let backup_destination = destination.clone();
        let mut backup =
            tokio::spawn(async move { backup_source.backup_to(&backup_destination).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("backup reaches pinned-parent barrier");
        let temporary = temporary
            .lock()
            .expect("snapshot temporary path lock poisoned")
            .clone()
            .expect("snapshot temporary path published");
        fs::rename(&destination_parent, &moved_parent).expect("detach pinned backup parent");
        fs::create_dir(&destination_parent).expect("create replacement backup parent");
        fs::set_permissions(&destination_parent, fs::Permissions::from_mode(0o700))
            .expect("secure replacement backup parent");
        release.notify_one();
        let error = tokio::time::timeout(Duration::from_secs(2), &mut backup)
            .await
            .expect("backup parent replacement remains bounded")
            .expect("backup parent replacement task joins")
            .expect_err("backup rejects replaced destination parent");
        assert!(matches!(
            error,
            StateError::InvalidPath {
                reason: "state directory path changed after its identity was verified",
                ..
            }
        ));
        assert!(!destination.exists());
        for artifact in [
            temporary.clone(),
            sidecar(&temporary, "-wal"),
            sidecar(&temporary, "-shm"),
            sidecar(&temporary, "-journal"),
        ] {
            assert!(
                !artifact.exists(),
                "pinned staging artifact must be removed through the held parent: {}",
                artifact.display()
            );
        }
        let source = std::sync::Arc::try_unwrap(source)
            .unwrap_or_else(|_| panic!("backup task retained source store"));
        source.close().await.expect("backup source closes");
    }

    #[tokio::test]
    async fn no_replace_failure_preserves_competing_destination() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "publication-race-source.sqlite");
        let destination = database_path(&directory, "publication-race-destination.sqlite");
        let source = open(&source_path).await;
        test_support::create_competing_destination_once(&destination);

        let error = source
            .backup_to(&destination)
            .await
            .expect_err("competing destination wins no-replace race");
        assert!(matches!(error, StateError::BackupDestinationExists { .. }));
        assert_eq!(
            fs::read(&destination).expect("read competing destination"),
            b"other publisher"
        );
        assert!(!sidecar(&destination, "-wal").exists());
        assert!(!sidecar(&destination, "-shm").exists());
        assert!(!sidecar(&destination, "-journal").exists());
        source.close().await.expect("source store closes");
    }

    #[tokio::test]
    async fn zero_length_destination_is_not_treated_as_absent() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "zero-destination-source.sqlite");
        let destination = database_path(&directory, "zero-destination.sqlite");
        let source = open(&source_path).await;
        fs::File::create(&destination).expect("create zero-length destination");
        make_private_file(&destination);
        assert!(matches!(
            source.backup_to(&destination).await,
            Err(StateError::BackupDestinationExists { .. })
        ));
        assert_eq!(
            fs::metadata(&destination)
                .expect("inspect zero-length destination")
                .len(),
            0
        );
        source
            .close()
            .await
            .expect("zero-destination source closes");
    }

    #[tokio::test]
    async fn published_snapshot_guard_cannot_truncate_backup() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "published-guard-source.sqlite");
        let destination = database_path(&directory, "published-guard-backup.sqlite");
        let source = open(&source_path).await;
        source.backup_to(&destination).await.expect("create backup");
        let before = fs::read(&destination).expect("read published backup");
        test_support::drop_disarmed_snapshot_guard(&destination).await;
        assert_eq!(
            fs::read(&destination).expect("reread published backup"),
            before
        );
        source.close().await.expect("published-guard source closes");
    }

    #[tokio::test]
    async fn in_flight_bound_destination_is_rejected_before_sqlite_open() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "bound-open-source.sqlite");
        let destination = database_path(&directory, "bound-open-backup.sqlite");
        let restored = database_path(&directory, "bound-open-restored.sqlite");
        let source = std::sync::Arc::new(open(&source_path).await);
        let (entered, release) = test_support::set_backup_capture_barrier(&destination);
        let backup_source = std::sync::Arc::clone(&source);
        let backup_destination = destination.clone();
        let backup =
            tokio::spawn(async move { backup_source.backup_to(&backup_destination).await });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("backup reaches in-memory capture boundary");
        let error = StateStore::open(StoreConfig::new(&destination))
            .await
            .err()
            .expect("staging-bound destination must be rejected before SQLite");
        assert!(matches!(
            error,
            StateError::InvalidPath {
                reason: "snapshot publication is still staging-bound",
                ..
            }
        ));
        release.store(true, std::sync::atomic::Ordering::Release);
        backup
            .await
            .expect("bound backup task joins")
            .expect("bound backup publishes");
        StateStore::restore_backup(&destination, &restored)
            .await
            .expect("published bound backup remains restorable");
        let source = std::sync::Arc::try_unwrap(source)
            .unwrap_or_else(|_| panic!("bound backup retained source"));
        source.close().await.expect("bound-open source closes");
    }

    #[tokio::test]
    async fn concurrent_snapshot_memory_saturation_is_bounded() {
        test_support::assert_snapshot_memory_saturation().await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_source_removal_failure_reports_published_destination() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "windows-publication-source.sqlite");
        let destination = database_path(&directory, "windows-publication-destination.sqlite");
        let restored = database_path(&directory, "windows-publication-restored.sqlite");
        let source = open(&source_path).await;
        test_support::fail_windows_source_removal_once(&destination);

        let error = source
            .backup_to(&destination)
            .await
            .expect_err("injected Windows source removal failure is surfaced");
        assert!(matches!(error, StateError::PublicationUncertain { .. }));
        assert!(destination.exists());
        assert!(!sidecar(&destination, "-wal").exists());
        assert!(!sidecar(&destination, "-shm").exists());
        assert!(!sidecar(&destination, "-journal").exists());
        StateStore::restore_backup(&destination, &restored)
            .await
            .expect("Windows published destination remains restorable");
        open(&restored)
            .await
            .close()
            .await
            .expect("Windows published destination remains valid");
        source.close().await.expect("source store closes");
    }

    #[tokio::test]
    async fn backup_materializes_committed_wal_content() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "wal-source.sqlite");
        let backup_path = database_path(&directory, "wal-backup.sqlite");
        let restored_path = database_path(&directory, "wal-restored.sqlite");
        let source = open(&source_path).await;
        source.close().await.expect("seed WAL source closes");
        let options = SqliteConnectOptions::new()
            .filename(&source_path)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("open standalone WAL writer");
        connection
            .execute("PRAGMA wal_autocheckpoint = 0")
            .await
            .expect("disable automatic checkpoint");
        connection
            .execute(
                "INSERT INTO sessions(id, status, created_at_ms, updated_at_ms, version)
                 VALUES ('wal-session', 'active', 1, 1, 1)",
            )
            .await
            .expect("commit row to WAL");
        assert!(sidecar(&source_path, "-wal").exists());
        test_support::trust_existing_sidecars(&source_path);

        let managed = open(&source_path).await;
        managed
            .backup_to(&backup_path)
            .await
            .expect("backup includes committed WAL content");
        managed.close().await.expect("managed WAL source closes");
        StateStore::restore_backup(&backup_path, &restored_path)
            .await
            .expect("restore standalone WAL backup");
        let restored = open(&restored_path).await;
        let id = SessionId::new("wal-session").expect("valid test session");
        assert!(
            restored
                .sessions()
                .get(&id)
                .await
                .expect("read restored WAL row")
                .is_some()
        );
        restored.close().await.expect("restored store closes");
        connection.close().await.expect("WAL writer closes");
    }

    #[tokio::test]
    async fn restore_remains_consistent_during_concurrent_checkpoint() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "checkpoint-source.sqlite");
        let backup_path = database_path(&directory, "checkpoint-backup.sqlite");
        let restored_path = database_path(&directory, "checkpoint-restored.sqlite");
        open(&source_path)
            .await
            .close()
            .await
            .expect("seed checkpoint source closes");
        let options = SqliteConnectOptions::new()
            .filename(&source_path)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let mut writer = SqliteConnection::connect_with(&options)
            .await
            .expect("open checkpoint writer");
        writer
            .execute("PRAGMA wal_autocheckpoint = 0")
            .await
            .expect("disable checkpointing");
        writer
            .execute(
                "WITH RECURSIVE n(value) AS (
                    VALUES(1) UNION ALL SELECT value + 1 FROM n WHERE value < 200
                 )
                 INSERT INTO sessions(id, status, created_at_ms, updated_at_ms, version)
                 SELECT printf('checkpoint-%03d', value), 'active', value, value, 1 FROM n",
            )
            .await
            .expect("commit checkpoint rows to WAL");
        let mut checkpointer = SqliteConnection::connect_with(&options)
            .await
            .expect("open concurrent checkpointer");
        test_support::trust_existing_sidecars(&source_path);
        let managed = open(&source_path).await;
        let (capture_entered, capture_release) =
            test_support::set_backup_capture_barrier(&backup_path);
        let (backup, checkpoint) = tokio::join!(managed.backup_to(&backup_path), async {
            capture_entered.notified().await;
            let checkpoint = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .execute(&mut checkpointer)
                .await;
            capture_release.store(true, std::sync::atomic::Ordering::Release);
            checkpoint
        });
        backup.expect("consistent backup completes");
        checkpoint.expect("concurrent checkpoint completes");
        managed.close().await.expect("managed source closes");
        writer.close().await.expect("checkpoint writer closes");
        checkpointer.close().await.expect("checkpointer closes");
        StateStore::restore_backup(&backup_path, &restored_path)
            .await
            .expect("restore checkpoint-raced backup");

        let restored = open(&restored_path).await;
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sessions")
            .fetch_one(test_support::pool(&restored))
            .await
            .expect("count checkpoint-restored rows");
        assert_eq!(count, 200);
        restored.close().await.expect("restored store closes");
    }

    #[tokio::test]
    async fn restore_rejects_mutation_after_seal_validation() {
        use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "restore-mutation-source.sqlite");
        let backup_path = database_path(&directory, "restore-mutation-backup.sqlite");
        let destination = database_path(&directory, "restore-mutation-destination.sqlite");
        let source = open(&source_path).await;
        source.backup_to(&backup_path).await.expect("create backup");
        let (entered, release) = test_support::set_restore_read_barrier(&destination);
        let restore_backup = backup_path.clone();
        let restore_destination = destination.clone();
        let restore = tokio::spawn(async move {
            StateStore::restore_backup(restore_backup, restore_destination).await
        });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("restore reaches authenticated-byte read barrier");
        let mut backup = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&backup_path)
            .expect("open backup for transient mutation");
        backup
            .seek(SeekFrom::Start(100))
            .expect("seek transient mutation byte");
        let mut byte = [0_u8; 1];
        backup
            .read_exact(&mut byte)
            .expect("read transient mutation byte");
        byte[0] ^= 0xff;
        backup
            .seek(SeekFrom::Start(100))
            .and_then(|_| backup.write_all(&byte))
            .and_then(|_| backup.sync_all())
            .expect("persist transient source mutation");
        release.notify_one();
        let error = restore
            .await
            .expect("restore mutation task joins")
            .expect_err("mutated authenticated bytes are rejected");
        assert!(matches!(error, StateError::InvalidBackup { .. }));
        assert!(!destination.exists());
        source
            .close()
            .await
            .expect("restore mutation source closes");
    }

    #[tokio::test]
    async fn backup_timeout_removes_staging_without_late_publication() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "backup-timeout-source.sqlite");
        let destination = database_path(&directory, "backup-timeout.sqlite");
        let source = StateStore::open(
            StoreConfig::new(&source_path).with_operation_timeout(Duration::from_millis(500)),
        )
        .await
        .expect("backup timeout source opens");
        let (temporary, entered, release) = test_support::set_snapshot_barrier(&destination);
        let error = tokio::time::timeout(Duration::from_secs(2), source.backup_to(&destination))
            .await
            .expect("backup timeout remains externally bounded")
            .expect_err("gated backup reaches configured timeout");
        assert_eq!(
            error,
            StateError::OperationTimedOut {
                operation: "SQLite backup",
                timeout_ms: 500,
            }
        );
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("backup reached deterministic post-capture gate");
        release.notify_one();
        test_support::clear_snapshot_barrier(&destination);
        let temporary = temporary
            .lock()
            .expect("snapshot temporary path lock poisoned")
            .clone()
            .expect("snapshot temporary path was published");
        assert!(!destination.exists());
        assert!(!temporary.exists());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!destination.exists());
        assert!(!temporary.exists());
        source.close().await.expect("backup timeout source closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exhausted_quarantine_rejects_before_backup_output_creation() {
        let directory = tempfile::tempdir().expect("quarantine capacity directory");
        let source_path = database_path(&directory, "quarantine-source.sqlite");
        let destination = database_path(&directory, "quarantine-destination.sqlite");
        let source = open(&source_path).await;
        for index in 0..64 {
            fs::write(
                directory
                    .path()
                    .join(format!(".gta-claw-quarantine-existing-{index:02}")),
                b"",
            )
            .expect("create quarantine tombstone");
        }
        let error = source
            .backup_to(&destination)
            .await
            .expect_err("exhausted quarantine rejects backup");
        assert!(matches!(error, StateError::InvalidPath { .. }));
        assert!(!destination.exists());
        for suffix in ["-wal", "-shm", "-journal"] {
            assert!(!sidecar(&destination, suffix).exists());
        }
        source.close().await.expect("close quarantine source");
    }

    #[tokio::test]
    async fn publication_deadline_is_fenced_immediately_before_and_after_marker_removal() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "publication-fence-source.sqlite");
        let prepublication = database_path(&directory, "publication-fence-before.sqlite");
        let postpublication = database_path(&directory, "publication-fence-after.sqlite");
        let restored = database_path(&directory, "publication-fence-restored.sqlite");
        let source = StateStore::open(
            StoreConfig::new(&source_path).with_operation_timeout(Duration::from_secs(2)),
        )
        .await
        .expect("publication fence source opens");

        test_support::expire_publication_deadline_once(&prepublication, 1);
        assert_eq!(
            source
                .backup_to(&prepublication)
                .await
                .expect_err("prepublication deadline fence rejects publication"),
            StateError::OperationTimedOut {
                operation: "SQLite backup",
                timeout_ms: 2_000,
            }
        );
        assert!(
            !prepublication.exists(),
            "prepublication expiry reclaims the exact staging object"
        );

        test_support::expire_publication_deadline_once(&postpublication, 2);
        let error = source
            .backup_to(&postpublication)
            .await
            .expect_err("postpublication deadline fence cannot report success");
        assert!(
            matches!(
                error,
                StateError::PublicationUncertain { ref path, ref reason }
                    if path.file_name() == postpublication.file_name()
                        && reason.contains("deadline expired")
            ),
            "unexpected postpublication deadline error: {error:?}"
        );
        assert!(
            postpublication.exists(),
            "postpublication expiry never truncates the published object"
        );
        StateStore::restore_backup(&postpublication, &restored)
            .await
            .expect("deadline-published snapshot remains a valid exact backup");
        open(&restored)
            .await
            .close()
            .await
            .expect("restored publication-fence store closes");
        for (stage, name) in [(3_u8, "durable-sync"), (4_u8, "final-handoff")] {
            let published = database_path(&directory, &format!("publication-fence-{name}.sqlite"));
            let restored = database_path(
                &directory,
                &format!("publication-fence-{name}-restored.sqlite"),
            );
            test_support::expire_publication_deadline_once(&published, stage);
            let error = source
                .backup_to(&published)
                .await
                .expect_err("late durable publication stage cannot report success");
            assert!(matches!(
                error,
                StateError::PublicationUncertain { ref reason, .. }
                    if reason.contains("deadline") || reason.contains("validation")
            ));
            assert!(
                published.exists(),
                "late durable publication remains preserved"
            );
            StateStore::restore_backup(&published, &restored)
                .await
                .expect("late durable publication remains restorable");
            open(&restored)
                .await
                .close()
                .await
                .expect("late durable publication restore closes");
        }
        source
            .close()
            .await
            .expect("publication fence source closes");
    }

    #[tokio::test]
    async fn cancelling_backup_and_restore_cleans_staging_and_keeps_pool_usable() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "cancel-source.sqlite");
        let backup_path = database_path(&directory, "cancel-backup.sqlite");
        let restore_path = database_path(&directory, "cancel-restore.sqlite");
        let source = std::sync::Arc::new(open(&source_path).await);

        let (backup_temporary, entered, _release) =
            test_support::set_snapshot_barrier(&backup_path);
        let backup_source = std::sync::Arc::clone(&source);
        let backup_destination = backup_path.clone();
        let backup =
            tokio::spawn(async move { backup_source.backup_to(&backup_destination).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("backup reaches cancellation barrier");
        let backup_temporary = backup_temporary
            .lock()
            .expect("backup temporary path lock poisoned")
            .clone()
            .expect("backup temporary path published");
        backup.abort();
        assert!(
            backup
                .await
                .expect_err("cancelled backup task")
                .is_cancelled()
        );
        test_support::clear_snapshot_barrier(&backup_path);
        wait_for_cleanup_absence(&[&backup_path, &backup_temporary]).await;
        source
            .sessions()
            .create(&session("post-cancel-backup", 1))
            .await
            .expect("cancelled backup leaves pool usable");

        source
            .backup_to(&backup_path)
            .await
            .expect("create restore cancellation source");
        let (restore_temporary, entered, _release) =
            test_support::set_snapshot_barrier(&restore_path);
        let restore_source = backup_path.clone();
        let restore_destination = restore_path.clone();
        let restore = tokio::spawn(async move {
            StateStore::restore_backup(&restore_source, &restore_destination).await
        });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("restore reaches cancellation barrier");
        let restore_temporary = restore_temporary
            .lock()
            .expect("restore temporary path lock poisoned")
            .clone()
            .expect("restore temporary path published");
        restore.abort();
        assert!(
            restore
                .await
                .expect_err("cancelled restore task")
                .is_cancelled()
        );
        test_support::clear_snapshot_barrier(&restore_path);
        wait_for_cleanup_absence(&[&restore_path, &restore_temporary]).await;

        let source = std::sync::Arc::try_unwrap(source)
            .unwrap_or_else(|_| panic!("cancelled operations retained source store"));
        source.close().await.expect("cancellation source closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backup_rejects_source_replaced_while_capture_is_in_flight() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "capture-replaced-source.sqlite");
        let detached = database_path(&directory, "capture-replaced-source.detached");
        let destination = database_path(&directory, "capture-replaced-backup.sqlite");
        let source = open(&source_path).await;
        let (entered, release) = test_support::set_backup_capture_barrier(&destination);
        let (backup, ()) = tokio::join!(source.backup_to(&destination), async {
            entered.notified().await;
            fs::rename(&source_path, &detached).expect("detach in-flight backup source");
            fs::write(&source_path, b"replacement").expect("replace in-flight source pathname");
            make_private_file(&source_path);
            release.store(true, std::sync::atomic::Ordering::Release);
        });
        let error = backup.expect_err("post-capture source replacement fails closed");
        assert!(matches!(error, StateError::InvalidPath { .. }));
        assert!(!destination.exists());
        fs::remove_file(&source_path).expect("remove replacement source");
        fs::rename(&detached, &source_path).expect("restore original source identity");
        source
            .close()
            .await
            .expect("source replacement store closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sqlite_and_snapshot_artifacts_remain_mode_0600() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "mode-source.sqlite");
        let backup_path = database_path(&directory, "mode-backup.sqlite");
        let restored_path = database_path(&directory, "mode-restored.sqlite");
        let source = open(&source_path).await;
        source
            .sessions()
            .create(&session("mode-row", 1))
            .await
            .expect("create WAL-backed mode row");
        source
            .backup_to(&backup_path)
            .await
            .expect("create private backup");
        for artifact in [
            source_path.clone(),
            sidecar(&source_path, "-wal"),
            sidecar(&source_path, "-shm"),
            backup_path.clone(),
        ] {
            assert_eq!(
                fs::symlink_metadata(&artifact)
                    .expect("inspect private artifact mode")
                    .mode()
                    & 0o7777,
                0o600,
                "artifact is not private: {}",
                artifact.display()
            );
        }
        StateStore::restore_backup(&backup_path, &restored_path)
            .await
            .expect("restore private backup");
        let restored = open(&restored_path).await;
        for artifact in [
            restored_path.clone(),
            sidecar(&restored_path, "-wal"),
            sidecar(&restored_path, "-shm"),
        ] {
            assert_eq!(
                fs::symlink_metadata(&artifact)
                    .expect("inspect restored artifact mode")
                    .mode()
                    & 0o7777,
                0o600,
                "restored artifact is not private: {}",
                artifact.display()
            );
        }
        restored.close().await.expect("restored mode store closes");
        source.close().await.expect("source mode store closes");
    }

    #[tokio::test]
    async fn forged_or_copied_snapshot_markers_lack_trusted_provenance() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let managed_path = database_path(&directory, "managed-marker.sqlite");
        let forged_destination = database_path(&directory, "forged-destination.sqlite");
        open(&managed_path)
            .await
            .close()
            .await
            .expect("managed store closes");
        execute_direct(
            &managed_path,
            "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
             VALUES (1, 'gta-claw-standalone-snapshot-v1', 0)",
        )
        .await;
        let forged = StateStore::restore_backup(&managed_path, &forged_destination)
            .await
            .expect_err("self-attested managed database is rejected");
        assert!(matches!(forged, StateError::BackupNotPortable { .. }));
        assert!(!forged_destination.exists());

        let source_path = database_path(&directory, "sealed-source.sqlite");
        let backup_path = database_path(&directory, "sealed-backup.sqlite");
        let copied_path = database_path(&directory, "copied-backup.sqlite");
        let copied_destination = database_path(&directory, "copied-destination.sqlite");
        let source = open(&source_path).await;
        source
            .backup_to(&backup_path)
            .await
            .expect("create genuinely sealed backup");
        fs::copy(&backup_path, &copied_path).expect("copy sealed backup bytes");
        #[cfg(windows)]
        test_support::secure_windows_file_fixture(&copied_path);

        #[cfg(unix)]
        {
            use xattr::FileExt as _;

            let source_file = fs::File::open(&backup_path).expect("open source backup seal");
            let seal_id = source_file
                .get_xattr("user.gta-claw.backup-seal-id")
                .expect("read source backup seal")
                .expect("source backup seal exists");
            let copied_file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&copied_path)
                .expect("open copied backup");
            copied_file
                .set_xattr("user.gta-claw.backup-seal-id", &seal_id)
                .expect("copy untrusted seal index");
        }
        #[cfg(windows)]
        {
            let seal_path = |path: &Path| {
                let mut seal = path.as_os_str().to_owned();
                seal.push(":gta-claw-backup-seal");
                PathBuf::from(seal)
            };
            let protected =
                fs::read(seal_path(&backup_path)).expect("read protected source backup seal");
            fs::write(seal_path(&copied_path), protected)
                .expect("copy protected seal to a different file identity");
        }

        let copied = StateStore::restore_backup(&copied_path, &copied_destination)
            .await
            .expect_err("copied marker and seal cannot authenticate a new inode");
        assert!(matches!(copied, StateError::InvalidBackup { .. }));
        assert!(!copied_destination.exists());

        let tampered_destination = database_path(&directory, "tampered-destination.sqlite");
        execute_direct(
            &backup_path,
            "INSERT INTO sessions(id, status, created_at_ms, updated_at_ms, version)
             VALUES ('post-seal-tamper', 'active', 1, 1, 1)",
        )
        .await;
        let tampered = StateStore::restore_backup(&backup_path, &tampered_destination)
            .await
            .expect_err("schema-valid post-seal mutation is rejected");
        assert!(matches!(tampered, StateError::InvalidBackup { .. }));
        assert!(!tampered_destination.exists());
        source.close().await.expect("source closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restore_rejects_hardlink_alias_with_committed_wal() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "wal-hardlink-source.sqlite");
        let alias = database_path(&directory, "wal-hardlink-alias.sqlite");
        let destination = database_path(&directory, "wal-hardlink-restored.sqlite");
        let source = open(&source_path).await;
        source.close().await.expect("seed hardlink source closes");
        let options = SqliteConnectOptions::new()
            .filename(&source_path)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("open hardlink WAL writer");
        let mut reader = SqliteConnection::connect_with(&options)
            .await
            .expect("open hardlink WAL reader");
        connection
            .execute("PRAGMA wal_autocheckpoint = 0")
            .await
            .expect("disable automatic checkpoint");
        reader
            .execute("BEGIN")
            .await
            .expect("begin reader snapshot");
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sessions")
            .fetch_one(&mut reader)
            .await
            .expect("establish reader snapshot");
        connection
            .execute(
                "INSERT INTO sessions(id, status, created_at_ms, updated_at_ms, version)
                 VALUES ('hardlink-wal-session', 'active', 1, 1, 1)",
            )
            .await
            .expect("commit hardlink row to WAL");
        assert!(sidecar(&source_path, "-wal").exists());
        fs::hard_link(&source_path, &alias).expect("create WAL source hard link");
        fs::remove_file(&source_path).expect("unlink original WAL database main file");
        assert_eq!(
            fs::metadata(&alias)
                .expect("inspect alias link count")
                .nlink(),
            1
        );

        let alias_options = SqliteConnectOptions::new()
            .filename(&alias)
            .read_only(true)
            .immutable(true);
        let mut alias_connection = SqliteConnection::connect_with(&alias_options)
            .await
            .expect("open detached alias without original sidecars");
        let alias_rows = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sessions WHERE id = ?")
            .bind("hardlink-wal-session")
            .fetch_one(&mut alias_connection)
            .await
            .expect("read stale detached alias");
        assert_eq!(
            alias_rows, 0,
            "detached alias must demonstrably miss WAL row"
        );
        alias_connection
            .close()
            .await
            .expect("close detached alias");

        let error = StateStore::restore_backup(&alias, &destination)
            .await
            .expect_err("detached WAL alias without snapshot provenance is rejected");
        assert!(matches!(error, StateError::InvalidBackup { .. }));
        assert!(!destination.exists());
        reader
            .execute("ROLLBACK")
            .await
            .expect("release reader snapshot");
        reader.close().await.expect("close WAL reader");
        connection
            .close()
            .await
            .expect("hardlink WAL writer closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn transplanted_and_recreated_sidecars_fail_closed() {
        use std::os::unix::fs::PermissionsExt as _;
        use xattr::FileExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let victim_path = database_path(&directory, "sidecar-victim.sqlite");
        let clone_path = database_path(&directory, "sidecar-clone.sqlite");
        let victim = open(&victim_path).await;
        victim.close().await.expect("seed sidecar victim closes");
        let clone = open(&clone_path).await;
        clone
            .sessions()
            .create(&session("clone-row", 1))
            .await
            .expect("create clone WAL row");
        let clone_wal = sidecar(&clone_path, "-wal");
        let clone_shm = sidecar(&clone_path, "-shm");
        let victim_wal = sidecar(&victim_path, "-wal");
        let victim_shm = sidecar(&victim_path, "-shm");
        for (source, destination) in [(&clone_wal, &victim_wal), (&clone_shm, &victim_shm)] {
            fs::copy(source, destination).expect("transplant valid clone sidecar");
            fs::set_permissions(destination, fs::Permissions::from_mode(0o600))
                .expect("preserve private transplanted sidecar mode");
            let generation = fs::File::open(source)
                .expect("open clone sidecar")
                .get_xattr("user.gta-claw.sidecar-generation")
                .expect("read clone sidecar generation")
                .expect("clone sidecar generation exists");
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(destination)
                .expect("open transplanted sidecar")
                .set_xattr("user.gta-claw.sidecar-generation", &generation)
                .expect("copy clone sidecar generation");
        }

        let before = database_artifact_bytes(&victim_path);
        let error = StateStore::open(StoreConfig::new(&victim_path))
            .await
            .err()
            .expect("transplanted sidecars are rejected");
        assert!(matches!(
            error,
            StateError::InvalidPath {
                reason: "SQLite sidecar belongs to a different database generation",
                ..
            }
        ));
        assert_database_artifacts_unchanged(&before, &database_artifact_bytes(&victim_path));
        fs::remove_file(&victim_wal).expect("remove transplanted WAL");
        fs::remove_file(&victim_shm).expect("remove transplanted SHM");

        let live = std::sync::Arc::new(open(&victim_path).await);
        let owner = test_support::owner(&live).to_owned();
        let (entered, release) = crate::repository::test_support::set_commit_barrier(&owner);
        let record = session("recreated-sidecar-row", 2);
        let record_id = record.id.clone();
        let writer_store = std::sync::Arc::clone(&live);
        let mut writer = tokio::spawn(async move { writer_store.sessions().create(&record).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("writer reaches sidecar commit boundary");
        fs::remove_file(&victim_wal).expect("unlink live victim WAL path");
        fs::copy(&clone_wal, &victim_wal).expect("recreate victim WAL from clone");
        fs::set_permissions(&victim_wal, fs::Permissions::from_mode(0o600))
            .expect("secure recreated WAL");
        let generation = fs::File::open(&clone_wal)
            .expect("open clone WAL generation")
            .get_xattr("user.gta-claw.sidecar-generation")
            .expect("read clone WAL generation")
            .expect("clone WAL generation exists");
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&victim_wal)
            .expect("open recreated WAL")
            .set_xattr("user.gta-claw.sidecar-generation", &generation)
            .expect("attach clone generation to recreated WAL");
        release.notify_one();
        let error = tokio::time::timeout(Duration::from_secs(2), &mut writer)
            .await
            .expect("sidecar commit rejection remains bounded")
            .expect("sidecar writer task joins")
            .expect_err("commit hook rejects recreated WAL generation");
        let StateError::Database(failure) = error else {
            panic!("expected commit-hook constraint, received {error:?}");
        };
        assert_eq!(failure.operation(), "commit session create");
        assert_eq!(failure.code(), Some("531"));
        assert!(
            live.sessions()
                .get(&record_id)
                .await
                .expect("read recreated-sidecar rollback")
                .is_none()
        );
        fs::remove_file(&victim_wal).expect("remove rejected recreated WAL");
        let live = std::sync::Arc::try_unwrap(live)
            .unwrap_or_else(|_| panic!("writer retained live sidecar store"));
        assert!(matches!(
            live.close().await,
            Err(StateError::CloseDegraded {
                os_lock_released: true,
                ..
            })
        ));
        clone.close().await.expect("clone store closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn preexisting_untagged_unix_sidecars_are_not_adopted() {
        use std::os::unix::fs::PermissionsExt as _;
        use xattr::FileExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "untagged-sidecars.sqlite");
        let saved_wal = database_path(&directory, "untagged-saved-wal");
        let saved_shm = database_path(&directory, "untagged-saved-shm");
        let store = open(&path).await;
        store
            .sessions()
            .create(&session("untagged-row", 1))
            .await
            .expect("create WAL content");
        fs::copy(sidecar(&path, "-wal"), &saved_wal).expect("save untagged WAL bytes");
        fs::copy(sidecar(&path, "-shm"), &saved_shm).expect("save untagged SHM bytes");
        store.close().await.expect("source closes");
        for (saved, target) in [
            (&saved_wal, sidecar(&path, "-wal")),
            (&saved_shm, sidecar(&path, "-shm")),
        ] {
            fs::copy(saved, &target).expect("restore untagged sidecar");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
                .expect("secure untagged sidecar");
            assert!(
                fs::File::open(&target)
                    .expect("open untagged sidecar")
                    .get_xattr("user.gta-claw.sidecar-generation")
                    .expect("inspect untagged sidecar")
                    .is_none()
            );
        }
        let wal_before = fs::read(sidecar(&path, "-wal")).expect("read untagged WAL");
        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("untagged sidecars are rejected");
        assert!(matches!(
            error,
            StateError::InvalidPath {
                reason: "SQLite sidecar generation is missing",
                ..
            }
        ));
        assert_eq!(
            fs::read(sidecar(&path, "-wal")).expect("reread untagged WAL"),
            wal_before
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn missing_live_wal_path_rolls_back_commit() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "missing-live-wal.sqlite");
        let store = std::sync::Arc::new(open(&path).await);
        let owner = test_support::owner(&store).to_owned();
        let (entered, release) = crate::repository::test_support::set_commit_barrier(&owner);
        let record = session("missing-wal-row", 1);
        let record_id = record.id.clone();
        let writer_store = std::sync::Arc::clone(&store);
        let mut writer = tokio::spawn(async move { writer_store.sessions().create(&record).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("writer reaches missing-WAL commit boundary");
        fs::remove_file(sidecar(&path, "-wal")).expect("unlink live WAL pathname");
        release.notify_one();
        let error = tokio::time::timeout(Duration::from_secs(2), &mut writer)
            .await
            .expect("missing-WAL rejection remains bounded")
            .expect("missing-WAL writer joins")
            .expect_err("commit hook rejects missing WAL pathname");
        let StateError::Database(failure) = error else {
            panic!("expected commit-hook constraint, received {error:?}");
        };
        assert_eq!(failure.operation(), "commit session create");
        assert_eq!(failure.code(), Some("531"));
        assert!(
            store
                .sessions()
                .get(&record_id)
                .await
                .expect("read missing-WAL rollback")
                .is_none()
        );
        let store = std::sync::Arc::try_unwrap(store)
            .unwrap_or_else(|_| panic!("writer retained missing-WAL store"));
        assert!(matches!(
            store.close().await,
            Err(StateError::CloseDegraded {
                os_lock_released: true,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn commit_hook_rejects_invalidated_writer_generation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "invalidated-writer-generation.sqlite");
        let store = std::sync::Arc::new(open(&path).await);
        let owner = test_support::owner(&store).to_owned();
        let (entered, release) = crate::repository::test_support::set_commit_barrier(&owner);
        let record = session("invalidated-generation-row", 1);
        let writer_store = std::sync::Arc::clone(&store);
        let mut writer = tokio::spawn(async move { writer_store.sessions().create(&record).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("writer reaches the actual commit boundary");
        test_support::invalidate_writer_generation(&store);
        release.notify_one();
        let error = tokio::time::timeout(Duration::from_secs(2), &mut writer)
            .await
            .expect("invalidated-generation rejection remains bounded")
            .expect("invalidated-generation writer joins")
            .expect_err("commit hook rejects an invalidated writer generation");
        let StateError::Database(failure) = error else {
            panic!("expected commit-hook constraint, received {error:?}");
        };
        assert_eq!(failure.operation(), "commit session create");
        assert_eq!(failure.code(), Some("531"));

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .read_only(true)
            .create_if_missing(false);
        let mut reader = SqliteConnection::connect_with(&options)
            .await
            .expect("open direct rollback reader");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sessions WHERE id = 'invalidated-generation-row'"
            )
            .fetch_one(&mut reader)
            .await
            .expect("read invalidated-generation rollback"),
            0
        );
        reader.close().await.expect("close rollback reader");
        test_support::restore_writer_generation(&store);
        let recovered_record = session("post-veto-row", 2);
        store
            .sessions()
            .create(&recovered_record)
            .await
            .expect("replacement connection commits after callback veto");
        let store = std::sync::Arc::try_unwrap(store)
            .unwrap_or_else(|_| panic!("writer retained invalidated-generation store"));
        store
            .close()
            .await
            .expect("restored-generation store closes");
        let reopened = open(&path).await;
        assert_eq!(
            reopened
                .sessions()
                .get(&recovered_record.id)
                .await
                .expect("read post-veto durable row"),
            Some(recovered_record)
        );
        reopened
            .close()
            .await
            .expect("post-veto reopened store closes");
    }

    #[tokio::test]
    async fn repository_precommit_deadline_rolls_back_staged_write() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "repository-precommit-deadline.sqlite");
        let store = std::sync::Arc::new(
            StateStore::open(
                StoreConfig::new(&path).with_operation_timeout(Duration::from_millis(250)),
            )
            .await
            .expect("deadline fixture store opens"),
        );
        let owner = test_support::owner(&store).to_owned();
        let (entered, release) = crate::repository::test_support::set_commit_barrier(&owner);
        let writer_store = std::sync::Arc::clone(&store);
        let writer = tokio::spawn(async move {
            writer_store
                .sessions()
                .create(&session("deadline-staged-row", 1))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("repository write reaches precommit barrier");
        tokio::time::sleep(Duration::from_millis(300)).await;
        release.notify_one();
        assert!(matches!(
            writer.await.expect("deadline writer joins"),
            Err(StateError::OperationTimedOut {
                operation: "commit session create",
                timeout_ms: 250,
            })
        ));
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sessions WHERE id = 'deadline-staged-row'",
        )
        .fetch_one(test_support::pool(&store))
        .await
        .expect("inspect deadline rollback");
        assert_eq!(count, 0);
        let store = std::sync::Arc::try_unwrap(store)
            .unwrap_or_else(|_| panic!("deadline writer retained store"));
        store.close().await.expect("deadline fixture store closes");
    }

    #[tokio::test]
    async fn repository_reads_use_the_absolute_operation_deadline() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "repository-read-pool-deadline.sqlite");
        let store = StateStore::open(
            StoreConfig::new(&path)
                .with_max_connections(1)
                .with_acquire_timeout(Duration::from_secs(2))
                .with_operation_timeout(Duration::from_millis(100)),
        )
        .await
        .expect("read pool-deadline fixture opens");
        let held = test_support::pool(&store)
            .acquire()
            .await
            .expect("hold the only read pool connection");
        let started = std::time::Instant::now();
        assert_eq!(
            store
                .sessions()
                .get(&SessionId::new("pool-blocked-read").expect("valid read id"))
                .await
                .expect_err("pool-blocked read reaches its operation deadline"),
            StateError::OperationTimedOut {
                operation: "read session",
                timeout_ms: 100,
            }
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "pool acquire timeout must not extend the repository read deadline"
        );
        drop(held);
        store
            .close()
            .await
            .expect("read pool-deadline fixture closes");
    }

    #[tokio::test]
    async fn administrative_operations_use_the_absolute_pool_deadline() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "administrative-pool-deadline.sqlite");
        let store = StateStore::open(
            StoreConfig::new(&path)
                .with_max_connections(1)
                .with_acquire_timeout(Duration::from_secs(2))
                .with_operation_timeout(Duration::from_millis(100)),
        )
        .await
        .expect("administrative deadline fixture opens");
        let held = test_support::pool(&store)
            .acquire()
            .await
            .expect("hold the only administrative pool connection");
        for (operation, result) in [
            (
                "inspect SQLite settings",
                store.settings().await.map(|_| ()),
            ),
            ("inspect SQLite health", store.health().await.map(|_| ())),
            (
                "checkpoint SQLite WAL",
                store.checkpoint().await.map(|_| ()),
            ),
        ] {
            assert_eq!(
                result.expect_err("pool-blocked administrative operation times out"),
                StateError::OperationTimedOut {
                    operation,
                    timeout_ms: 100,
                }
            );
        }
        drop(held);
        store
            .settings()
            .await
            .expect("settings recover after admission timeout");
        store
            .health()
            .await
            .expect("health recovers after admission timeout");
        store
            .checkpoint()
            .await
            .expect("checkpoint recovers after admission timeout");
        store
            .close()
            .await
            .expect("administrative deadline fixture closes");
    }

    #[tokio::test]
    async fn health_progress_timeout_keeps_the_runtime_responsive() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "health-progress-deadline.sqlite");
        let store = StateStore::open(
            StoreConfig::new(&path).with_operation_timeout(Duration::from_millis(100)),
        )
        .await
        .expect("health progress fixture opens");
        test_support::stall_health_progress_once(&path);
        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let ticks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let heartbeat_running = std::sync::Arc::clone(&running);
        let heartbeat_ticks = std::sync::Arc::clone(&ticks);
        let heartbeat = tokio::spawn(async move {
            while heartbeat_running.load(std::sync::atomic::Ordering::Acquire) {
                heartbeat_ticks.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                tokio::task::yield_now().await;
            }
        });
        assert_eq!(
            store
                .health()
                .await
                .expect_err("infinite health query reaches operation deadline"),
            StateError::OperationTimedOut {
                operation: "inspect SQLite health",
                timeout_ms: 100,
            }
        );
        running.store(false, std::sync::atomic::Ordering::Release);
        heartbeat.await.expect("health heartbeat task joins");
        assert!(
            ticks.load(std::sync::atomic::Ordering::Acquire) > 10,
            "health progress cancellation must not block Tokio"
        );
        store
            .health()
            .await
            .expect("health connection generation recovers after timeout");
        store.close().await.expect("health progress fixture closes");
    }

    #[tokio::test]
    async fn checkpoint_busy_wait_obeys_operation_deadline() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "checkpoint-operation-deadline.sqlite");
        let store = StateStore::open(
            StoreConfig::new(&path)
                .with_max_connections(2)
                .with_busy_timeout(Duration::from_secs(5))
                .with_operation_timeout(Duration::from_millis(500)),
        )
        .await
        .expect("checkpoint deadline fixture opens");
        store
            .sessions()
            .create(&session("checkpoint-before-reader", 1))
            .await
            .expect("seed checkpoint reader snapshot");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .read_only(true)
            .busy_timeout(Duration::from_secs(5));
        let mut reader = SqliteConnection::connect_with(&options)
            .await
            .expect("open checkpoint deadline reader");
        reader
            .execute("BEGIN")
            .await
            .expect("begin checkpoint deadline reader");
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sessions")
            .fetch_one(&mut reader)
            .await
            .expect("establish checkpoint deadline snapshot");
        store
            .sessions()
            .create(&session("checkpoint-after-reader", 2))
            .await
            .expect("create WAL frame behind reader");

        let started = std::time::Instant::now();
        assert!(matches!(
            store
                .checkpoint()
                .await
                .expect_err("busy checkpoint reaches operation deadline"),
            StateError::OperationCleanupFailed {
                operation: "checkpoint SQLite WAL",
                primary,
                ref cleanup,
            } if *primary == StateError::OperationTimedOut {
                operation: "checkpoint SQLite WAL",
                timeout_ms: 500,
            } && cleanup.contains("Quarantined")
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        reader
            .execute("ROLLBACK")
            .await
            .expect("release checkpoint deadline reader");
        reader
            .close()
            .await
            .expect("close checkpoint deadline reader");
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if store
                    .checkpoint()
                    .await
                    .is_ok_and(|report| report.busy == 0)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("checkpoint recovers after busy deadline");
        store
            .close()
            .await
            .expect("checkpoint deadline fixture closes");
    }

    #[tokio::test]
    async fn repository_update_deadline_includes_preliminary_read() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "repository-read-deadline.sqlite");
        let store = std::sync::Arc::new(
            StateStore::open(
                StoreConfig::new(&path).with_operation_timeout(Duration::from_millis(250)),
            )
            .await
            .expect("read deadline fixture opens"),
        );
        let record = session("read-deadline-row", 1);
        store
            .sessions()
            .create(&record)
            .await
            .expect("seed read deadline row");
        let owner = test_support::owner(&store).to_owned();
        let (entered, release) = crate::repository::test_support::set_read_barrier(&owner);
        let update_store = std::sync::Arc::clone(&store);
        let id = record.id.clone();
        let update = tokio::spawn(async move {
            update_store
                .sessions()
                .update_status(&id, 1, SessionStatus::Archived, timestamp(2))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("update reaches preliminary read barrier");
        tokio::time::sleep(Duration::from_millis(300)).await;
        release.notify_one();
        assert!(matches!(
            update.await.expect("read deadline update joins"),
            Err(StateError::OperationTimedOut {
                operation: "begin session update",
                timeout_ms: 250,
            })
        ));
        assert_eq!(
            store
                .sessions()
                .get(&record.id)
                .await
                .expect("read deadline row remains readable")
                .expect("read deadline row remains present")
                .status,
            SessionStatus::Active
        );
        let store = std::sync::Arc::try_unwrap(store)
            .unwrap_or_else(|_| panic!("read deadline update retained store"));
        store.close().await.expect("read deadline fixture closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restore_rejects_symlinked_source_wal() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "symlink-wal-source.sqlite");
        let backup_path = database_path(&directory, "symlink-wal-backup.sqlite");
        let destination = database_path(&directory, "symlink-wal-restored.sqlite");
        let missing_wal = database_path(&directory, "missing-source-wal");
        let source = open(&source_path).await;
        source.backup_to(&backup_path).await.expect("create backup");
        symlink(&missing_wal, sidecar(&backup_path, "-wal")).expect("create symlinked source WAL");

        let error = StateStore::restore_backup(&backup_path, &destination)
            .await
            .expect_err("symlinked source WAL is rejected");
        assert!(matches!(
            error,
            StateError::InvalidPath { .. } | StateError::FileSystem { .. }
        ));
        assert!(!destination.exists());
        source.close().await.expect("source store closes");
    }

    #[tokio::test]
    async fn restore_rejects_stale_destination_sidecars() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "sidecar-source.sqlite");
        let backup_path = database_path(&directory, "sidecar-backup.sqlite");
        let destination = database_path(&directory, "sidecar-destination.sqlite");
        let source = open(&source_path).await;
        source.backup_to(&backup_path).await.expect("create backup");
        fs::write(sidecar(&destination, "-wal"), b"stale WAL").expect("create stale WAL");

        let error = StateStore::restore_backup(&backup_path, &destination)
            .await
            .expect_err("stale destination WAL rejects restore");
        assert_eq!(
            error,
            StateError::BackupDestinationExists {
                path: sidecar(&destination, "-wal"),
            }
        );
        assert!(!destination.exists());
        assert_eq!(
            fs::read(sidecar(&destination, "-wal")).expect("read stale WAL"),
            b"stale WAL"
        );
        source.close().await.expect("source store closes");
    }

    #[tokio::test]
    async fn restore_rejects_source_and_destination_rollback_journals() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "journal-source.sqlite");
        let backup_path = database_path(&directory, "journal-backup.sqlite");
        let source_destination = database_path(&directory, "journal-source-restored.sqlite");
        let collision_destination =
            database_path(&directory, "journal-collision-destination.sqlite");
        let source = open(&source_path).await;
        source.backup_to(&backup_path).await.expect("create backup");

        fs::write(sidecar(&backup_path, "-journal"), b"hot journal")
            .expect("create source rollback journal");
        let error = StateStore::restore_backup(&backup_path, &source_destination)
            .await
            .expect_err("source rollback journal rejects restore");
        assert!(matches!(error, StateError::InvalidBackup { .. }));
        assert!(!source_destination.exists());
        fs::remove_file(sidecar(&backup_path, "-journal")).expect("remove source rollback journal");

        fs::write(
            sidecar(&collision_destination, "-journal"),
            b"stale journal",
        )
        .expect("create destination rollback journal");
        let error = StateStore::restore_backup(&backup_path, &collision_destination)
            .await
            .expect_err("destination rollback journal rejects restore");
        assert_eq!(
            error,
            StateError::BackupDestinationExists {
                path: sidecar(&collision_destination, "-journal"),
            }
        );
        assert!(!collision_destination.exists());
        source.close().await.expect("source store closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restore_rejects_dangling_destination_sidecar_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "symlink-sidecar-source.sqlite");
        let backup_path = database_path(&directory, "symlink-sidecar-backup.sqlite");
        let destination = database_path(&directory, "symlink-sidecar-destination.sqlite");
        let dangling_target = database_path(&directory, "missing-wal-target");
        let source = open(&source_path).await;
        source.backup_to(&backup_path).await.expect("create backup");
        symlink(&dangling_target, sidecar(&destination, "-wal"))
            .expect("create dangling destination WAL symlink");

        let error = StateStore::restore_backup(&backup_path, &destination)
            .await
            .expect_err("dangling destination sidecar rejects restore");
        assert_eq!(
            error,
            StateError::BackupDestinationExists {
                path: sidecar(&destination, "-wal"),
            }
        );
        assert!(!destination.exists());
        assert!(fs::symlink_metadata(sidecar(&destination, "-wal")).is_ok());
        source.close().await.expect("source store closes");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn restore_rejects_destination_sidecar_reparse_when_available() {
        use std::os::windows::fs::symlink_file;

        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "reparse-sidecar-source.sqlite");
        let backup_path = database_path(&directory, "reparse-sidecar-backup.sqlite");
        let destination = database_path(&directory, "reparse-sidecar-destination.sqlite");
        let dangling_target = database_path(&directory, "missing-wal-target");
        let source = open(&source_path).await;
        source.backup_to(&backup_path).await.expect("create backup");
        if let Err(error) = symlink_file(&dangling_target, sidecar(&destination, "-wal")) {
            if error.kind() == std::io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(1314)
            {
                source.close().await.expect("source store closes");
                return;
            }

            panic!("create destination WAL reparse point: {error}");
        }

        let error = StateStore::restore_backup(&backup_path, &destination)
            .await
            .expect_err("destination reparse sidecar rejects restore");
        assert!(matches!(error, StateError::BackupDestinationExists { .. }));
        assert!(!destination.exists());
        source.close().await.expect("source store closes");
    }

    #[tokio::test]
    async fn restore_rejects_stale_writer_lock_without_publication() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "stale-lock-source.sqlite");
        let backup_path = database_path(&directory, "stale-lock-backup.sqlite");
        let destination = database_path(&directory, "stale-lock-destination.sqlite");
        let mut lock_path = destination.as_os_str().to_owned();
        lock_path.push(".writer.lock");
        let lock_path = PathBuf::from(lock_path);
        let source = open(&source_path).await;
        source.backup_to(&backup_path).await.expect("create backup");
        fs::write(&lock_path, b"stale-lock-header").expect("create stale writer lock");

        assert_eq!(
            StateStore::restore_backup(&backup_path, &destination)
                .await
                .expect_err("stale destination writer lock rejects restore"),
            StateError::BackupDestinationExists {
                path: lock_path.clone(),
            }
        );
        assert!(!destination.exists());
        assert_eq!(
            fs::read(&lock_path).expect("read unchanged stale writer lock"),
            b"stale-lock-header"
        );
        fs::remove_file(&lock_path).expect("remove stale writer lock");
        StateStore::restore_backup(&backup_path, &destination)
            .await
            .expect("restore succeeds after stale lock removal");
        open(&destination)
            .await
            .close()
            .await
            .expect("restored destination opens");
        source.close().await.expect("source store closes");
    }

    #[tokio::test]
    async fn restore_requires_exact_history_foreign_keys_and_integrity() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "validation-source.sqlite");
        let base_backup = database_path(&directory, "validation-base.sqlite");
        let source = open(&source_path).await;
        source
            .backup_to(&base_backup)
            .await
            .expect("create validation backup");
        source.close().await.expect("source store closes");

        let cases = [
            (
                "name",
                "UPDATE claw_schema_migrations SET name = 'renamed' WHERE version = 1",
            ),
            (
                "checksum",
                "UPDATE claw_schema_migrations
                 SET checksum = '0000000000000000000000000000000000000000000000000000000000000000'
                 WHERE version = 1",
            ),
            ("older", "DELETE FROM claw_schema_migrations"),
            (
                "gap",
                "DELETE FROM claw_schema_migrations;
                 INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
                 VALUES (2, 'gap', 'gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg', 1)",
            ),
            (
                "newer",
                "INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
                 VALUES (3, 'future', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 1)",
            ),
            (
                "invalid-type",
                "DROP TABLE claw_schema_migrations;
                 CREATE TABLE claw_schema_migrations(
                    version,
                    name,
                    checksum,
                    applied_at_ms
                 );
                 INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
                 VALUES (X'01', 'initial',
                    '0000000000000000000000000000000000000000000000000000000000000000',
                    1)",
            ),
            ("missing-table", "DROP TABLE tasks"),
            (
                "foreign-key",
                "PRAGMA foreign_keys = OFF;
                 INSERT INTO tasks(
                    id, session_id, kind, payload, status, created_at_ms, updated_at_ms, version
                 ) VALUES ('orphan', 'missing', 'test', '', 'pending', 1, 1, 1)",
            ),
        ];
        for (name, sql) in cases {
            let variant = database_path(&directory, &format!("{name}.sqlite"));
            let destination = database_path(&directory, &format!("{name}-restored.sqlite"));
            fs::copy(&base_backup, &variant).expect("copy backup variant");
            execute_direct(&variant, sql).await;
            test_support::reseal_backup_fixture(&variant);
            assert_restore_rejected(&variant, &destination).await;
            test_support::remove_backup_fixture_seal(&variant);
        }
        for (name, sql) in schema_drift_cases() {
            let variant = database_path(&directory, &format!("restore-{name}.sqlite"));
            let destination =
                database_path(&directory, &format!("restore-{name}-destination.sqlite"));
            fs::copy(&base_backup, &variant).expect("copy schema drift backup");
            execute_direct(&variant, sql).await;
            test_support::reseal_backup_fixture(&variant);
            assert_restore_rejected(&variant, &destination).await;
            test_support::remove_backup_fixture_seal(&variant);
        }

        let corrupt = database_path(&directory, "corrupt.sqlite");
        let corrupt_destination = database_path(&directory, "corrupt-restored.sqlite");
        fs::copy(&base_backup, &corrupt).expect("copy corrupt variant");
        let length = fs::metadata(&corrupt).expect("corrupt metadata").len();
        OpenOptions::new()
            .write(true)
            .open(&corrupt)
            .expect("open corrupt variant")
            .set_len(length / 2)
            .expect("truncate corrupt variant");
        test_support::reseal_backup_fixture(&corrupt);
        assert_restore_rejected(&corrupt, &corrupt_destination).await;
        test_support::remove_backup_fixture_seal(&corrupt);
    }

    #[tokio::test]
    async fn writer_lock_rejects_a_second_store_without_stealing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "locked.sqlite");
        let owner = open(&path).await;
        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("second writer is rejected");
        assert!(
            matches!(error, StateError::StoreLocked { .. }),
            "unexpected second-writer error: {error:?}"
        );
        assert!(
            owner
                .health()
                .await
                .expect("lock owner remains usable")
                .is_healthy()
        );
        owner.close().await.expect("lock owner closes");

        let next_owner = open(&path).await;
        next_owner.close().await.expect("next owner closes");
    }

    #[tokio::test]
    async fn stale_application_lock_is_recovered_under_the_os_lock() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "stale-lock.sqlite");
        let store = open(&path).await;
        store.close().await.expect("seed store closes");

        let options = SqliteConnectOptions::new().filename(&path);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("open database directly");
        sqlx::query(
            "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
             VALUES (1, 'crashed-process', 1)",
        )
        .execute(&mut connection)
        .await
        .expect("record stale owner");
        connection.close().await.expect("close direct connection");

        let recovered = StateStore::open(StoreConfig::new(&path))
            .await
            .expect("stale lock is recoverable after OS lock acquisition");
        assert_eq!(
            recovered.recovered_writer(),
            Some(&RecoveredWriterLock {
                previous_owner: "crashed-process".to_owned(),
                previous_acquired_at_ms: 1,
            })
        );
        recovered.close().await.expect("recovered store closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_lock_identity_upgrades_to_inode_bound_v2() {
        use std::os::unix::fs::MetadataExt as _;
        use xattr::FileExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "legacy-lock-upgrade.sqlite");
        open(&path).await.close().await.expect("seed store closes");
        let lock_path = unix_lock_path(&path);
        let metadata = fs::metadata(&path).expect("inspect legacy database identity");
        let legacy = format!(
            "v1\n{}\n{}\n{}",
            metadata.dev(),
            metadata.ino(),
            lock_path.display()
        );
        fs::write(&lock_path, &legacy).expect("write legacy lock header");
        let database_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open legacy database identity");
        database_file
            .set_xattr("user.gta-claw.writer-lock-path", legacy.as_bytes())
            .expect("write legacy database identity");
        database_file.sync_all().expect("sync legacy identity");

        let upgraded = open(&path).await;
        let value = database_file
            .get_xattr("user.gta-claw.writer-lock-path")
            .expect("read upgraded identity")
            .expect("upgraded identity exists");
        assert!(value.starts_with(b"v2\n"));
        assert_eq!(
            fs::read(&lock_path).expect("read upgraded lock header"),
            value
        );
        upgraded.close().await.expect("upgraded store closes");
    }

    #[test]
    fn child_process_writer() {
        let Some(path) = std::env::var_os("CLAW_STATE_CHILD_DATABASE") else {
            return;
        };
        let ready = PathBuf::from(
            std::env::var_os("CLAW_STATE_CHILD_READY").expect("child ready path is configured"),
        );
        let runtime = tokio::runtime::Runtime::new().expect("child Tokio runtime");
        let _store = runtime
            .block_on(StateStore::open(StoreConfig::new(PathBuf::from(path))))
            .expect("child state store opens");
        fs::write(ready, b"ready").expect("signal child readiness");
        thread::sleep(Duration::from_secs(60));
    }

    #[test]
    fn child_process_first_open() {
        let (Some(path), Some(ready), Some(result)) = (
            std::env::var_os("CLAW_STATE_CHILD_DATABASE"),
            std::env::var_os("CLAW_STATE_CHILD_READY"),
            std::env::var_os("CLAW_STATE_CHILD_RESULT"),
        ) else {
            return;
        };
        let ready = PathBuf::from(ready);
        let result = PathBuf::from(result);
        let runtime = tokio::runtime::Runtime::new().expect("child Tokio runtime");
        match runtime.block_on(StateStore::open(StoreConfig::new(PathBuf::from(path)))) {
            Ok(_store) => {
                fs::write(&result, b"opened").expect("record successful first open");
                fs::write(ready, b"ready").expect("signal first-open readiness");
                thread::sleep(Duration::from_secs(60));
            }
            Err(StateError::StoreLocked { .. }) => {
                fs::write(result, b"locked").expect("record expected lock rejection");
            }
            Err(StateError::InvalidPath { .. }) => {
                fs::write(result, b"identity-rejected").expect("record identity-bound rejection");
            }
            Err(error) => {
                fs::write(result, format!("unexpected:{error:?}"))
                    .expect("record unexpected first-open failure");
            }
        }
    }

    #[tokio::test]
    async fn killed_writer_is_recovered_but_live_writer_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "crashed-writer.sqlite");
        let ready = database_path(&directory, "child.ready");
        let executable = std::env::current_exe().expect("current test executable");
        let child = Command::new(executable)
            .arg("--exact")
            .arg("tests::child_process_writer")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env("CLAW_STATE_CHILD_DATABASE", &path)
            .env("CLAW_STATE_CHILD_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn writer child");
        let mut child = ChildGuard::new(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }
        if !ready.exists() {
            let status = child
                .child_mut()
                .try_wait()
                .expect("inspect writer child readiness");
            panic!("writer child did not become ready; exit status: {status:?}");
        }

        let live_error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("live writer is rejected");
        assert!(matches!(live_error, StateError::StoreLocked { .. }));
        child.kill_and_wait().expect("kill and reap writer child");

        let recovered = StateStore::open(StoreConfig::new(&path))
            .await
            .expect("killed writer is recovered");
        assert!(recovered.recovered_writer().is_some());
        recovered.close().await.expect("recovered store closes");
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_first_open_has_exactly_one_writer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "first-open.sqlite");
        let ready_a = database_path(&directory, "first-a.ready");
        let ready_b = database_path(&directory, "first-b.ready");
        let result_a = database_path(&directory, "first-a.result");
        let result_b = database_path(&directory, "first-b.result");
        let executable = std::env::current_exe().expect("current test executable");
        let spawn = |ready: &Path, result: &Path| {
            let child = Command::new(&executable)
                .arg("--exact")
                .arg("tests::child_process_first_open")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env("CLAW_STATE_CHILD_DATABASE", &path)
                .env("CLAW_STATE_CHILD_READY", ready)
                .env("CLAW_STATE_CHILD_RESULT", result)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn first-open contender");
            ChildGuard::new(child)
        };
        let mut child_a = spawn(&ready_a, &result_a);
        let mut child_b = spawn(&ready_b, &result_b);
        let deadline = Instant::now() + Duration::from_secs(10);
        while (!result_a.exists() || !result_b.exists()) && Instant::now() < deadline {
            if ready_a.exists() && ready_b.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        let result_a_text = fs::read_to_string(&result_a).unwrap_or_else(|_| "missing".to_owned());
        let result_b_text = fs::read_to_string(&result_b).unwrap_or_else(|_| "missing".to_owned());
        let mut outcomes = [result_a_text.as_str(), result_b_text.as_str()];
        outcomes.sort_unstable();
        if outcomes != ["locked", "opened"] {
            let _ = child_a.kill();
            let _ = child_b.kill();
            let _ = child_a.wait();
            let _ = child_b.wait();
            panic!("unexpected first-open outcomes: {outcomes:?}");
        }
        let (winner, loser) = if result_a_text == "opened" {
            (&mut child_a, &mut child_b)
        } else {
            (&mut child_b, &mut child_a)
        };
        let loser_status = loop {
            if let Some(status) = loser.try_wait().expect("inspect losing contender") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = winner.kill();
                let _ = loser.kill();
                let _ = winner.wait();
                let _ = loser.wait();
                panic!("losing first-open contender did not exit within ten seconds");
            }
            thread::sleep(Duration::from_millis(25));
        };
        assert!(loser_status.success());
        winner.kill().expect("stop winning contender");
        winner.wait().expect("reap winning contender");
    }

    #[tokio::test]
    async fn hardlink_alias_cannot_open_a_second_writer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "hardlink-source.sqlite");
        let alias = database_path(&directory, "hardlink-alias.sqlite");
        let owner = open(&path).await;
        fs::hard_link(&path, &alias).expect("create database hard link");

        let error = StateStore::open(StoreConfig::new(&alias))
            .await
            .err()
            .expect("hard-link alias is rejected");
        assert!(matches!(
            error,
            StateError::InvalidPath { .. }
                | StateError::StoreLocked { .. }
                | StateError::FileSystem { .. }
        ));
        #[cfg(unix)]
        fs::remove_file(&alias).expect("remove rejected Unix hard-link alias before close");
        owner.close().await.expect("lock owner closes");

        #[cfg(not(unix))]
        {
            let error = StateStore::open(StoreConfig::new(&alias))
                .await
                .err()
                .expect("hard-link alias remains rejected after the owner closes");
            assert!(
                matches!(error, StateError::InvalidPath { .. }),
                "hard-link alias returned unexpected error: {error:?}"
            );
            fs::remove_file(&alias).expect("remove rejected Windows hard-link alias");
        }
        open(&path)
            .await
            .close()
            .await
            .expect("canonical database name still opens");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn oversized_writer_lock_is_rejected_without_unbounded_read() {
        let directory = tempfile::tempdir().expect("oversized lock directory");
        let path = database_path(&directory, "oversized-lock.sqlite");
        let store = open(&path).await;
        let lock_path = test_support::lock_path(&store).to_owned();
        store.close().await.expect("close oversized lock fixture");
        fs::write(&lock_path, vec![b'x'; 4097]).expect("write oversized writer lock");
        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("oversized writer lock is rejected");
        assert!(matches!(error, StateError::InvalidPath { .. }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dangling_symlink_cannot_create_a_database() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = database_path(&directory, "missing-target.sqlite");
        let alias = database_path(&directory, "dangling-alias.sqlite");
        symlink(&target, &alias).expect("create dangling database symlink");

        let error = StateStore::open(StoreConfig::new(&alias))
            .await
            .err()
            .expect("dangling database symlink is rejected");
        assert!(matches!(error, StateError::InvalidPath { .. }));
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn private_lock_artifact_attacks_fail_closed() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().expect("temporary directory");

        let symlink_db = database_path(&directory, "symlink-root.sqlite");
        create_private_empty_file(&symlink_db);
        let real_root = directory.path().join("real-lock-root");
        fs::create_dir(&real_root).expect("create real lock root");
        fs::set_permissions(&real_root, fs::Permissions::from_mode(0o700))
            .expect("secure real lock root");
        let linked_root = directory.path().join("linked-lock-root");
        symlink(&real_root, &linked_root).expect("create lock-root symlink");
        set_unix_lock_identity(
            &symlink_db,
            &linked_root.join(unix_lock_file_name(&symlink_db, "test")),
        );
        let error = StateStore::open(StoreConfig::new(&symlink_db))
            .await
            .err()
            .expect("symlink lock root is rejected");
        assert!(matches!(
            error,
            StateError::InvalidPath { .. } | StateError::FileSystem { .. }
        ));

        let permissive_db = database_path(&directory, "permissive-root.sqlite");
        create_private_empty_file(&permissive_db);
        let permissive_root = directory.path().join("permissive-lock-root");
        fs::create_dir(&permissive_root).expect("create permissive lock root");
        fs::set_permissions(&permissive_root, fs::Permissions::from_mode(0o755))
            .expect("make lock root permissive");
        set_unix_lock_identity(
            &permissive_db,
            &permissive_root.join(unix_lock_file_name(&permissive_db, "test")),
        );
        let error = StateStore::open(StoreConfig::new(&permissive_db))
            .await
            .err()
            .expect("permissive lock root is rejected");
        assert!(matches!(error, StateError::InvalidPath { .. }));

        let hardlink_db = database_path(&directory, "hardlink-lock.sqlite");
        create_private_empty_file(&hardlink_db);
        let metadata = fs::metadata(&hardlink_db).expect("read hardlink DB identity");
        use std::os::unix::fs::MetadataExt as _;
        let hardlink_root = directory.path().join("hardlink-lock-root");
        fs::create_dir(&hardlink_root).expect("create hardlink lock root");
        fs::set_permissions(&hardlink_root, fs::Permissions::from_mode(0o700))
            .expect("secure hardlink lock root");
        let lock_path = hardlink_root.join(format!(
            "dev-{}-ino-{}-test.lock",
            metadata.dev(),
            metadata.ino()
        ));
        fs::write(&lock_path, b"placeholder").expect("create lock file");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
            .expect("secure lock file");
        fs::hard_link(&lock_path, hardlink_root.join("second-link")).expect("hardlink lock file");
        set_unix_lock_identity(&hardlink_db, &lock_path);
        let error = StateStore::open(StoreConfig::new(&hardlink_db))
            .await
            .err()
            .expect("hardlinked lock file is rejected");
        assert!(matches!(error, StateError::InvalidPath { .. }));

        let stale_db = database_path(&directory, "stale-lock-entry.sqlite");
        create_private_empty_file(&stale_db);
        let stale_root = directory.path().join("stale-lock-root");
        fs::create_dir(&stale_root).expect("create stale lock root");
        fs::set_permissions(&stale_root, fs::Permissions::from_mode(0o700))
            .expect("secure stale lock root");
        let stale_lock = stale_root.join(unix_lock_file_name(&stale_db, "test"));
        fs::write(&stale_lock, b"wrong identity").expect("create stale lock entry");
        fs::set_permissions(&stale_lock, fs::Permissions::from_mode(0o600))
            .expect("secure stale lock entry");
        set_unix_lock_identity(&stale_db, &stale_lock);
        let error = StateStore::open(StoreConfig::new(&stale_db))
            .await
            .err()
            .expect("stale lock contents are rejected");
        assert!(matches!(error, StateError::InvalidPath { .. }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn canonical_private_lock_entries_reject_alias_and_stale_attacks() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
        use xattr::FileExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let token = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("current test time")
                .as_nanos()
        );
        for attack in ["symlink", "hardlink", "stale"] {
            let database = database_path(&directory, &format!("canonical-{attack}.sqlite"));
            let root = test_support::private_lock_root(&database);
            create_private_empty_file(&database);
            let metadata = fs::metadata(&database).expect("read canonical attack identity");
            let lock_path = root.join(format!(
                "dev-{}-ino-{}-{token}-{attack}.lock",
                metadata.dev(),
                metadata.ino()
            ));
            let encoded = format!(
                "v1\n{}\n{}\n{}",
                metadata.dev(),
                metadata.ino(),
                lock_path.display()
            );
            let mut cleanup = vec![lock_path.clone()];
            match attack {
                "symlink" => {
                    let target = directory.path().join("canonical-symlink-target");
                    fs::write(&target, b"target must remain untouched")
                        .expect("create symlink target");
                    symlink(&target, &lock_path).expect("create canonical lock symlink");
                }
                "hardlink" => {
                    fs::write(&lock_path, &encoded).expect("create canonical lock");
                    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                        .expect("secure canonical lock");
                    let alias = root.join(format!("canonical-lock-alias-{token}"));
                    fs::hard_link(&lock_path, &alias).expect("hardlink canonical lock");
                    cleanup.push(alias);
                }
                "stale" => {
                    fs::write(&lock_path, b"wrong identity").expect("create stale canonical lock");
                    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                        .expect("secure stale canonical lock");
                }
                _ => unreachable!("fixed attack inventory"),
            }
            let database_file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&database)
                .expect("open canonical attack database");
            database_file
                .set_xattr("user.gta-claw.writer-lock-path", encoded.as_bytes())
                .expect("set canonical attack identity");

            let error = StateStore::open(StoreConfig::new(&database))
                .await
                .err()
                .expect("canonical private lock attack is rejected");
            assert!(matches!(
                error,
                StateError::InvalidPath { .. } | StateError::FileSystem { .. }
            ));
            for artifact in cleanup {
                fs::remove_file(artifact).expect("remove unreferenced test lock artifact");
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_lock_file_replacement_forces_fail_closed_shutdown() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "lock-replacement.sqlite");
        let store = open(&path).await;
        let lock_path = unix_lock_path(&path);
        fs::remove_file(&lock_path).expect("unlink live lock path");
        fs::write(&lock_path, b"replacement").expect("replace live lock file");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
            .expect("secure replacement lock");

        let error = store
            .health()
            .await
            .expect_err("cached checkout fails closed");
        assert_eq!(
            error,
            StateError::InvalidPath {
                path: lock_path,
                reason: "database path changed after its identity was verified",
            }
        );
        let close_error = tokio::time::timeout(Duration::from_secs(2), store.close())
            .await
            .expect("replacement-degraded close remains bounded")
            .expect_err("replacement prevents clean close");
        assert!(matches!(
            close_error,
            StateError::CloseDegraded {
                checkpoint_completed: false,
                application_lock_released: false,
                os_lock_released: true,
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn active_write_and_second_process_reject_replaced_lock_inode() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "active-lock-replacement.sqlite");
        let store = std::sync::Arc::new(open(&path).await);
        let owner = test_support::owner(&store).to_owned();
        let (entered, release) = crate::repository::test_support::set_commit_barrier(&owner);
        let record = session("must-not-commit-after-lock-replacement", 1);
        let writer_store = std::sync::Arc::clone(&store);
        let mut writer = tokio::spawn(async move { writer_store.sessions().create(&record).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("repository transaction reaches the SQLite commit hook barrier");

        let lock_path = unix_lock_path(&path);
        let lock_contents = fs::read(&lock_path).expect("read held lock identity");
        fs::remove_file(&lock_path).expect("unlink held lock inode");
        fs::write(&lock_path, lock_contents).expect("replace lock inode with matching bytes");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
            .expect("secure replacement lock inode");

        let child_ready = database_path(&directory, "replacement-child.ready");
        let child_result = database_path(&directory, "replacement-child.result");
        let executable = std::env::current_exe().expect("current test executable");
        let child = Command::new(executable)
            .arg("--exact")
            .arg("tests::child_process_first_open")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env("CLAW_STATE_CHILD_DATABASE", &path)
            .env("CLAW_STATE_CHILD_READY", &child_ready)
            .env("CLAW_STATE_CHILD_RESULT", &child_result)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn replacement-lock contender");
        let mut child = ChildGuard::new(child);
        let child_outcome = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(result) = fs::read_to_string(&child_result) {
                    break result;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("second process reports a bounded outcome");
        assert_eq!(child_outcome, "identity-rejected");
        let child_status = child.wait().expect("reap replacement-lock contender");
        assert!(child_status.success());

        release.notify_one();
        let write_result = match tokio::time::timeout(Duration::from_secs(2), &mut writer).await {
            Ok(join) => join.expect("active repository task joins"),
            Err(_) => {
                writer.abort();
                let _ = writer.await;
                panic!("active repository write exceeded two seconds");
            }
        };
        assert!(
            write_result.is_err(),
            "active write must roll back after lock inode replacement"
        );

        let store = std::sync::Arc::try_unwrap(store)
            .unwrap_or_else(|_| panic!("writer retained the state store"));
        assert!(matches!(
            store.close().await,
            Err(StateError::CloseDegraded {
                os_lock_released: true,
                ..
            })
        ));
        let options = SqliteConnectOptions::new().filename(&path);
        let mut direct = SqliteConnection::connect_with(&options)
            .await
            .expect("open database after degraded close");
        let rows = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sessions WHERE id = 'must-not-commit-after-lock-replacement'",
        )
        .fetch_one(&mut direct)
        .await
        .expect("count rolled-back lock replacement row");
        assert_eq!(rows, 0);
        direct.close().await.expect("close direct verifier");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_xattr_replacement_forces_fail_closed_shutdown() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        use xattr::FileExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "xattr-replacement.sqlite");
        let store = open(&path).await;
        let original_lock = unix_lock_path(&path);
        let metadata = fs::metadata(&path).expect("read database identity");
        let replacement_lock = original_lock
            .parent()
            .expect("lock has parent")
            .join(format!(
                "dev-{}-ino-{}-replacement.lock",
                metadata.dev(),
                metadata.ino()
            ));
        let replacement_identity = format!(
            "v1\n{}\n{}\n{}",
            metadata.dev(),
            metadata.ino(),
            replacement_lock.display()
        );
        fs::write(&replacement_lock, replacement_identity.as_bytes())
            .expect("create replacement identity lock");
        fs::set_permissions(&replacement_lock, fs::Permissions::from_mode(0o600))
            .expect("secure replacement identity lock");
        let database_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open database for xattr replacement");
        database_file
            .set_xattr(
                "user.gta-claw.writer-lock-path",
                replacement_identity.as_bytes(),
            )
            .expect("replace database lock xattr");

        let error = store
            .health()
            .await
            .expect_err("cached checkout detects xattr replacement");
        let canonical_path = fs::canonicalize(path.parent().expect("database path has a parent"))
            .expect("canonicalize database parent")
            .join(path.file_name().expect("database path has a file name"));
        assert_eq!(
            error,
            StateError::InvalidPath {
                path: canonical_path,
                reason: "database lock identity changed while open",
            }
        );
        let close_error = tokio::time::timeout(Duration::from_secs(2), store.close())
            .await
            .expect("xattr-degraded close remains bounded")
            .expect_err("xattr replacement prevents clean close");
        assert!(matches!(
            close_error,
            StateError::CloseDegraded {
                checkpoint_completed: false,
                application_lock_released: false,
                os_lock_released: true,
                ..
            }
        ));

        let recovered = open(&path).await;
        assert!(recovered.recovered_writer().is_some());
        recovered.close().await.expect("replacement owner closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn existing_database_missing_lock_identity_fails_closed() {
        use xattr::FileExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "missing-lock-identity.sqlite");
        open(&path).await.close().await.expect("seed store closes");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open seeded database");
        file.remove_xattr("user.gta-claw.writer-lock-path")
            .expect("remove database lock identity");

        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("existing database does not recreate missing identity");
        assert!(matches!(error, StateError::InvalidPath { .. }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn identity_lock_survives_hardlink_and_original_unlink() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "identity-source.sqlite");
        let alias = database_path(&directory, "identity-alias.sqlite");
        let owner = open(&path).await;
        owner
            .checkpoint()
            .await
            .expect("checkpoint identity source");
        fs::hard_link(&path, &alias).expect("create live database hard link");
        fs::remove_file(&path).expect("unlink original live database name");

        let error = StateStore::open(StoreConfig::new(&alias))
            .await
            .err()
            .expect("identity-bound lock rejects remaining hard-link name");
        assert!(matches!(error, StateError::StoreLocked { .. }));
        let close_error = tokio::time::timeout(Duration::from_secs(2), owner.close())
            .await
            .expect("degraded close completes within its bound")
            .expect_err("vanished pathname prevents a clean checkpoint");
        assert!(matches!(
            close_error,
            StateError::CloseDegraded {
                checkpoint_completed: false,
                application_lock_released: false,
                os_lock_released: true,
                ..
            }
        ));

        let next_owner = StateStore::open(StoreConfig::new(&alias))
            .await
            .expect("new owner opens only after degraded close releases identity lock");
        assert!(next_owner.recovered_writer().is_some());
        next_owner.close().await.expect("new owner closes cleanly");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn checkpoint_rejects_database_replaced_after_sqlite_operation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "checkpoint-post-identity.sqlite");
        let detached = database_path(&directory, "checkpoint-post-identity.detached");
        let owner = std::sync::Arc::new(open(&path).await);
        let (entered, release) = store::test_support::set_checkpoint_barrier(&path);
        let checkpoint_owner = std::sync::Arc::clone(&owner);
        let checkpoint = tokio::spawn(async move { checkpoint_owner.checkpoint().await });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("checkpoint reaches post-operation identity barrier");
        fs::rename(&path, &detached).expect("detach database after SQLite checkpoint");
        fs::write(&path, b"replacement").expect("create replacement database name");
        release.notify_one();
        let error = checkpoint
            .await
            .expect("checkpoint task joins")
            .expect_err("post-operation replacement fails closed");
        assert!(matches!(error, StateError::InvalidPath { .. }));
        fs::remove_file(&path).expect("remove replacement database name");
        fs::rename(&detached, &path).expect("restore database identity for clean close");
        std::sync::Arc::try_unwrap(owner)
            .ok()
            .expect("checkpoint task released store")
            .close()
            .await
            .expect("checkpoint fixture closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replacement_path_cannot_receive_a_reconnected_pool_connection() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "replacement.sqlite");
        let detached = database_path(&directory, "replacement-detached.sqlite");
        let first = StateStore::open(
            StoreConfig::new(&path)
                .with_busy_timeout(Duration::from_millis(75))
                .with_acquire_timeout(Duration::from_millis(500)),
        )
        .await
        .expect("first store opens");
        let connection = test_support::pool(&first)
            .acquire()
            .await
            .expect("acquire sole identity-bound connection");
        fs::rename(&path, &detached).expect("detach locked database pathname");
        for suffix in ["-wal", "-shm", "-journal"] {
            let original = sidecar(&path, suffix);
            if original.exists() {
                fs::rename(&original, sidecar(&detached, suffix))
                    .expect("detach SQLite sidecar with original database");
            }
        }
        let replacement = open(&path).await;
        drop(connection);

        let record = session("must-not-cross-identity", 1);
        let error = first
            .sessions()
            .create(&record)
            .await
            .expect_err("cached connection checkout fails closed after replacement");
        assert!(matches!(error, StateError::Database(_)));
        assert!(
            replacement
                .sessions()
                .get(&record.id)
                .await
                .expect("read replacement store")
                .is_none()
        );
        drop(first);
        replacement.close().await.expect("replacement store closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_parent_replacement_rolls_back_at_commit_boundary() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let original_parent = directory.path().to_owned();
        let moved_parent = original_parent.with_extension("moved");
        let path = database_path(&directory, "parent-replacement.sqlite");
        let store = std::sync::Arc::new(open(&path).await);
        let owner = test_support::owner(&store).to_owned();
        let (entered, release) = crate::repository::test_support::set_commit_barrier(&owner);
        let record = session("parent-replacement-row", 1);
        let writer_store = std::sync::Arc::clone(&store);
        let mut writer = tokio::spawn(async move { writer_store.sessions().create(&record).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("writer reaches parent-identity commit boundary");
        fs::rename(&original_parent, &moved_parent).expect("detach pinned state parent");
        fs::create_dir(&original_parent).expect("create replacement state parent");
        fs::set_permissions(&original_parent, fs::Permissions::from_mode(0o700))
            .expect("secure replacement state parent");
        release.notify_one();
        let error = tokio::time::timeout(Duration::from_secs(2), &mut writer)
            .await
            .expect("parent replacement rejection remains bounded")
            .expect("parent replacement writer joins")
            .expect_err("commit hook rejects a replaced state parent");
        let StateError::Database(failure) = error else {
            panic!("expected commit-hook constraint, received {error:?}");
        };
        assert_eq!(failure.operation(), "commit session create");
        assert_eq!(failure.code(), Some("531"));
        let store = std::sync::Arc::try_unwrap(store)
            .unwrap_or_else(|_| panic!("writer retained parent-replacement store"));
        assert!(matches!(
            store.close().await,
            Err(StateError::CloseDegraded {
                os_lock_released: true,
                ..
            })
        ));

        let moved_database = moved_parent.join("parent-replacement.sqlite");
        let options = SqliteConnectOptions::new()
            .filename(&moved_database)
            .read_only(true)
            .create_if_missing(false);
        let mut reader = SqliteConnection::connect_with(&options)
            .await
            .expect("open moved database rollback reader");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sessions WHERE id = 'parent-replacement-row'"
            )
            .fetch_one(&mut reader)
            .await
            .expect("read parent-replacement rollback"),
            0
        );
        reader.close().await.expect("close moved rollback reader");
        fs::remove_dir(&original_parent).expect("remove replacement state parent");
        fs::remove_dir_all(&moved_parent).expect("remove moved state parent");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sqlite_handle_detects_path_swap_and_swap_back() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "sqlite-handle.sqlite");
        let detached = database_path(&directory, "sqlite-handle-detached.sqlite");
        let replacement_path = database_path(&directory, "sqlite-handle-replacement.sqlite");
        open(&path)
            .await
            .close()
            .await
            .expect("seed locked database closes");
        open(&replacement_path)
            .await
            .close()
            .await
            .expect("seed replacement database closes");
        let options = SqliteConnectOptions::new().filename(&path);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("open direct SQLite handle");

        fs::rename(&path, &detached).expect("detach opened SQLite file");
        fs::rename(&replacement_path, &path).expect("replace original pathname");
        assert!(
            !test_support::sqlite_identity_is_valid(&mut connection).await,
            "SQLite VFS must report the opened file was moved"
        );
        connection.close().await.expect("direct handle closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn active_repository_transaction_fails_closed_on_database_replacement() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "active-write.sqlite");
        let detached = database_path(&directory, "active-write-detached.sqlite");
        let store = std::sync::Arc::new(open(&path).await);
        let owner = test_support::owner(&store).to_owned();
        let (entered, release) = crate::repository::test_support::set_write_barrier(&owner);
        let record = session("must-not-commit-after-replacement", 1);
        let record_id = record.id.clone();
        let writer_store = std::sync::Arc::clone(&store);
        let mut writer = tokio::spawn(async move { writer_store.sessions().create(&record).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("repository write reaches verified transaction within two seconds");

        fs::rename(&path, &detached).expect("detach active database");
        for suffix in ["-wal", "-shm"] {
            let source = sidecar(&path, suffix);
            if source.exists() {
                fs::rename(&source, sidecar(&detached, suffix))
                    .expect("move active database sidecar");
            }
        }
        let replacement = open(&path).await;
        release.notify_one();
        let write_result = match tokio::time::timeout(Duration::from_secs(2), &mut writer).await {
            Ok(join) => join.expect("repository write task joins"),
            Err(_) => {
                writer.abort();
                let _ = writer.await;
                panic!("repository write exceeded two seconds");
            }
        };
        assert!(
            write_result.is_err(),
            "repository write must not report success after path replacement"
        );
        assert!(
            replacement
                .sessions()
                .get(&record_id)
                .await
                .expect("read replacement database")
                .is_none()
        );
        replacement.close().await.expect("replacement closes");

        let store = match std::sync::Arc::try_unwrap(store) {
            Ok(store) => store,
            Err(_) => panic!("writer task retained the state store"),
        };
        let close = store
            .close()
            .await
            .expect_err("detached path degrades original close");
        assert!(matches!(
            close,
            StateError::CloseDegraded {
                os_lock_released: true,
                ..
            }
        ));
        let detached_store = open(&detached).await;
        assert!(
            detached_store
                .sessions()
                .get(&record_id)
                .await
                .expect("read detached database")
                .is_none()
        );
        detached_store
            .close()
            .await
            .expect("detached database closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn commit_boundary_logical_identity_drift_rolls_back_every_change() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "commit-logical-drift.sqlite");
        let store = open(&path).await;
        let owner = test_support::owner(&store).to_owned();
        crate::repository::test_support::set_commit_tamper(&owner);
        let record = session("must-rollback-logical-drift", 1);
        let error = store
            .sessions()
            .create(&record)
            .await
            .expect_err("commit-boundary logical drift is rejected");
        assert!(matches!(error, StateError::InvalidMigrationHistory { .. }));
        assert!(
            store
                .sessions()
                .get(&record.id)
                .await
                .expect("read rolled-back session")
                .is_none()
        );
        assert!(
            store
                .health()
                .await
                .expect("health after logical rollback")
                .is_healthy()
        );
        let rogue_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type = 'table' AND name = 'commit_boundary_rogue'
             )",
        )
        .fetch_one(test_support::pool(&store))
        .await
        .expect("inspect rolled-back rogue schema");
        assert!(!rogue_exists);
        store.close().await.expect("logical drift store closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn commit_hook_rejects_xattr_and_lock_generation_drift() {
        use std::os::unix::fs::PermissionsExt as _;
        use xattr::FileExt as _;

        for drift in ["xattr", "header"] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let path = database_path(&directory, &format!("commit-{drift}.sqlite"));
            let store = std::sync::Arc::new(open(&path).await);
            let owner = test_support::owner(&store).to_owned();
            let lock_path = unix_lock_path(&path);
            let lock_header = fs::read(&lock_path).expect("read original lock header");
            let database_file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .expect("open database identity xattr");
            let identity = database_file
                .get_xattr("user.gta-claw.writer-lock-path")
                .expect("read original database identity")
                .expect("database identity exists");
            let (entered, release) = crate::repository::test_support::set_commit_barrier(&owner);
            let record = session(&format!("commit-{drift}-rollback"), 1);
            let record_id = record.id.clone();
            let writer_store = std::sync::Arc::clone(&store);
            let mut writer =
                tokio::spawn(async move { writer_store.sessions().create(&record).await });
            tokio::time::timeout(Duration::from_secs(2), entered.notified())
                .await
                .expect("writer reaches actual SQLite commit boundary");

            if drift == "xattr" {
                database_file
                    .remove_xattr("user.gta-claw.writer-lock-path")
                    .expect("remove database generation before commit");
            } else {
                fs::write(&lock_path, vec![b'x'; lock_header.len()])
                    .expect("replace lock generation bytes before commit");
                fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                    .expect("preserve private lock mode");
            }
            release.notify_one();
            let error = tokio::time::timeout(Duration::from_secs(2), &mut writer)
                .await
                .expect("commit-hook rejection remains bounded")
                .expect("writer task joins")
                .expect_err("commit hook rejects lost binding");
            let StateError::Database(failure) = error else {
                panic!("expected SQLite commit-hook constraint, received {error:?}");
            };
            assert_eq!(failure.operation(), "commit session create");
            assert_eq!(failure.code(), Some("531"));

            if drift == "xattr" {
                database_file
                    .set_xattr("user.gta-claw.writer-lock-path", &identity)
                    .expect("restore database generation");
            } else {
                fs::write(&lock_path, &lock_header).expect("restore lock generation");
                fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                    .expect("restore private lock mode");
            }
            assert!(
                store
                    .sessions()
                    .get(&record_id)
                    .await
                    .expect("read rolled-back commit-hook row")
                    .is_none()
            );
            let store = std::sync::Arc::try_unwrap(store)
                .unwrap_or_else(|_| panic!("writer retained commit-hook store"));
            store.close().await.expect("commit-hook store closes");
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_identity_handle_prevents_path_replacement() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "windows-identity.sqlite");
        let detached = database_path(&directory, "windows-identity-detached.sqlite");
        let store = open(&path).await;

        let error = fs::rename(&path, &detached)
            .expect_err("locked Windows identity cannot be renamed or replaced");
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Other
            ) || error.raw_os_error() == Some(32)
        );
        assert!(
            store
                .health()
                .await
                .expect("store remains healthy")
                .is_healthy()
        );
        store.close().await.expect("Windows identity store closes");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_live_lock_cannot_be_renamed_or_split() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "windows-live-lock.sqlite");
        let renamed = database_path(&directory, "windows-live-lock-renamed");
        let store = open(&path).await;
        let lock_path = test_support::lock_path(&store).to_owned();
        let owner_before = persisted_writer(&path)
            .await
            .expect("live Windows owner is persisted");
        let error = fs::rename(&lock_path, &renamed)
            .expect_err("held Windows lock excludes delete sharing");
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Other
            ) || error.raw_os_error() == Some(32)
        );
        let error = fs::OpenOptions::new()
            .write(true)
            .open(&lock_path)
            .expect_err("held Windows lock excludes hostile write handles");
        assert!(matches!(
            error.raw_os_error(),
            Some(5) | Some(32) | Some(33)
        ));
        let wal_path = sidecar(&path, "-wal");
        let detached_wal = sidecar(&path, "-wal-detached");
        let error = fs::rename(&wal_path, &detached_wal)
            .expect_err("pinned Windows WAL handle excludes delete sharing");
        assert!(matches!(
            error.raw_os_error(),
            Some(5) | Some(32) | Some(33)
        ));
        let detached_parent = directory.path().with_extension("detached-parent");
        let error = fs::rename(directory.path(), &detached_parent)
            .expect_err("pinned Windows state directory excludes delete sharing");
        assert!(matches!(
            error.raw_os_error(),
            Some(5) | Some(32) | Some(33)
        ));
        let second = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("second Windows writer is rejected");
        assert!(matches!(second, StateError::StoreLocked { .. }));
        assert_eq!(persisted_writer(&path).await, Some(owner_before));
        store.close().await.expect("Windows live-lock store closes");
        assert!(!renamed.exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_cross_principal_empty_database_is_not_adopted() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "world-writable-empty.sqlite");
        fs::write(&path, b"").expect("precreate empty Windows database");
        test_support::secure_windows_file_fixture(&path);
        let status = Command::new("icacls.exe")
            .arg(&path)
            .args(["/grant", "*S-1-1-0:(M)"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run native Windows ACL editor");
        assert!(status.success());
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open insecure Windows database");
        assert!(
            !claw_sqlite_file_control::windows_file_is_service_private(&file)
                .expect("inspect insecure Windows ACL")
        );
        let identity = claw_sqlite_file_control::windows_file_identity(&file)
            .expect("capture insecure Windows identity");
        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("world-writable empty database is rejected");
        assert!(matches!(
            error,
            StateError::InvalidPath {
                reason: "state database does not have the exact protected service DACL",
                ..
            }
        ));
        assert_eq!(fs::read(&path).expect("read unchanged empty database"), b"");
        assert_eq!(
            claw_sqlite_file_control::windows_file_identity(&file)
                .expect("recapture insecure Windows identity"),
            identity
        );
        assert!(!sidecar(&path, "-wal").exists());
        assert!(!sidecar(&path, "-shm").exists());
        assert!(!sidecar(&path, ":gta-claw-writer-identity").exists());

        let readonly_path = database_path(&directory, "world-readable-empty.sqlite");
        fs::write(&readonly_path, b"").expect("precreate readable empty Windows database");
        test_support::secure_windows_file_fixture(&readonly_path);
        let status = Command::new("icacls.exe")
            .arg(&readonly_path)
            .args(["/grant", "*S-1-1-0:(R)"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("grant native Windows read-only ACL");
        assert!(status.success());
        let readonly_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&readonly_path)
            .expect("open readable Windows database");
        assert!(
            !claw_sqlite_file_control::windows_file_is_service_private(&readonly_file)
                .expect("read-only cross-principal ACL is not service-private")
        );
        let error = StateStore::open(StoreConfig::new(&readonly_path))
            .await
            .err()
            .expect("world-readable empty database is rejected");
        assert!(matches!(
            error,
            StateError::InvalidPath {
                reason: "state database does not have the exact protected service DACL",
                ..
            }
        ));
        assert_eq!(
            fs::read(&readonly_path).expect("read unchanged readable database"),
            b""
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_inherited_temp_parent_requires_private_fixture_preparation() {
        let outer = tempfile::tempdir().expect("outer temporary directory");
        let status = Command::new("icacls.exe")
            .arg(outer.path())
            .args(["/grant", "*S-1-1-0:(OI)(CI)(M)"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("grant inheritable world-write test ACL");
        assert!(status.success());
        let inherited = tempfile::Builder::new()
            .prefix("inherited-state-")
            .tempdir_in(outer.path())
            .expect("create inherited temporary directory");
        let path = inherited.path().join("state.sqlite");

        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("raw inherited temporary parent is rejected");
        assert!(matches!(
            error,
            StateError::InvalidPath {
                reason: "state directory does not have the exact protected service DACL",
                ..
            }
        ));
        assert!(!path.exists());

        secure_windows_test_directory(inherited.path());
        open(&path)
            .await
            .close()
            .await
            .expect("prepared temporary parent satisfies the public path contract");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_case_only_database_path_reopens_same_identity() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let lower = database_path(&directory, "case-path.sqlite");
        open(&lower)
            .await
            .close()
            .await
            .expect("seed lowercase Windows path");
        let upper = directory.path().join("CASE-PATH.SQLITE");
        let reopened = StateStore::open(StoreConfig::new(&upper))
            .await
            .expect("case-only Windows path resolves to the same file identity");
        reopened.close().await.expect("case-only store closes");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_moved_database_rejects_committed_old_path_sidecar() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let original = database_path(&directory, "moved-sidecar-source.sqlite");
        let moved = directory.path().join("moved-sidecar-target.sqlite");
        open(&original)
            .await
            .close()
            .await
            .expect("seed moved-sidecar source");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match fs::rename(&original, &moved) {
                    Ok(()) => break,
                    Err(error) if matches!(error.raw_os_error(), Some(32) | Some(33)) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("move database without sidecars: {error}"),
                }
            }
        })
        .await
        .expect("closed source releases Windows sharing handles");
        let old_wal = sidecar(&original, "-wal");
        fs::write(&old_wal, b"committed-old-path-wal").expect("create old-path WAL fixture");
        test_support::secure_windows_file_fixture(&old_wal);
        let error = StateStore::open(StoreConfig::new(&moved))
            .await
            .err()
            .expect("old-path WAL prevents rebinding moved database");
        assert!(matches!(
            error,
            StateError::InvalidPath {
                reason: "database was moved without its SQLite sidecars",
                ..
            }
        ));
        assert_eq!(
            fs::read(&old_wal).expect("read untouched old-path WAL"),
            b"committed-old-path-wal"
        );
    }

    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[tokio::test]
    async fn unix_fifo_restore_source_is_rejected_without_blocking() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let fifo = directory.path().join("restore-source.fifo");
        let destination = database_path(&directory, "fifo-destination.sqlite");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .expect("create FIFO restore fixture");
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            StateStore::restore_backup(&fifo, &destination),
        )
        .await
        .expect("FIFO restore preflight must not block")
        .expect_err("FIFO restore source is rejected");
        assert!(matches!(error, StateError::InvalidPath { .. }));
        assert!(!destination.exists());
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn apple_extended_acl_is_rejected_without_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temporary directory");
        let ancestor = root.path().join("acl-ancestor");
        fs::create_dir(&ancestor).expect("create ACL-bearing ancestor");
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))
            .expect("set private ancestor mode before ACL");
        let parent = ancestor.join("clean-state-parent");
        fs::create_dir(&parent).expect("create ACL state parent");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .expect("set clean state-parent mode");
        let status = Command::new("chmod")
            .args(["+a", "everyone allow write,delete"])
            .arg(&ancestor)
            .status()
            .expect("attach Apple ancestor ACL");
        assert!(status.success());
        let path = parent.join("state.sqlite");
        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("Apple extended ACL is rejected");
        assert!(matches!(error, StateError::InvalidPath { .. }));
        assert!(!path.exists());
        let status = Command::new("chmod")
            .arg("-N")
            .arg(&ancestor)
            .status()
            .expect("remove Apple ancestor ACL for cleanup");
        assert!(status.success());
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn apple_acl_less_private_store_commits_and_backs_up() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "acl-less-state.sqlite");
        let backup = database_path(&directory, "acl-less-backup.sqlite");
        let store = open(&path).await;
        store
            .sessions()
            .create(&session("acl-less-row", 1))
            .await
            .expect("ACL-less Apple store commits");
        store
            .backup_to(&backup)
            .await
            .expect("ACL-less Apple store backs up");
        assert!(backup.exists());
        store.close().await.expect("ACL-less Apple store closes");
    }

    #[tokio::test]
    async fn in_memory_and_uncreatable_paths_never_fall_back() {
        let memory = StateStore::open(StoreConfig::new(":memory:"))
            .await
            .err()
            .expect("memory path is rejected");
        assert!(matches!(
            memory,
            StateError::InvalidPath {
                reason: "in-memory databases are not permitted",
                ..
            }
        ));

        let directory = tempfile::tempdir().expect("temporary directory");
        let missing_parent = directory.path().join("missing").join("state.sqlite");
        let error = StateStore::open(StoreConfig::new(&missing_parent))
            .await
            .err()
            .expect("missing parent fails");
        assert!(matches!(error, StateError::FileSystem { .. }));
        assert!(!missing_parent.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn insecure_precreated_empty_database_is_rejected_without_mutation() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        use xattr::FileExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = database_path(&directory, "foreign-empty.sqlite");
        fs::write(&path, b"").expect("precreate empty database");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
            .expect("make precreated database untrusted");
        let before = fs::symlink_metadata(&path).expect("inspect precreated database");
        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("insecure precreated database is rejected");
        assert_eq!(
            error,
            StateError::InvalidPath {
                path: fs::canonicalize(directory.path())
                    .expect("canonicalize test directory")
                    .join("foreign-empty.sqlite"),
                reason: "state database must be service-owned, mode 0600, regular, and single-link",
            }
        );
        let after = fs::symlink_metadata(&path).expect("reinspect precreated database");
        assert_eq!(
            fs::read(&path).expect("read unchanged precreated database"),
            b""
        );
        assert_eq!(after.mode(), before.mode());
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.ino(), before.ino());
        assert!(
            fs::File::open(&path)
                .expect("open unchanged database")
                .get_xattr("user.gta-claw.writer-lock-path")
                .expect("read unchanged identity xattr")
                .is_none()
        );
        assert!(!sidecar(&path, "-wal").exists());
        assert!(!sidecar(&path, "-shm").exists());
    }

    #[tokio::test]
    async fn authentication_and_task_state_machines_reach_terminal_states() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = open(&database_path(&directory, "state-machines.sqlite")).await;
        let session = session("session-1", 1);
        let device = device("device-1", 2);
        let authentication = authentication("auth-1", &device.id, 3);
        let task = task("task-1", &session.id, 4);
        store
            .sessions()
            .create(&session)
            .await
            .expect("create session");
        store
            .devices()
            .create(&device)
            .await
            .expect("create device");
        store
            .authentications()
            .create(&authentication)
            .await
            .expect("create authentication");
        store.tasks().create(&task).await.expect("create task");

        let authorized = store
            .authentications()
            .update_status(
                &authentication.id,
                1,
                AuthenticationStatus::Authorized,
                Some("github-subject".to_owned()),
                timestamp(5),
            )
            .await
            .expect("authorize");
        assert_eq!(authorized.subject.as_deref(), Some("github-subject"));
        let completed = store
            .tasks()
            .update_status(&task.id, 1, TaskStatus::Running, timestamp(5))
            .await
            .expect("start task");
        let completed = store
            .tasks()
            .update_status(
                &task.id,
                completed.version,
                TaskStatus::Succeeded,
                timestamp(6),
            )
            .await
            .expect("complete task");
        assert_eq!(completed.status, TaskStatus::Succeeded);
        let invalid = store
            .tasks()
            .update_status(
                &task.id,
                completed.version,
                TaskStatus::Running,
                timestamp(7),
            )
            .await
            .expect_err("terminal task cannot restart");
        assert!(matches!(invalid, StateError::InvalidTransition { .. }));
    }
}

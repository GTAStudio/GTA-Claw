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

    use claw_domain::SessionId;
    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::{Connection, Executor, SqliteConnection};
    use tempfile::TempDir;

    use super::*;
    use crate::store::test_support;

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
        directory.path().join(name)
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

        let store = StateStore::open(StoreConfig::new(&path))
            .await
            .expect("version-zero prefix migrates");
        assert!(store.health().await.expect("migrated health").is_healthy());
        assert!(store.recovered_writer().is_none());
        store.close().await.expect("migrated store closes");
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
        assert!(matches!(error, StateError::InvalidMigrationHistory { .. }));
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
        for index in 0..20 {
            let session = session(&format!("race-session-{index}"), index * 10 + 1);
            let task = task(&format!("race-task-{index}"), &session.id, index * 10 + 2);
            store
                .sessions()
                .create(&session)
                .await
                .expect("create racing session");
            let sessions = store.sessions();
            let tasks = store.tasks();
            let (archived, created) = tokio::join!(
                sessions.update_status(
                    &session.id,
                    1,
                    SessionStatus::Archived,
                    timestamp(index * 10 + 3)
                ),
                tasks.create(&task)
            );
            archived.expect("archive wins or follows task creation");
            match created {
                Ok(()) => assert!(
                    store
                        .tasks()
                        .get(&task.id)
                        .await
                        .expect("read racing task")
                        .is_some()
                ),
                Err(StateError::InactiveParent {
                    entity: "session",
                    state: "archived",
                    ..
                }) => {}
                Err(error) => panic!("unexpected archive/create race result: {error}"),
            }
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
             VALUES (2, 'future', ?, 1)",
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
                found: 2,
                supported: 1,
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
        let journal_before = test_support::journal_mode(&path)
            .await
            .expect("read journal before empty-history rejection");
        let writer_before = persisted_writer(&path).await;
        let before = database_artifact_bytes(&path);

        let error = StateStore::open(StoreConfig::new(&path))
            .await
            .err()
            .expect("complete schema with empty history is rejected");
        assert!(matches!(error, StateError::InvalidMigrationHistory { .. }));
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
            let journal_before = test_support::journal_mode(&path)
                .await
                .expect("read journal before schema rejection");
            let writer_before = persisted_writer(&path).await;
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

    #[cfg(unix)]
    #[tokio::test]
    async fn restore_accepts_read_only_standalone_backup() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "read-only-source.sqlite");
        let backup_directory = directory.path().join("read-only-backup");
        fs::create_dir(&backup_directory).expect("create read-only backup directory");
        let backup_path = backup_directory.join("backup.sqlite");
        let destination = database_path(&directory, "read-only-restored.sqlite");
        let source = open(&source_path).await;
        source.backup_to(&backup_path).await.expect("create backup");
        source.close().await.expect("source store closes");
        fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o444))
            .expect("make backup read-only");
        fs::set_permissions(&backup_directory, fs::Permissions::from_mode(0o555))
            .expect("make backup directory read-only");

        StateStore::restore_backup(&backup_path, &destination)
            .await
            .expect("restore does not mutate read-only source");
        open(&destination)
            .await
            .close()
            .await
            .expect("restored store closes");

        fs::set_permissions(&backup_directory, fs::Permissions::from_mode(0o755))
            .expect("restore backup directory permissions for cleanup");
    }

    #[tokio::test]
    async fn post_publication_failure_reports_published_destination() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "publication-source.sqlite");
        let destination = database_path(&directory, "publication-destination.sqlite");
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
        open(&destination)
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

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_source_removal_failure_reports_published_destination() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = database_path(&directory, "windows-publication-source.sqlite");
        let destination = database_path(&directory, "windows-publication-destination.sqlite");
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
        open(&destination)
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
        let managed = open(&source_path).await;

        let (backup, checkpoint) = tokio::join!(managed.backup_to(&backup_path), async {
            sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .execute(&mut checkpointer)
                .await
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
                 VALUES (2, 'future', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 1)",
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
        assert!(matches!(error, StateError::StoreLocked { .. }));
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
        owner.close().await.expect("lock owner closes");

        let error = StateStore::open(StoreConfig::new(&alias))
            .await
            .err()
            .expect("hard-link alias remains rejected after the owner closes");
        assert!(matches!(error, StateError::InvalidPath { .. }));
        #[cfg(unix)]
        fs::remove_file(&alias).expect("remove rejected Unix hard-link alias");
        open(&path)
            .await
            .close()
            .await
            .expect("canonical database name still opens");
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
        fs::File::create(&symlink_db).expect("create symlink-root database");
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
        assert!(matches!(error, StateError::InvalidPath { .. }));

        let permissive_db = database_path(&directory, "permissive-root.sqlite");
        fs::File::create(&permissive_db).expect("create permissive-root database");
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
        fs::File::create(&hardlink_db).expect("create hardlink-lock database");
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
        fs::File::create(&stale_db).expect("create stale-lock database");
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
        let root = test_support::private_lock_root();
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
            fs::File::create(&database).expect("create canonical attack database");
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

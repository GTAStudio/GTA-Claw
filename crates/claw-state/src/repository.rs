use claw_domain::SessionId;
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
#[cfg(test)]
use std::sync::{Arc, Mutex};

use crate::error::database;
use crate::model::{finish_page, invalid_stored, validate_text};
use crate::{
    AuthenticationId, AuthenticationRecord, AuthenticationStatus, DeviceId, DeviceRecord, Page,
    PageCursor, PageRequest, SessionRecord, SessionStatus, StateError, TaskId, TaskRecord,
    TaskStatus, TimestampMs,
};

#[cfg(test)]
static WRITE_TEST_BARRIER: Mutex<Option<WriteTestBarrier>> = Mutex::new(None);

#[cfg(test)]
struct WriteTestBarrier {
    owner: String,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

/// Transactional access to durable sessions.
pub struct SessionRepository<'store> {
    pool: &'store SqlitePool,
    owner: &'store str,
}

impl<'store> SessionRepository<'store> {
    pub(crate) const fn new(pool: &'store SqlitePool, owner: &'store str) -> Self {
        Self { pool, owner }
    }

    /// Creates one session.
    pub async fn create(&self, record: &SessionRecord) -> Result<(), StateError> {
        validate_new_session(record)?;
        let mut transaction =
            begin_verified_write(self.pool, self.owner, "begin session create").await?;
        sqlx::query(
            "INSERT INTO sessions(id, status, created_at_ms, updated_at_ms, version)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(record.id.as_str())
        .bind(record.status.as_db())
        .bind(record.created_at.get())
        .bind(record.updated_at.get())
        .bind(record.version)
        .execute(&mut *transaction)
        .await
        .map_err(|error| create_error(error, "session", record.id.as_str(), None))?;
        commit_verified(transaction, "commit session create").await?;
        Ok(())
    }

    /// Reads one session.
    pub async fn get(&self, id: &SessionId) -> Result<Option<SessionRecord>, StateError> {
        let row = sqlx::query(
            "SELECT id, status, created_at_ms, updated_at_ms, version
             FROM sessions WHERE id = ?",
        )
        .bind(id.as_str())
        .fetch_optional(self.pool)
        .await
        .map_err(|error| database("read session", error))?;
        row.map(session_from_row).transpose()
    }

    /// Lists sessions in stable creation-time and identifier order.
    pub async fn list(&self, request: &PageRequest) -> Result<Page<SessionRecord>, StateError> {
        let (after_time, after_id) = request.after_parts();
        let rows = sqlx::query(
            "SELECT id, status, created_at_ms, updated_at_ms, version
             FROM sessions
             WHERE created_at_ms > ? OR (created_at_ms = ? AND id > ?)
             ORDER BY created_at_ms, id
             LIMIT ?",
        )
        .bind(after_time)
        .bind(after_time)
        .bind(after_id)
        .bind(request.query_limit())
        .fetch_all(self.pool)
        .await
        .map_err(|error| database("list sessions", error))?;
        let items = rows
            .into_iter()
            .map(session_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(finish_page(items, request.limit(), |record| {
            PageCursor::new(record.created_at, record.id.as_str())
                .expect("persisted session id is a valid cursor")
        }))
    }

    /// Applies a valid lifecycle transition with optimistic concurrency.
    pub async fn update_status(
        &self,
        id: &SessionId,
        expected_version: i64,
        status: SessionStatus,
        updated_at: TimestampMs,
    ) -> Result<SessionRecord, StateError> {
        let current = self
            .get(id)
            .await?
            .ok_or_else(|| not_found("session", id.as_str()))?;
        if current.version != expected_version {
            return Err(conflict("session", id.as_str(), expected_version));
        }
        if !matches!(
            (current.status, status),
            (SessionStatus::Active, SessionStatus::Archived)
        ) {
            return Err(StateError::InvalidTransition {
                entity: "session",
                from: current.status.as_db(),
                to: status.as_db(),
            });
        }
        validate_update_time(current.updated_at, updated_at)?;
        let mut transaction =
            begin_verified_write(self.pool, self.owner, "begin session update").await?;
        let row = sqlx::query(
            "UPDATE sessions
             SET status = ?, updated_at_ms = ?, version = version + 1
             WHERE id = ? AND version = ?
             RETURNING id, status, created_at_ms, updated_at_ms, version",
        )
        .bind(status.as_db())
        .bind(updated_at.get())
        .bind(id.as_str())
        .bind(expected_version)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database("update session", error))?;
        let record = row
            .map(session_from_row)
            .transpose()?
            .ok_or_else(|| conflict("session", id.as_str(), expected_version))?;
        commit_verified(transaction, "commit session update").await?;
        Ok(record)
    }
}

/// Transactional access to durable devices.
pub struct DeviceRepository<'store> {
    pool: &'store SqlitePool,
    owner: &'store str,
}

impl<'store> DeviceRepository<'store> {
    pub(crate) const fn new(pool: &'store SqlitePool, owner: &'store str) -> Self {
        Self { pool, owner }
    }

    /// Creates one device.
    pub async fn create(&self, record: &DeviceRecord) -> Result<(), StateError> {
        validate_new_device(record)?;
        let mut transaction =
            begin_verified_write(self.pool, self.owner, "begin device create").await?;
        insert_device(&mut transaction, record).await?;
        commit_verified(transaction, "commit device create").await?;
        Ok(())
    }

    /// Atomically creates a device and its initial authentication.
    pub async fn create_with_authentication(
        &self,
        device: &DeviceRecord,
        authentication: &AuthenticationRecord,
    ) -> Result<(), StateError> {
        validate_new_device(device)?;
        validate_new_authentication(authentication)?;
        if device.id != authentication.device_id {
            return Err(StateError::InvalidValue {
                field: "authentication device id",
                reason: "must match the device created in the transaction",
            });
        }
        let mut transaction = begin_verified_write(
            self.pool,
            self.owner,
            "begin device and authentication create",
        )
        .await?;
        insert_device(&mut transaction, device).await?;
        insert_authentication(&mut transaction, authentication).await?;
        commit_verified(transaction, "commit device and authentication create").await?;
        Ok(())
    }

    /// Reads one device.
    pub async fn get(&self, id: &DeviceId) -> Result<Option<DeviceRecord>, StateError> {
        let row = sqlx::query(
            "SELECT id, display_name, created_at_ms, updated_at_ms, version
             FROM devices WHERE id = ?",
        )
        .bind(id.as_str())
        .fetch_optional(self.pool)
        .await
        .map_err(|error| database("read device", error))?;
        row.map(device_from_row).transpose()
    }

    /// Lists devices in stable creation-time and identifier order.
    pub async fn list(&self, request: &PageRequest) -> Result<Page<DeviceRecord>, StateError> {
        let (after_time, after_id) = request.after_parts();
        let rows = sqlx::query(
            "SELECT id, display_name, created_at_ms, updated_at_ms, version
             FROM devices
             WHERE created_at_ms > ? OR (created_at_ms = ? AND id > ?)
             ORDER BY created_at_ms, id
             LIMIT ?",
        )
        .bind(after_time)
        .bind(after_time)
        .bind(after_id)
        .bind(request.query_limit())
        .fetch_all(self.pool)
        .await
        .map_err(|error| database("list devices", error))?;
        let items = rows
            .into_iter()
            .map(device_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(finish_page(items, request.limit(), |record| {
            PageCursor::new(record.created_at, record.id.as_str())
                .expect("persisted device id is a valid cursor")
        }))
    }

    /// Renames a device with optimistic concurrency.
    pub async fn rename(
        &self,
        id: &DeviceId,
        expected_version: i64,
        display_name: impl Into<String>,
        updated_at: TimestampMs,
    ) -> Result<DeviceRecord, StateError> {
        let display_name = validate_text("device display name", display_name.into())?;
        let current = self
            .get(id)
            .await?
            .ok_or_else(|| not_found("device", id.as_str()))?;
        if current.version != expected_version {
            return Err(conflict("device", id.as_str(), expected_version));
        }
        validate_update_time(current.updated_at, updated_at)?;
        let mut transaction =
            begin_verified_write(self.pool, self.owner, "begin device rename").await?;
        let row = sqlx::query(
            "UPDATE devices
             SET display_name = ?, updated_at_ms = ?, version = version + 1
             WHERE id = ? AND version = ?
             RETURNING id, display_name, created_at_ms, updated_at_ms, version",
        )
        .bind(display_name)
        .bind(updated_at.get())
        .bind(id.as_str())
        .bind(expected_version)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database("rename device", error))?;
        let record = row
            .map(device_from_row)
            .transpose()?
            .ok_or_else(|| conflict("device", id.as_str(), expected_version))?;
        commit_verified(transaction, "commit device rename").await?;
        Ok(record)
    }
}

/// Transactional access to provider authentication records.
pub struct AuthenticationRepository<'store> {
    pool: &'store SqlitePool,
    owner: &'store str,
}

impl<'store> AuthenticationRepository<'store> {
    pub(crate) const fn new(pool: &'store SqlitePool, owner: &'store str) -> Self {
        Self { pool, owner }
    }

    /// Creates one authentication.
    pub async fn create(&self, record: &AuthenticationRecord) -> Result<(), StateError> {
        validate_new_authentication(record)?;
        let mut transaction =
            begin_verified_write(self.pool, self.owner, "begin authentication create").await?;
        insert_authentication(&mut transaction, record).await?;
        commit_verified(transaction, "commit authentication create").await?;
        Ok(())
    }

    /// Reads one authentication.
    pub async fn get(
        &self,
        id: &AuthenticationId,
    ) -> Result<Option<AuthenticationRecord>, StateError> {
        let row = sqlx::query(
            "SELECT id, device_id, provider, subject, status, created_at_ms, updated_at_ms, version
             FROM authentication_records WHERE id = ?",
        )
        .bind(id.as_str())
        .fetch_optional(self.pool)
        .await
        .map_err(|error| database("read authentication", error))?;
        row.map(authentication_from_row).transpose()
    }

    /// Lists a device's authentications in stable creation-time and identifier order.
    pub async fn list_for_device(
        &self,
        device_id: &DeviceId,
        request: &PageRequest,
    ) -> Result<Page<AuthenticationRecord>, StateError> {
        let (after_time, after_id) = request.after_parts();
        let rows = sqlx::query(
            "SELECT id, device_id, provider, subject, status, created_at_ms, updated_at_ms, version
             FROM authentication_records
             WHERE device_id = ?
               AND (created_at_ms > ? OR (created_at_ms = ? AND id > ?))
             ORDER BY created_at_ms, id
             LIMIT ?",
        )
        .bind(device_id.as_str())
        .bind(after_time)
        .bind(after_time)
        .bind(after_id)
        .bind(request.query_limit())
        .fetch_all(self.pool)
        .await
        .map_err(|error| database("list authentications", error))?;
        let items = rows
            .into_iter()
            .map(authentication_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(finish_page(items, request.limit(), |record| {
            PageCursor::new(record.created_at, record.id.as_str())
                .expect("persisted authentication id is a valid cursor")
        }))
    }

    /// Applies a valid lifecycle transition with optimistic concurrency.
    pub async fn update_status(
        &self,
        id: &AuthenticationId,
        expected_version: i64,
        status: AuthenticationStatus,
        subject: Option<String>,
        updated_at: TimestampMs,
    ) -> Result<AuthenticationRecord, StateError> {
        let subject = validate_auth_subject(status, subject)?;
        let current = self
            .get(id)
            .await?
            .ok_or_else(|| not_found("authentication", id.as_str()))?;
        if current.version != expected_version {
            return Err(conflict("authentication", id.as_str(), expected_version));
        }
        let valid = matches!(
            (current.status, status),
            (
                AuthenticationStatus::Pending,
                AuthenticationStatus::Authorized
            ) | (AuthenticationStatus::Pending, AuthenticationStatus::Revoked)
                | (
                    AuthenticationStatus::Authorized,
                    AuthenticationStatus::Revoked
                )
        );
        if !valid {
            return Err(StateError::InvalidTransition {
                entity: "authentication",
                from: current.status.as_db(),
                to: status.as_db(),
            });
        }
        validate_update_time(current.updated_at, updated_at)?;
        let mut transaction =
            begin_verified_write(self.pool, self.owner, "begin authentication update").await?;
        let row = sqlx::query(
            "UPDATE authentication_records
             SET status = ?, subject = ?, updated_at_ms = ?, version = version + 1
             WHERE id = ? AND version = ?
             RETURNING id, device_id, provider, subject, status,
                       created_at_ms, updated_at_ms, version",
        )
        .bind(status.as_db())
        .bind(subject)
        .bind(updated_at.get())
        .bind(id.as_str())
        .bind(expected_version)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database("update authentication", error))?;
        let record = row
            .map(authentication_from_row)
            .transpose()?
            .ok_or_else(|| conflict("authentication", id.as_str(), expected_version))?;
        commit_verified(transaction, "commit authentication update").await?;
        Ok(record)
    }
}

/// Transactional access to durable tasks.
pub struct TaskRepository<'store> {
    pool: &'store SqlitePool,
    owner: &'store str,
}

impl<'store> TaskRepository<'store> {
    pub(crate) const fn new(pool: &'store SqlitePool, owner: &'store str) -> Self {
        Self { pool, owner }
    }

    /// Creates one task.
    pub async fn create(&self, record: &TaskRecord) -> Result<(), StateError> {
        validate_new_task(record)?;
        let mut transaction =
            begin_verified_write(self.pool, self.owner, "begin task create").await?;
        insert_task(&mut transaction, record).await?;
        commit_verified(transaction, "commit task create").await
    }

    /// Reads one task.
    pub async fn get(&self, id: &TaskId) -> Result<Option<TaskRecord>, StateError> {
        let row = sqlx::query(
            "SELECT id, session_id, kind, payload, status, created_at_ms, updated_at_ms, version
             FROM tasks WHERE id = ?",
        )
        .bind(id.as_str())
        .fetch_optional(self.pool)
        .await
        .map_err(|error| database("read task", error))?;
        row.map(task_from_row).transpose()
    }

    /// Lists a session's tasks in stable creation-time and identifier order.
    pub async fn list_for_session(
        &self,
        session_id: &SessionId,
        request: &PageRequest,
    ) -> Result<Page<TaskRecord>, StateError> {
        let (after_time, after_id) = request.after_parts();
        let rows = sqlx::query(
            "SELECT id, session_id, kind, payload, status, created_at_ms, updated_at_ms, version
             FROM tasks
             WHERE session_id = ?
               AND (created_at_ms > ? OR (created_at_ms = ? AND id > ?))
             ORDER BY created_at_ms, id
             LIMIT ?",
        )
        .bind(session_id.as_str())
        .bind(after_time)
        .bind(after_time)
        .bind(after_id)
        .bind(request.query_limit())
        .fetch_all(self.pool)
        .await
        .map_err(|error| database("list tasks", error))?;
        let items = rows
            .into_iter()
            .map(task_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(finish_page(items, request.limit(), |record| {
            PageCursor::new(record.created_at, record.id.as_str())
                .expect("persisted task id is a valid cursor")
        }))
    }

    /// Applies a valid lifecycle transition with optimistic concurrency.
    pub async fn update_status(
        &self,
        id: &TaskId,
        expected_version: i64,
        status: TaskStatus,
        updated_at: TimestampMs,
    ) -> Result<TaskRecord, StateError> {
        let current = self
            .get(id)
            .await?
            .ok_or_else(|| not_found("task", id.as_str()))?;
        if current.version != expected_version {
            return Err(conflict("task", id.as_str(), expected_version));
        }
        let valid = matches!(
            (current.status, status),
            (TaskStatus::Pending, TaskStatus::Running)
                | (TaskStatus::Pending, TaskStatus::Cancelled)
                | (TaskStatus::Running, TaskStatus::Succeeded)
                | (TaskStatus::Running, TaskStatus::Failed)
                | (TaskStatus::Running, TaskStatus::Cancelled)
        );
        if !valid {
            return Err(StateError::InvalidTransition {
                entity: "task",
                from: current.status.as_db(),
                to: status.as_db(),
            });
        }
        validate_update_time(current.updated_at, updated_at)?;
        let mut transaction =
            begin_verified_write(self.pool, self.owner, "begin task update").await?;
        let row = sqlx::query(
            "UPDATE tasks
             SET status = ?, updated_at_ms = ?, version = version + 1
             WHERE id = ? AND version = ?
             RETURNING id, session_id, kind, payload, status,
                       created_at_ms, updated_at_ms, version",
        )
        .bind(status.as_db())
        .bind(updated_at.get())
        .bind(id.as_str())
        .bind(expected_version)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database("update task", error))?;
        let record = row
            .map(task_from_row)
            .transpose()?
            .ok_or_else(|| conflict("task", id.as_str(), expected_version))?;
        commit_verified(transaction, "commit task update").await?;
        Ok(record)
    }
}

async fn begin_verified_write<'pool>(
    pool: &'pool SqlitePool,
    owner: &str,
    operation: &'static str,
) -> Result<Transaction<'pool, Sqlite>, StateError> {
    const APPLICATION_ID: i64 = 0x4754_4143;

    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| database(operation, error))?;
    let ownership = sqlx::query(
        "UPDATE claw_writer_lock
         SET owner = owner
         WHERE singleton = 1 AND owner = ?",
    )
    .bind(owner)
    .execute(&mut *transaction)
    .await
    .map_err(|error| database("lock and verify application writer", error))?;
    if ownership.rows_affected() != 1 {
        return Err(StateError::InvalidMigrationHistory {
            reason: "application writer ownership changed before repository write".to_owned(),
        });
    }
    let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| database("verify repository application id", error))?;
    if application_id != APPLICATION_ID {
        return Err(StateError::InvalidValue {
            field: "SQLite application id",
            reason: "database ownership changed before repository write",
        });
    }
    #[cfg(test)]
    wait_at_write_test_barrier(owner).await;
    Ok(transaction)
}

#[cfg(test)]
async fn wait_at_write_test_barrier(owner: &str) {
    let barrier = WRITE_TEST_BARRIER
        .lock()
        .expect("write test barrier lock poisoned")
        .as_ref()
        .filter(|configured| configured.owner == owner)
        .map(|configured| {
            (
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        release.notified().await;
        WRITE_TEST_BARRIER
            .lock()
            .expect("write test barrier lock poisoned")
            .take();
    }
}

#[cfg(all(test, unix))]
pub(crate) mod test_support {
    use super::{Arc, WRITE_TEST_BARRIER, WriteTestBarrier};

    pub(crate) fn set_write_barrier(
        owner: &str,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        *WRITE_TEST_BARRIER
            .lock()
            .expect("write test barrier lock poisoned") = Some(WriteTestBarrier {
            owner: owner.to_owned(),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        (entered, release)
    }
}

async fn commit_verified(
    transaction: Transaction<'_, Sqlite>,
    operation: &'static str,
) -> Result<(), StateError> {
    #[cfg(unix)]
    let mut transaction = transaction;
    #[cfg(not(unix))]
    let transaction = transaction;
    #[cfg(unix)]
    {
        let moved = claw_sqlite_file_control::main_database_has_moved(&mut transaction)
            .await
            .map_err(|error| database(operation, sqlx::Error::Protocol(error.to_string())))?;
        if moved {
            return Err(database(
                operation,
                sqlx::Error::Protocol(
                    "SQLite main database identity changed before commit".to_owned(),
                ),
            ));
        }
    }
    transaction
        .commit()
        .await
        .map_err(|error| database(operation, error))
}

async fn insert_device(
    transaction: &mut Transaction<'_, Sqlite>,
    record: &DeviceRecord,
) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO devices(id, display_name, created_at_ms, updated_at_ms, version)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(record.id.as_str())
    .bind(&record.display_name)
    .bind(record.created_at.get())
    .bind(record.updated_at.get())
    .bind(record.version)
    .execute(&mut **transaction)
    .await
    .map_err(|error| create_error(error, "device", record.id.as_str(), None))?;
    Ok(())
}

async fn insert_authentication(
    transaction: &mut Transaction<'_, Sqlite>,
    record: &AuthenticationRecord,
) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO authentication_records(
            id, device_id, provider, subject, status, created_at_ms, updated_at_ms, version
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(record.id.as_str())
    .bind(record.device_id.as_str())
    .bind(&record.provider)
    .bind(&record.subject)
    .bind(record.status.as_db())
    .bind(record.created_at.get())
    .bind(record.updated_at.get())
    .bind(record.version)
    .execute(&mut **transaction)
    .await
    .map_err(|error| {
        create_error(
            error,
            "authentication",
            record.id.as_str(),
            Some(("device", record.device_id.as_str())),
        )
    })?;
    Ok(())
}

async fn insert_task(
    transaction: &mut Transaction<'_, Sqlite>,
    record: &TaskRecord,
) -> Result<(), StateError> {
    let result = sqlx::query(
        "INSERT INTO tasks(
            id, session_id, kind, payload, status, created_at_ms, updated_at_ms, version
         )
         SELECT ?, ?, ?, ?, ?, ?, ?, ?
         WHERE EXISTS (
             SELECT 1 FROM sessions WHERE id = ? AND status = 'active'
         )",
    )
    .bind(record.id.as_str())
    .bind(record.session_id.as_str())
    .bind(&record.kind)
    .bind(&record.payload)
    .bind(record.status.as_db())
    .bind(record.created_at.get())
    .bind(record.updated_at.get())
    .bind(record.version)
    .bind(record.session_id.as_str())
    .execute(&mut **transaction)
    .await
    .map_err(|error| {
        create_error(
            error,
            "task",
            record.id.as_str(),
            Some(("session", record.session_id.as_str())),
        )
    })?;
    if result.rows_affected() == 0 {
        let status = sqlx::query_scalar::<_, String>("SELECT status FROM sessions WHERE id = ?")
            .bind(record.session_id.as_str())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| database("inspect task parent session", error))?;
        return match status.as_deref() {
            None => Err(StateError::ForeignKeyViolation {
                entity: "session",
                id: record.session_id.as_str().to_owned(),
            }),
            Some("archived") => Err(StateError::InactiveParent {
                entity: "session",
                id: record.session_id.as_str().to_owned(),
                state: "archived",
            }),
            Some(_) => Err(invalid_stored("task parent session status")),
        };
    }
    Ok(())
}

fn session_from_row(row: sqlx::sqlite::SqliteRow) -> Result<SessionRecord, StateError> {
    Ok(SessionRecord {
        id: SessionId::new(row.get::<String, _>("id")).map_err(|_| invalid_stored("session id"))?,
        status: SessionStatus::from_db(row.get("status"))?,
        created_at: TimestampMs::new(row.get("created_at_ms"))?,
        updated_at: TimestampMs::new(row.get("updated_at_ms"))?,
        version: valid_version(row.get("version"))?,
    })
}

fn device_from_row(row: sqlx::sqlite::SqliteRow) -> Result<DeviceRecord, StateError> {
    Ok(DeviceRecord {
        id: DeviceId::new(row.get::<String, _>("id"))?,
        display_name: validate_text("stored device display name", row.get("display_name"))?,
        created_at: TimestampMs::new(row.get("created_at_ms"))?,
        updated_at: TimestampMs::new(row.get("updated_at_ms"))?,
        version: valid_version(row.get("version"))?,
    })
}

fn authentication_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<AuthenticationRecord, StateError> {
    let status = AuthenticationStatus::from_db(row.get("status"))?;
    let subject = validate_auth_subject(status, row.get("subject"))?;
    Ok(AuthenticationRecord {
        id: AuthenticationId::new(row.get::<String, _>("id"))?,
        device_id: DeviceId::new(row.get::<String, _>("device_id"))?,
        provider: validate_text("stored authentication provider", row.get("provider"))?,
        subject,
        status,
        created_at: TimestampMs::new(row.get("created_at_ms"))?,
        updated_at: TimestampMs::new(row.get("updated_at_ms"))?,
        version: valid_version(row.get("version"))?,
    })
}

fn task_from_row(row: sqlx::sqlite::SqliteRow) -> Result<TaskRecord, StateError> {
    Ok(TaskRecord {
        id: TaskId::new(row.get::<String, _>("id"))?,
        session_id: SessionId::new(row.get::<String, _>("session_id"))
            .map_err(|_| invalid_stored("task session id"))?,
        kind: validate_text("stored task kind", row.get("kind"))?,
        payload: row.get("payload"),
        status: TaskStatus::from_db(row.get("status"))?,
        created_at: TimestampMs::new(row.get("created_at_ms"))?,
        updated_at: TimestampMs::new(row.get("updated_at_ms"))?,
        version: valid_version(row.get("version"))?,
    })
}

fn validate_auth_subject(
    status: AuthenticationStatus,
    subject: Option<String>,
) -> Result<Option<String>, StateError> {
    match (status, subject) {
        (AuthenticationStatus::Authorized, Some(subject)) => {
            validate_text("authentication subject", subject).map(Some)
        }
        (AuthenticationStatus::Authorized, None) => Err(StateError::InvalidValue {
            field: "authentication subject",
            reason: "is required for authorized records",
        }),
        (_, None) => Ok(None),
        (_, Some(_)) => Err(StateError::InvalidValue {
            field: "authentication subject",
            reason: "is only valid for authorized records",
        }),
    }
}

fn validate_update_time(current: TimestampMs, updated: TimestampMs) -> Result<(), StateError> {
    if updated < current {
        return Err(StateError::InvalidValue {
            field: "updated timestamp",
            reason: "must not precede the current timestamp",
        });
    }
    Ok(())
}

fn validate_new_session(record: &SessionRecord) -> Result<(), StateError> {
    validate_initial_version_and_time(record.version, record.created_at, record.updated_at)?;
    if record.status != SessionStatus::Active {
        return Err(StateError::InvalidValue {
            field: "new session status",
            reason: "must be active",
        });
    }
    Ok(())
}

fn validate_new_device(record: &DeviceRecord) -> Result<(), StateError> {
    validate_text("device display name", record.display_name.clone())?;
    validate_initial_version_and_time(record.version, record.created_at, record.updated_at)
}

fn validate_new_authentication(record: &AuthenticationRecord) -> Result<(), StateError> {
    validate_text("authentication provider", record.provider.clone())?;
    validate_auth_subject(record.status, record.subject.clone())?;
    validate_initial_version_and_time(record.version, record.created_at, record.updated_at)?;
    if record.status != AuthenticationStatus::Pending {
        return Err(StateError::InvalidValue {
            field: "new authentication status",
            reason: "must be pending",
        });
    }
    Ok(())
}

fn validate_new_task(record: &TaskRecord) -> Result<(), StateError> {
    validate_text("task kind", record.kind.clone())?;
    validate_initial_version_and_time(record.version, record.created_at, record.updated_at)?;
    if record.status != TaskStatus::Pending {
        return Err(StateError::InvalidValue {
            field: "new task status",
            reason: "must be pending",
        });
    }
    Ok(())
}

fn validate_initial_version_and_time(
    version: i64,
    created_at: TimestampMs,
    updated_at: TimestampMs,
) -> Result<(), StateError> {
    if version != 1 {
        return Err(StateError::InvalidValue {
            field: "new record version",
            reason: "must be one",
        });
    }
    if updated_at != created_at {
        return Err(StateError::InvalidValue {
            field: "new record updated timestamp",
            reason: "must equal its creation timestamp",
        });
    }
    Ok(())
}

fn valid_version(version: i64) -> Result<i64, StateError> {
    if version < 1 {
        return Err(invalid_stored("record version"));
    }
    Ok(version)
}

fn create_error(
    error: sqlx::Error,
    entity: &'static str,
    id: &str,
    parent: Option<(&'static str, &str)>,
) -> StateError {
    if let sqlx::Error::Database(details) = &error {
        let message = details.message();
        if message.contains("UNIQUE constraint failed") {
            return StateError::AlreadyExists {
                entity,
                id: id.to_owned(),
            };
        }
        if message.contains("FOREIGN KEY constraint failed") {
            let (entity, id) = parent.unwrap_or((entity, id));
            return StateError::ForeignKeyViolation {
                entity,
                id: id.to_owned(),
            };
        }
    }
    database("create durable record", error)
}

fn not_found(entity: &'static str, id: &str) -> StateError {
    StateError::NotFound {
        entity,
        id: id.to_owned(),
    }
}

fn conflict(entity: &'static str, id: &str, expected_version: i64) -> StateError {
    StateError::OptimisticConflict {
        entity,
        id: id.to_owned(),
        expected_version,
    }
}

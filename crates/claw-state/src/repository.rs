use claw_domain::SessionId;
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
#[cfg(test)]
use std::sync::LazyLock;
#[cfg(test)]
use std::sync::Mutex;

use crate::error::{database, database_code};
use crate::model::{finish_page, invalid_stored, validate_text};
use crate::store::{OperationalIdentity, validate_operational_schema};
use crate::{
    AuthenticationId, AuthenticationRecord, AuthenticationStatus, DeviceId, DeviceRecord, Page,
    PageCursor, PageRequest, SessionRecord, SessionStatus, StateError, TaskId, TaskRecord,
    TaskStatus, TimestampMs,
};

const APPLICATION_ID: i64 = 0x4754_4143;

type PoolManualTransaction =
    claw_sqlite_file_control::ManualTransaction<sqlx::pool::PoolConnection<sqlx::Sqlite>>;

struct RepositoryDeadline {
    deadline: std::time::Instant,
    cleanup_deadline: std::time::Instant,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    timeout_ms: u64,
}

impl RepositoryDeadline {
    fn new(identity: OperationalIdentity<'_>) -> Result<Self, StateError> {
        let timeout_ms = u64::try_from(identity.operation_timeout.as_millis()).unwrap_or(u64::MAX);
        let deadline = std::time::Instant::now()
            .checked_add(identity.operation_timeout)
            .ok_or(StateError::InvalidValue {
                field: "repository operation timeout",
                reason: "is too large for the monotonic clock",
            })?;
        let cleanup_deadline =
            deadline
                .checked_add(identity.cleanup_timeout)
                .ok_or(StateError::InvalidValue {
                    field: "repository cleanup timeout",
                    reason: "is too large for the monotonic clock",
                })?;
        Ok(Self {
            deadline,
            cleanup_deadline,
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            timeout_ms,
        })
    }

    fn timeout_error(&self, operation: &'static str) -> StateError {
        StateError::OperationTimedOut {
            operation,
            timeout_ms: self.timeout_ms,
        }
    }

    async fn run<T>(
        &self,
        operation: &'static str,
        future: impl std::future::Future<Output = Result<T, StateError>>,
    ) -> Result<T, StateError> {
        if self.cancelled.load(std::sync::atomic::Ordering::Acquire)
            || std::time::Instant::now() >= self.deadline
        {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(self.timeout_error(operation));
        }
        let timer = tokio::time::sleep_until(tokio::time::Instant::from_std(self.deadline));
        tokio::pin!(timer);
        tokio::pin!(future);
        let result = tokio::select! {
            biased;
            () = &mut timer => {
                self.cancelled
                    .store(true, std::sync::atomic::Ordering::Release);
                return Err(self.timeout_error(operation));
            }
            result = &mut future => result,
        };
        if std::time::Instant::now() >= self.deadline {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::Release);
            Err(self.timeout_error(operation))
        } else {
            result
        }
    }
}

async fn read_with_deadline<T>(
    identity: OperationalIdentity<'_>,
    operation: &'static str,
    future: impl std::future::Future<Output = Result<T, StateError>>,
) -> Result<T, StateError> {
    let timing = RepositoryDeadline::new(identity)?;
    timing.run(operation, future).await
}

struct VerifiedWriteTransaction {
    transaction: Option<PoolManualTransaction>,
    deadline: std::time::Instant,
    cleanup_deadline: std::time::Instant,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    restore_busy_timeout: std::time::Duration,
    timeout_ms: u64,
    #[cfg(test)]
    rollback_cleanup_test: Option<Arc<RollbackCleanupTestState>>,
    #[cfg(all(test, unix))]
    test_owner: String,
}

macro_rules! rollback_on_error {
    ($transaction:ident, $operation:expr, $result:expr) => {
        match $result {
            Ok(value) => value,
            Err(error) => {
                return Err($transaction.rollback_after_error($operation, error).await);
            }
        }
    };
}

#[derive(Clone)]
struct WriteDeadline {
    deadline: std::time::Instant,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    timeout_ms: u64,
}

impl WriteDeadline {
    async fn run<T, E>(
        &self,
        operation: &'static str,
        future: impl std::future::Future<Output = Result<T, E>>,
        map_error: impl FnOnce(E) -> StateError,
    ) -> Result<T, StateError> {
        let timeout = || StateError::OperationTimedOut {
            operation,
            timeout_ms: self.timeout_ms,
        };
        if self.cancelled.load(std::sync::atomic::Ordering::Acquire)
            || std::time::Instant::now() >= self.deadline
        {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(timeout());
        }
        let timer = tokio::time::sleep_until(tokio::time::Instant::from_std(self.deadline));
        tokio::pin!(timer);
        tokio::pin!(future);
        tokio::select! {
            biased;
            () = &mut timer => {
                self.cancelled
                    .store(true, std::sync::atomic::Ordering::Release);
                Err(timeout())
            }
            result = &mut future => result.map_err(map_error),
        }
    }
}

impl VerifiedWriteTransaction {
    fn executor(&mut self) -> &mut PoolManualTransaction {
        self.transaction
            .as_mut()
            .expect("verified write transaction remains owned")
    }

    fn ensure_within_deadline(&self, operation: &'static str) -> Result<(), StateError> {
        if self.cancelled.load(std::sync::atomic::Ordering::Acquire)
            || std::time::Instant::now() >= self.deadline
        {
            Err(StateError::OperationTimedOut {
                operation,
                timeout_ms: self.timeout_ms,
            })
        } else {
            Ok(())
        }
    }

    fn operation_deadline(&self) -> WriteDeadline {
        WriteDeadline {
            deadline: self.deadline,
            cancelled: Arc::clone(&self.cancelled),
            timeout_ms: self.timeout_ms,
        }
    }

    #[cfg(unix)]
    async fn main_database_has_moved(
        &mut self,
    ) -> Result<bool, claw_sqlite_file_control::FileControlError> {
        let moved = self.executor().main_database_has_moved().await?;
        #[cfg(test)]
        if moved {
            wait_at_identity_invalidation_test_barrier(&self.test_owner).await;
        }
        Ok(moved)
    }

    async fn commit(
        mut self,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Sqlite>, claw_sqlite_file_control::FileControlError>
    {
        let (connection, post_commit_owner) = self
            .transaction
            .take()
            .expect("verified write transaction remains owned")
            .commit_with_deadline(
                self.deadline,
                self.cleanup_deadline,
                Arc::clone(&self.cancelled),
                self.restore_busy_timeout,
                None,
            )
            .await?;
        post_commit_owner
            .shutdown()
            .map_err(claw_sqlite_file_control::FileControlError::CommittedWithCleanupFailure)?;
        Ok(connection)
    }

    async fn rollback_after_error(
        mut self,
        operation: &'static str,
        primary: StateError,
    ) -> StateError {
        #[cfg(test)]
        if self
            .rollback_cleanup_test
            .as_ref()
            .is_some_and(|state| (1..=3).contains(&state.mode))
        {
            return primary;
        }
        #[cfg(test)]
        self.rollback_cleanup_test.take();
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        let transaction = self
            .transaction
            .take()
            .expect("failed verified write transaction remains owned");
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(self.cleanup_deadline),
            transaction.rollback(),
        )
        .await
        {
            Ok(Ok(connection)) => {
                drop(connection);
                primary
            }
            Ok(Err(error)) => StateError::OperationCleanupFailed {
                operation,
                primary: Box::new(primary),
                cleanup: format!("repository rollback failed: {error}"),
            },
            Err(_) => StateError::OperationCleanupFailed {
                operation,
                primary: Box::new(primary),
                cleanup: "repository rollback exceeded its cleanup deadline".to_owned(),
            },
        }
    }
}

impl Drop for VerifiedWriteTransaction {
    fn drop(&mut self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        #[cfg(test)]
        if let Some(state) = self.rollback_cleanup_test.take()
            && let Some(transaction) = self.transaction.take()
        {
            match state.mode {
                1 => drop(transaction),
                2 => {
                    std::thread::spawn(move || drop(transaction))
                        .join()
                        .expect("no-runtime rollback cleanup thread joins");
                }
                3 => {
                    std::thread::spawn(move || drop(transaction));
                }
                4 => {
                    std::thread::spawn(move || {
                        state
                            .detached_started
                            .store(true, std::sync::atomic::Ordering::Release);
                        state.detached_entered.notify_one();
                        state.wait_for_detached_release();
                        drop(transaction);
                    });
                }
                _ => unreachable!("validated rollback cleanup test mode"),
            }
        }
    }
}

#[cfg(test)]
static WRITE_TEST_BARRIERS: LazyLock<Mutex<std::collections::HashMap<String, WriteTestBarrier>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static READ_TEST_BARRIERS: LazyLock<Mutex<std::collections::HashMap<String, WriteTestBarrier>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static COMMIT_TEST_TAMPERS: LazyLock<Mutex<std::collections::HashSet<String>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static COMMIT_TEST_BARRIERS: LazyLock<Mutex<std::collections::HashMap<String, WriteTestBarrier>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(all(test, unix))]
static IDENTITY_INVALIDATION_TEST_BARRIERS: LazyLock<
    Mutex<std::collections::HashMap<String, WriteTestBarrier>>,
> = LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static ROLLBACK_CLEANUP_TEST_STATES: LazyLock<
    Mutex<std::collections::HashMap<String, Arc<RollbackCleanupTestState>>>,
> = LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
struct WriteTestBarrier {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
struct RollbackCleanupTestState {
    mode: u8,
    claimed: std::sync::atomic::AtomicBool,
    claim_entered: tokio::sync::Notify,
    begin_released: std::sync::atomic::AtomicBool,
    begin_release: tokio::sync::Notify,
    detached_started: std::sync::atomic::AtomicBool,
    detached_entered: tokio::sync::Notify,
    detached_released: std::sync::atomic::AtomicBool,
    detached_release: std::sync::Condvar,
    detached_release_lock: std::sync::Mutex<()>,
}

#[cfg(test)]
impl RollbackCleanupTestState {
    fn release(&self) {
        if !self
            .begin_released
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.begin_release.notify_waiters();
        }
        if !self
            .detached_released
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.detached_release.notify_all();
        }
    }

    async fn wait_after_claim(&self) {
        if self.mode != 4 {
            return;
        }
        self.claim_entered.notify_one();
        while !self
            .begin_released
            .load(std::sync::atomic::Ordering::Acquire)
        {
            let released = self.begin_release.notified();
            tokio::pin!(released);
            if self
                .begin_released
                .load(std::sync::atomic::Ordering::Acquire)
            {
                break;
            }
            released.await;
        }
    }

    fn wait_for_detached_release(&self) {
        let mut locked = self
            .detached_release_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !self
            .detached_released
            .load(std::sync::atomic::Ordering::Acquire)
        {
            locked = self
                .detached_release
                .wait(locked)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

#[cfg(test)]
fn claim_rollback_cleanup_test(owner: &str) -> Option<Arc<RollbackCleanupTestState>> {
    let state = ROLLBACK_CLEANUP_TEST_STATES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(owner)?;
    state
        .claimed
        .store(true, std::sync::atomic::Ordering::Release);
    Some(state)
}

/// Transactional access to durable sessions.
pub struct SessionRepository<'store> {
    pool: &'store SqlitePool,
    owner: &'store str,
    identity: OperationalIdentity<'store>,
}

impl<'store> SessionRepository<'store> {
    pub(crate) const fn new(
        pool: &'store SqlitePool,
        owner: &'store str,
        identity: OperationalIdentity<'store>,
    ) -> Self {
        Self {
            pool,
            owner,
            identity,
        }
    }

    /// Creates one session.
    pub async fn create(&self, record: &SessionRecord) -> Result<(), StateError> {
        validate_new_session(record)?;
        let mut transaction =
            begin_verified_write(self.pool, self.owner, self.identity, "begin session create")
                .await?;
        let deadline = transaction.operation_deadline();
        rollback_on_error!(
            transaction,
            "session create",
            deadline
                .run(
                    "insert session",
                    sqlx::query(
                        "INSERT INTO sessions(id, status, created_at_ms, updated_at_ms, version)
                     VALUES (?, ?, ?, ?, ?)",
                    )
                    .bind(record.id.as_str())
                    .bind(record.status.as_db())
                    .bind(record.created_at.get())
                    .bind(record.updated_at.get())
                    .bind(record.version)
                    .execute(transaction.executor()),
                    |error| create_error(error, "session", record.id.as_str(), None),
                )
                .await
        );
        commit_verified(
            transaction,
            self.owner,
            self.identity,
            "commit session create",
        )
        .await?;
        Ok(())
    }

    /// Reads one session.
    pub async fn get(&self, id: &SessionId) -> Result<Option<SessionRecord>, StateError> {
        read_with_deadline(self.identity, "read session", async {
            let row = sqlx::query(
                "SELECT id, status, created_at_ms, updated_at_ms, version
                 FROM sessions WHERE id = ?",
            )
            .bind(id.as_str())
            .fetch_optional(self.pool)
            .await
            .map_err(|error| database("read session", error))?;
            row.map(session_from_row).transpose()
        })
        .await
    }

    /// Lists sessions in stable creation-time and identifier order.
    pub async fn list(&self, request: &PageRequest) -> Result<Page<SessionRecord>, StateError> {
        read_with_deadline(self.identity, "list sessions", async {
            let (after_time, after_id) = request.after_parts();
            let rows = sqlx::query(
                "SELECT id, status, created_at_ms, updated_at_ms, version
                 FROM sessions
                 WHERE (created_at_ms, id) > (?, ?)
                 ORDER BY created_at_ms, id
                 LIMIT ?",
            )
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
        })
        .await
    }

    /// Applies a valid lifecycle transition with optimistic concurrency.
    pub async fn update_status(
        &self,
        id: &SessionId,
        expected_version: i64,
        status: SessionStatus,
        updated_at: TimestampMs,
    ) -> Result<SessionRecord, StateError> {
        let operation = "begin session update";
        let timing = RepositoryDeadline::new(self.identity)?;
        let current = timing
            .run(operation, async {
                #[cfg(test)]
                wait_at_read_test_barrier(self.owner).await;
                self.get(id).await
            })
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
        let mut transaction = begin_verified_write_with_deadline(
            self.pool,
            self.owner,
            self.identity,
            operation,
            timing,
        )
        .await?;
        let deadline = transaction.operation_deadline();
        let row = rollback_on_error!(
            transaction,
            "session update",
            deadline
                .run(
                    "update session",
                    sqlx::query(
                        "UPDATE sessions
                     SET status = ?, updated_at_ms = ?, version = version + 1
                     WHERE id = ? AND version = ?
                     RETURNING id, status, created_at_ms, updated_at_ms, version",
                    )
                    .bind(status.as_db())
                    .bind(updated_at.get())
                    .bind(id.as_str())
                    .bind(expected_version)
                    .fetch_optional(transaction.executor()),
                    |error| database("update session", error),
                )
                .await
        );
        let record = rollback_on_error!(
            transaction,
            "session update",
            row.map(session_from_row).transpose().and_then(|record| {
                record.ok_or_else(|| conflict("session", id.as_str(), expected_version))
            })
        );
        commit_verified(
            transaction,
            self.owner,
            self.identity,
            "commit session update",
        )
        .await?;
        Ok(record)
    }
}

/// Transactional access to durable devices.
pub struct DeviceRepository<'store> {
    pool: &'store SqlitePool,
    owner: &'store str,
    identity: OperationalIdentity<'store>,
}

impl<'store> DeviceRepository<'store> {
    pub(crate) const fn new(
        pool: &'store SqlitePool,
        owner: &'store str,
        identity: OperationalIdentity<'store>,
    ) -> Self {
        Self {
            pool,
            owner,
            identity,
        }
    }

    /// Creates one device.
    pub async fn create(&self, record: &DeviceRecord) -> Result<(), StateError> {
        validate_new_device(record)?;
        let mut transaction =
            begin_verified_write(self.pool, self.owner, self.identity, "begin device create")
                .await?;
        rollback_on_error!(
            transaction,
            "device create",
            insert_device(&mut transaction, record).await
        );
        commit_verified(
            transaction,
            self.owner,
            self.identity,
            "commit device create",
        )
        .await?;
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
            self.identity,
            "begin device and authentication create",
        )
        .await?;
        rollback_on_error!(
            transaction,
            "device and authentication create",
            insert_device(&mut transaction, device).await
        );
        rollback_on_error!(
            transaction,
            "device and authentication create",
            insert_authentication(&mut transaction, authentication).await
        );
        commit_verified(
            transaction,
            self.owner,
            self.identity,
            "commit device and authentication create",
        )
        .await?;
        Ok(())
    }

    /// Reads one device.
    pub async fn get(&self, id: &DeviceId) -> Result<Option<DeviceRecord>, StateError> {
        read_with_deadline(self.identity, "read device", async {
            let row = sqlx::query(
                "SELECT id, display_name, created_at_ms, updated_at_ms, version
                 FROM devices WHERE id = ?",
            )
            .bind(id.as_str())
            .fetch_optional(self.pool)
            .await
            .map_err(|error| database("read device", error))?;
            row.map(device_from_row).transpose()
        })
        .await
    }

    /// Lists devices in stable creation-time and identifier order.
    pub async fn list(&self, request: &PageRequest) -> Result<Page<DeviceRecord>, StateError> {
        read_with_deadline(self.identity, "list devices", async {
            let (after_time, after_id) = request.after_parts();
            let rows = sqlx::query(
                "SELECT id, display_name, created_at_ms, updated_at_ms, version
                 FROM devices
                 WHERE (created_at_ms, id) > (?, ?)
                 ORDER BY created_at_ms, id
                 LIMIT ?",
            )
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
        })
        .await
    }

    /// Renames a device with optimistic concurrency.
    pub async fn rename(
        &self,
        id: &DeviceId,
        expected_version: i64,
        display_name: impl Into<String>,
        updated_at: TimestampMs,
    ) -> Result<DeviceRecord, StateError> {
        let operation = "begin device rename";
        let timing = RepositoryDeadline::new(self.identity)?;
        let display_name = validate_text("device display name", display_name.into())?;
        let current = timing
            .run(operation, self.get(id))
            .await?
            .ok_or_else(|| not_found("device", id.as_str()))?;
        if current.version != expected_version {
            return Err(conflict("device", id.as_str(), expected_version));
        }
        validate_update_time(current.updated_at, updated_at)?;
        let mut transaction = begin_verified_write_with_deadline(
            self.pool,
            self.owner,
            self.identity,
            operation,
            timing,
        )
        .await?;
        let deadline = transaction.operation_deadline();
        let row = rollback_on_error!(
            transaction,
            "device rename",
            deadline
                .run(
                    "rename device",
                    sqlx::query(
                        "UPDATE devices
                     SET display_name = ?, updated_at_ms = ?, version = version + 1
                     WHERE id = ? AND version = ?
                     RETURNING id, display_name, created_at_ms, updated_at_ms, version",
                    )
                    .bind(display_name)
                    .bind(updated_at.get())
                    .bind(id.as_str())
                    .bind(expected_version)
                    .fetch_optional(transaction.executor()),
                    |error| database("rename device", error),
                )
                .await
        );
        let record = rollback_on_error!(
            transaction,
            "device rename",
            row.map(device_from_row).transpose().and_then(|record| {
                record.ok_or_else(|| conflict("device", id.as_str(), expected_version))
            })
        );
        commit_verified(
            transaction,
            self.owner,
            self.identity,
            "commit device rename",
        )
        .await?;
        Ok(record)
    }
}

/// Transactional access to provider authentication records.
pub struct AuthenticationRepository<'store> {
    pool: &'store SqlitePool,
    owner: &'store str,
    identity: OperationalIdentity<'store>,
}

impl<'store> AuthenticationRepository<'store> {
    pub(crate) const fn new(
        pool: &'store SqlitePool,
        owner: &'store str,
        identity: OperationalIdentity<'store>,
    ) -> Self {
        Self {
            pool,
            owner,
            identity,
        }
    }

    /// Creates one authentication.
    pub async fn create(&self, record: &AuthenticationRecord) -> Result<(), StateError> {
        validate_new_authentication(record)?;
        let mut transaction = begin_verified_write(
            self.pool,
            self.owner,
            self.identity,
            "begin authentication create",
        )
        .await?;
        rollback_on_error!(
            transaction,
            "authentication create",
            insert_authentication(&mut transaction, record).await
        );
        commit_verified(
            transaction,
            self.owner,
            self.identity,
            "commit authentication create",
        )
        .await?;
        Ok(())
    }

    /// Reads one authentication.
    pub async fn get(
        &self,
        id: &AuthenticationId,
    ) -> Result<Option<AuthenticationRecord>, StateError> {
        read_with_deadline(self.identity, "read authentication", async {
            let row = sqlx::query(
                "SELECT id, device_id, provider, subject, status, created_at_ms, updated_at_ms, version
                 FROM authentication_records WHERE id = ?",
            )
            .bind(id.as_str())
            .fetch_optional(self.pool)
            .await
            .map_err(|error| database("read authentication", error))?;
            row.map(authentication_from_row).transpose()
        })
        .await
    }

    /// Lists a device's authentications in stable creation-time and identifier order.
    pub async fn list_for_device(
        &self,
        device_id: &DeviceId,
        request: &PageRequest,
    ) -> Result<Page<AuthenticationRecord>, StateError> {
        read_with_deadline(self.identity, "list authentications", async {
            let (after_time, after_id) = request.after_parts();
            let rows = sqlx::query(
                "SELECT id, device_id, provider, subject, status, created_at_ms, updated_at_ms, version
                 FROM authentication_records
                 WHERE device_id = ?
                   AND (created_at_ms, id) > (?, ?)
                 ORDER BY created_at_ms, id
                 LIMIT ?",
            )
            .bind(device_id.as_str())
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
        })
        .await
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
        let operation = "begin authentication update";
        let timing = RepositoryDeadline::new(self.identity)?;
        let subject = validate_auth_subject(status, subject)?;
        let current = timing
            .run(operation, self.get(id))
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
        let mut transaction = begin_verified_write_with_deadline(
            self.pool,
            self.owner,
            self.identity,
            operation,
            timing,
        )
        .await?;
        let deadline = transaction.operation_deadline();
        let row = rollback_on_error!(
            transaction,
            "authentication update",
            deadline
                .run(
                    "update authentication",
                    sqlx::query(
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
                    .fetch_optional(transaction.executor()),
                    |error| database("update authentication", error),
                )
                .await
        );
        let record = rollback_on_error!(
            transaction,
            "authentication update",
            row.map(authentication_from_row)
                .transpose()
                .and_then(|record| {
                    record.ok_or_else(|| conflict("authentication", id.as_str(), expected_version))
                })
        );
        commit_verified(
            transaction,
            self.owner,
            self.identity,
            "commit authentication update",
        )
        .await?;
        Ok(record)
    }
}

/// Transactional access to durable tasks.
pub struct TaskRepository<'store> {
    pool: &'store SqlitePool,
    owner: &'store str,
    identity: OperationalIdentity<'store>,
}

impl<'store> TaskRepository<'store> {
    pub(crate) const fn new(
        pool: &'store SqlitePool,
        owner: &'store str,
        identity: OperationalIdentity<'store>,
    ) -> Self {
        Self {
            pool,
            owner,
            identity,
        }
    }

    /// Creates one task.
    pub async fn create(&self, record: &TaskRecord) -> Result<(), StateError> {
        validate_new_task(record)?;
        let mut transaction =
            begin_verified_write(self.pool, self.owner, self.identity, "begin task create").await?;
        rollback_on_error!(
            transaction,
            "task create",
            insert_task(&mut transaction, record).await
        );
        commit_verified(transaction, self.owner, self.identity, "commit task create").await
    }

    /// Reads one task.
    pub async fn get(&self, id: &TaskId) -> Result<Option<TaskRecord>, StateError> {
        read_with_deadline(self.identity, "read task", async {
            let row = sqlx::query(
                "SELECT id, session_id, kind, payload, status, created_at_ms, updated_at_ms, version
                 FROM tasks WHERE id = ?",
            )
            .bind(id.as_str())
            .fetch_optional(self.pool)
            .await
            .map_err(|error| database("read task", error))?;
            row.map(task_from_row).transpose()
        })
        .await
    }

    /// Lists a session's tasks in stable creation-time and identifier order.
    pub async fn list_for_session(
        &self,
        session_id: &SessionId,
        request: &PageRequest,
    ) -> Result<Page<TaskRecord>, StateError> {
        read_with_deadline(self.identity, "list tasks", async {
            let (after_time, after_id) = request.after_parts();
            let rows = sqlx::query(
                "SELECT id, session_id, kind, payload, status, created_at_ms, updated_at_ms, version
                 FROM tasks
                 WHERE session_id = ?
                   AND (created_at_ms, id) > (?, ?)
                 ORDER BY created_at_ms, id
                 LIMIT ?",
            )
            .bind(session_id.as_str())
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
        })
        .await
    }

    /// Applies a valid lifecycle transition with optimistic concurrency.
    pub async fn update_status(
        &self,
        id: &TaskId,
        expected_version: i64,
        status: TaskStatus,
        updated_at: TimestampMs,
    ) -> Result<TaskRecord, StateError> {
        let operation = "begin task update";
        let timing = RepositoryDeadline::new(self.identity)?;
        let current = timing
            .run(operation, self.get(id))
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
        let mut transaction = begin_verified_write_with_deadline(
            self.pool,
            self.owner,
            self.identity,
            operation,
            timing,
        )
        .await?;
        let deadline = transaction.operation_deadline();
        let row = rollback_on_error!(
            transaction,
            "task update",
            deadline
                .run(
                    "update task",
                    sqlx::query(
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
                    .fetch_optional(transaction.executor()),
                    |error| database("update task", error),
                )
                .await
        );
        let record = rollback_on_error!(
            transaction,
            "task update",
            row.map(task_from_row).transpose().and_then(|record| {
                record.ok_or_else(|| conflict("task", id.as_str(), expected_version))
            })
        );
        commit_verified(transaction, self.owner, self.identity, "commit task update").await?;
        Ok(record)
    }
}

async fn begin_verified_write(
    pool: &SqlitePool,
    owner: &str,
    identity: OperationalIdentity<'_>,
    operation: &'static str,
) -> Result<VerifiedWriteTransaction, StateError> {
    let deadline = RepositoryDeadline::new(identity)?;
    begin_verified_write_with_deadline(pool, owner, identity, operation, deadline).await
}

async fn begin_verified_write_with_deadline(
    pool: &SqlitePool,
    owner: &str,
    identity: OperationalIdentity<'_>,
    operation: &'static str,
    timing: RepositoryDeadline,
) -> Result<VerifiedWriteTransaction, StateError> {
    let connection = timing
        .run(operation, async {
            pool.acquire()
                .await
                .map_err(|error| database(operation, error))
        })
        .await?;
    let RepositoryDeadline {
        deadline,
        cleanup_deadline,
        cancelled,
        timeout_ms,
    } = timing;
    let begin_timeout = identity
        .busy_timeout
        .min(deadline.saturating_duration_since(std::time::Instant::now()));
    let active =
        match claw_sqlite_file_control::begin_manual_pool_transaction_with_restore_deadline(
            connection,
            deadline,
            begin_timeout,
            identity.busy_timeout,
            Some(Arc::clone(&cancelled)),
        )
        .await
        {
            Ok(active) => active,
            Err(error) => {
                let begin_operation = "lock and verify application writer";
                if std::time::Instant::now() >= deadline || error.code() == Some(9) {
                    return Err(StateError::OperationTimedOut {
                        operation,
                        timeout_ms,
                    });
                }
                return Err(error.code().map_or_else(
                    || database(begin_operation, sqlx::Error::Protocol(error.to_string())),
                    |code| database_code(begin_operation, code, error.to_string()),
                ));
            }
        };
    let mut transaction = VerifiedWriteTransaction {
        transaction: Some(active),
        deadline,
        cleanup_deadline,
        cancelled,
        restore_busy_timeout: identity.busy_timeout,
        timeout_ms,
        #[cfg(test)]
        rollback_cleanup_test: claim_rollback_cleanup_test(owner),
        #[cfg(all(test, unix))]
        test_owner: owner.to_owned(),
    };
    #[cfg(test)]
    if let Some(state) = transaction.rollback_cleanup_test.as_ref() {
        state.wait_after_claim().await;
    }
    let deadline = transaction.operation_deadline();
    let ownership = rollback_on_error!(
        transaction,
        operation,
        deadline
            .run(
                "lock and verify application writer",
                sqlx::query(
                    "UPDATE claw_writer_lock
                 SET owner = owner
                 WHERE singleton = 1 AND owner = ?",
                )
                .bind(owner)
                .execute(transaction.executor()),
                |error| database("lock and verify application writer", error),
            )
            .await
    );
    if ownership.rows_affected() != 1 {
        let error = StateError::InvalidMigrationHistory {
            reason: "application writer ownership changed before repository write".to_owned(),
        };
        return Err(transaction.rollback_after_error(operation, error).await);
    }
    let deadline = transaction.operation_deadline();
    let application_id = rollback_on_error!(
        transaction,
        operation,
        deadline
            .run(
                "verify repository application id",
                sqlx::query_scalar::<_, i64>("PRAGMA application_id")
                    .fetch_one(transaction.executor()),
                |error| database("verify repository application id", error),
            )
            .await
    );
    if application_id != APPLICATION_ID {
        let error = StateError::InvalidValue {
            field: "SQLite application id",
            reason: "database ownership changed before repository write",
        };
        return Err(transaction.rollback_after_error(operation, error).await);
    }
    let deadline = transaction.operation_deadline();
    rollback_on_error!(
        transaction,
        operation,
        deadline
            .run(
                "validate repository schema",
                validate_operational_schema(transaction.executor()),
                std::convert::identity,
            )
            .await
    );
    rollback_on_error!(transaction, operation, identity.verify());
    rollback_on_error!(
        transaction,
        operation,
        transaction.ensure_within_deadline(operation)
    );
    #[cfg(test)]
    wait_at_write_test_barrier(owner).await;
    Ok(transaction)
}

#[cfg(test)]
async fn wait_at_read_test_barrier(owner: &str) {
    let barrier = READ_TEST_BARRIERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(owner)
        .map(|configured| {
            (
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        release.notified().await;
        READ_TEST_BARRIERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(owner);
    }
}

#[cfg(test)]
async fn wait_at_write_test_barrier(owner: &str) {
    let barrier = WRITE_TEST_BARRIERS
        .lock()
        .expect("write test barriers lock poisoned")
        .get(owner)
        .map(|configured| {
            (
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        release.notified().await;
        WRITE_TEST_BARRIERS
            .lock()
            .expect("write test barriers lock poisoned")
            .remove(owner);
    }
}

#[cfg(test)]
async fn wait_at_commit_test_barrier(owner: &str) {
    let barrier = COMMIT_TEST_BARRIERS
        .lock()
        .expect("commit test barriers lock poisoned")
        .get(owner)
        .map(|configured| {
            (
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        release.notified().await;
        COMMIT_TEST_BARRIERS
            .lock()
            .expect("commit test barriers lock poisoned")
            .remove(owner);
    }
}

#[cfg(all(test, unix))]
async fn wait_at_identity_invalidation_test_barrier(owner: &str) {
    let barrier = IDENTITY_INVALIDATION_TEST_BARRIERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(owner)
        .map(|configured| {
            (
                Arc::clone(&configured.entered),
                Arc::clone(&configured.release),
            )
        });
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        release.notified().await;
        IDENTITY_INVALIDATION_TEST_BARRIERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(owner);
    }
}

async fn commit_verified(
    mut transaction: VerifiedWriteTransaction,
    owner: &str,
    identity: OperationalIdentity<'_>,
    operation: &'static str,
) -> Result<(), StateError> {
    rollback_on_error!(
        transaction,
        operation,
        transaction.ensure_within_deadline(operation)
    );
    #[cfg(test)]
    rollback_on_error!(
        transaction,
        operation,
        apply_commit_test_tamper(&mut transaction, owner).await
    );
    let deadline_guard = transaction.operation_deadline();
    let persisted_owner = rollback_on_error!(
        transaction,
        operation,
        deadline_guard
            .run(
                "reverify repository writer owner",
                sqlx::query_scalar::<_, String>(
                    "SELECT owner FROM claw_writer_lock WHERE singleton = 1",
                )
                .fetch_optional(transaction.executor()),
                |error| database("reverify repository writer owner", error),
            )
            .await
    );
    if persisted_owner.as_deref() != Some(owner) {
        let error = StateError::InvalidMigrationHistory {
            reason: "application writer ownership changed before repository commit".to_owned(),
        };
        return Err(transaction.rollback_after_error(operation, error).await);
    }
    let deadline_guard = transaction.operation_deadline();
    let application_id = rollback_on_error!(
        transaction,
        operation,
        deadline_guard
            .run(
                "reverify repository application id",
                sqlx::query_scalar::<_, i64>("PRAGMA application_id")
                    .fetch_one(transaction.executor()),
                |error| database("reverify repository application id", error),
            )
            .await
    );
    if application_id != APPLICATION_ID {
        let error = StateError::InvalidValue {
            field: "SQLite application id",
            reason: "database ownership changed before repository commit",
        };
        return Err(transaction.rollback_after_error(operation, error).await);
    }
    let deadline_guard = transaction.operation_deadline();
    rollback_on_error!(
        transaction,
        operation,
        deadline_guard
            .run(
                "revalidate repository schema",
                validate_operational_schema(transaction.executor()),
                std::convert::identity,
            )
            .await
    );
    rollback_on_error!(transaction, operation, identity.verify());
    #[cfg(unix)]
    {
        let deadline_guard = transaction.operation_deadline();
        let moved = rollback_on_error!(
            transaction,
            operation,
            deadline_guard
                .run(operation, transaction.main_database_has_moved(), |error| {
                    database(operation, sqlx::Error::Protocol(error.to_string()))
                })
                .await
        );
        if moved {
            let error = database(
                operation,
                sqlx::Error::Protocol(
                    "SQLite main database identity changed before commit".to_owned(),
                ),
            );
            return Err(transaction.rollback_after_error(operation, error).await);
        }
    }
    rollback_on_error!(
        transaction,
        operation,
        transaction.ensure_within_deadline(operation)
    );
    #[cfg(test)]
    wait_at_commit_test_barrier(owner).await;
    rollback_on_error!(
        transaction,
        operation,
        transaction.ensure_within_deadline(operation)
    );
    let deadline = transaction.deadline;
    let timeout_ms = transaction.timeout_ms;
    transaction
        .commit()
        .await
        .map(drop)
        .map_err(|error| match error {
            claw_sqlite_file_control::FileControlError::CommittedAfterDeadline(cleanup) => {
                StateError::CommittedAfterDeadline { operation, cleanup }
            }
            claw_sqlite_file_control::FileControlError::CommittedWithCleanupFailure(cleanup) => {
                StateError::CommittedWithCleanupFailure { operation, cleanup }
            }
            claw_sqlite_file_control::FileControlError::CommitOutcomeUncertain(code, message) => {
                StateError::CommitOutcomeUncertain {
                    operation,
                    code,
                    message,
                }
            }
            other if other.code() == Some(9) && std::time::Instant::now() >= deadline => {
                StateError::OperationTimedOut {
                    operation,
                    timeout_ms,
                }
            }
            other => other.code().map_or_else(
                || database(operation, sqlx::Error::Protocol(other.to_string())),
                |code| database_code(operation, code, other.to_string()),
            ),
        })
}

#[cfg(test)]
async fn apply_commit_test_tamper(
    transaction: &mut VerifiedWriteTransaction,
    owner: &str,
) -> Result<(), StateError> {
    let tamper = COMMIT_TEST_TAMPERS
        .lock()
        .expect("commit test tampers lock poisoned")
        .remove(owner);
    if tamper {
        for statement in [
            "UPDATE claw_writer_lock
             SET owner = 'commit-boundary-attacker'
             WHERE singleton = 1",
            "PRAGMA application_id = 0",
            "CREATE TABLE commit_boundary_rogue(value TEXT) STRICT",
        ] {
            sqlx::raw_sql(statement)
                .execute(transaction.executor())
                .await
                .map_err(|error| database("apply commit-boundary test tamper", error))?;
        }
    }
    Ok(())
}

async fn insert_device(
    transaction: &mut VerifiedWriteTransaction,
    record: &DeviceRecord,
) -> Result<(), StateError> {
    let deadline = transaction.operation_deadline();
    deadline
        .run(
            "insert device",
            sqlx::query(
                "INSERT INTO devices(id, display_name, created_at_ms, updated_at_ms, version)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(record.id.as_str())
            .bind(&record.display_name)
            .bind(record.created_at.get())
            .bind(record.updated_at.get())
            .bind(record.version)
            .execute(transaction.executor()),
            |error| create_error(error, "device", record.id.as_str(), None),
        )
        .await?;
    Ok(())
}

async fn insert_authentication(
    transaction: &mut VerifiedWriteTransaction,
    record: &AuthenticationRecord,
) -> Result<(), StateError> {
    let deadline = transaction.operation_deadline();
    deadline
        .run(
            "insert authentication",
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
            .execute(transaction.executor()),
            |error| {
                create_error(
                    error,
                    "authentication",
                    record.id.as_str(),
                    Some(("device", record.device_id.as_str())),
                )
            },
        )
        .await?;
    Ok(())
}

async fn insert_task(
    transaction: &mut VerifiedWriteTransaction,
    record: &TaskRecord,
) -> Result<(), StateError> {
    let deadline = transaction.operation_deadline();
    let result = deadline
        .run(
            "insert task",
            sqlx::query(
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
            .execute(transaction.executor()),
            |error| {
                create_error(
                    error,
                    "task",
                    record.id.as_str(),
                    Some(("session", record.session_id.as_str())),
                )
            },
        )
        .await?;
    if result.rows_affected() == 0 {
        let deadline = transaction.operation_deadline();
        let status = deadline
            .run(
                "inspect task parent session",
                sqlx::query_scalar::<_, String>("SELECT status FROM sessions WHERE id = ?")
                    .bind(record.session_id.as_str())
                    .fetch_optional(transaction.executor()),
                |error| database("inspect task parent session", error),
            )
            .await?;
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

fn stored_session_id(raw: String, field: &'static str) -> Result<SessionId, StateError> {
    let id = SessionId::new(raw.clone()).map_err(|_| invalid_stored(field))?;
    if id.as_str() == raw {
        Ok(id)
    } else {
        Err(invalid_stored(field))
    }
}

fn stored_device_id(raw: String, field: &'static str) -> Result<DeviceId, StateError> {
    let id = DeviceId::new(raw.clone()).map_err(|_| invalid_stored(field))?;
    if id.as_str() == raw {
        Ok(id)
    } else {
        Err(invalid_stored(field))
    }
}

fn stored_authentication_id(
    raw: String,
    field: &'static str,
) -> Result<AuthenticationId, StateError> {
    let id = AuthenticationId::new(raw.clone()).map_err(|_| invalid_stored(field))?;
    if id.as_str() == raw {
        Ok(id)
    } else {
        Err(invalid_stored(field))
    }
}

fn stored_task_id(raw: String, field: &'static str) -> Result<TaskId, StateError> {
    let id = TaskId::new(raw.clone()).map_err(|_| invalid_stored(field))?;
    if id.as_str() == raw {
        Ok(id)
    } else {
        Err(invalid_stored(field))
    }
}

fn session_from_row(row: sqlx::sqlite::SqliteRow) -> Result<SessionRecord, StateError> {
    let created_at = TimestampMs::new(
        row.try_get("created_at_ms")
            .map_err(|_| invalid_stored("session created timestamp"))?,
    )?;
    let updated_at = TimestampMs::new(
        row.try_get("updated_at_ms")
            .map_err(|_| invalid_stored("session updated timestamp"))?,
    )?;
    validate_update_time(created_at, updated_at)?;
    Ok(SessionRecord {
        id: stored_session_id(
            row.try_get::<String, _>("id")
                .map_err(|_| invalid_stored("session id"))?,
            "session id",
        )?,
        status: SessionStatus::from_db(
            row.try_get("status")
                .map_err(|_| invalid_stored("session status"))?,
        )?,
        created_at,
        updated_at,
        version: valid_version(
            row.try_get("version")
                .map_err(|_| invalid_stored("session version"))?,
        )?,
    })
}

fn device_from_row(row: sqlx::sqlite::SqliteRow) -> Result<DeviceRecord, StateError> {
    let created_at = TimestampMs::new(
        row.try_get("created_at_ms")
            .map_err(|_| invalid_stored("device created timestamp"))?,
    )?;
    let updated_at = TimestampMs::new(
        row.try_get("updated_at_ms")
            .map_err(|_| invalid_stored("device updated timestamp"))?,
    )?;
    validate_update_time(created_at, updated_at)?;
    Ok(DeviceRecord {
        id: stored_device_id(
            row.try_get::<String, _>("id")
                .map_err(|_| invalid_stored("device id"))?,
            "device id",
        )?,
        display_name: validate_text(
            "stored device display name",
            row.try_get("display_name")
                .map_err(|_| invalid_stored("device display name"))?,
        )?,
        created_at,
        updated_at,
        version: valid_version(
            row.try_get("version")
                .map_err(|_| invalid_stored("device version"))?,
        )?,
    })
}

fn authentication_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<AuthenticationRecord, StateError> {
    let status = AuthenticationStatus::from_db(
        row.try_get("status")
            .map_err(|_| invalid_stored("authentication status"))?,
    )?;
    let subject = validate_auth_subject(
        status,
        row.try_get("subject")
            .map_err(|_| invalid_stored("authentication subject"))?,
    )?;
    let created_at = TimestampMs::new(
        row.try_get("created_at_ms")
            .map_err(|_| invalid_stored("authentication created timestamp"))?,
    )?;
    let updated_at = TimestampMs::new(
        row.try_get("updated_at_ms")
            .map_err(|_| invalid_stored("authentication updated timestamp"))?,
    )?;
    validate_update_time(created_at, updated_at)?;
    Ok(AuthenticationRecord {
        id: stored_authentication_id(
            row.try_get::<String, _>("id")
                .map_err(|_| invalid_stored("authentication id"))?,
            "authentication id",
        )?,
        device_id: stored_device_id(
            row.try_get::<String, _>("device_id")
                .map_err(|_| invalid_stored("authentication device id"))?,
            "authentication device id",
        )?,
        provider: validate_text(
            "stored authentication provider",
            row.try_get("provider")
                .map_err(|_| invalid_stored("authentication provider"))?,
        )?,
        subject,
        status,
        created_at,
        updated_at,
        version: valid_version(
            row.try_get("version")
                .map_err(|_| invalid_stored("authentication version"))?,
        )?,
    })
}

fn task_from_row(row: sqlx::sqlite::SqliteRow) -> Result<TaskRecord, StateError> {
    let created_at = TimestampMs::new(
        row.try_get("created_at_ms")
            .map_err(|_| invalid_stored("task created timestamp"))?,
    )?;
    let updated_at = TimestampMs::new(
        row.try_get("updated_at_ms")
            .map_err(|_| invalid_stored("task updated timestamp"))?,
    )?;
    validate_update_time(created_at, updated_at)?;
    Ok(TaskRecord {
        id: stored_task_id(
            row.try_get::<String, _>("id")
                .map_err(|_| invalid_stored("task id"))?,
            "task id",
        )?,
        session_id: stored_session_id(
            row.try_get::<String, _>("session_id")
                .map_err(|_| invalid_stored("task session id"))?,
            "task session id",
        )?,
        kind: validate_text(
            "stored task kind",
            row.try_get("kind")
                .map_err(|_| invalid_stored("task kind"))?,
        )?,
        payload: row
            .try_get("payload")
            .map_err(|_| invalid_stored("task payload"))?,
        status: TaskStatus::from_db(
            row.try_get("status")
                .map_err(|_| invalid_stored("task status"))?,
        )?,
        created_at,
        updated_at,
        version: valid_version(
            row.try_get("version")
                .map_err(|_| invalid_stored("task version"))?,
        )?,
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

#[cfg(test)]
mod deadline_tests {
    use super::WriteDeadline;
    use crate::StateError;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[tokio::test]
    async fn expired_write_deadline_never_polls_statement_future() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let deadline = WriteDeadline {
            deadline: std::time::Instant::now(),
            cancelled: Arc::clone(&cancelled),
            timeout_ms: 1,
        };
        let polled = Arc::new(AtomicBool::new(false));
        let future_polled = Arc::clone(&polled);
        let future = std::future::poll_fn(move |_| {
            future_polled.store(true, Ordering::Release);
            std::task::Poll::Ready(Ok::<(), ()>(()))
        });
        assert_eq!(
            deadline
                .run("expired test write", future, |_| unreachable!())
                .await,
            Err(StateError::OperationTimedOut {
                operation: "expired test write",
                timeout_ms: 1,
            })
        );
        assert!(!polled.load(Ordering::Acquire));
        assert!(cancelled.load(Ordering::Acquire));
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::{
        Arc, COMMIT_TEST_BARRIERS, READ_TEST_BARRIERS, ROLLBACK_CLEANUP_TEST_STATES,
        RollbackCleanupTestState, WRITE_TEST_BARRIERS, WriteTestBarrier,
    };
    #[cfg(unix)]
    use super::{COMMIT_TEST_TAMPERS, IDENTITY_INVALIDATION_TEST_BARRIERS};

    pub(crate) struct RollbackCleanupTestRegistration {
        owner: String,
        state: Arc<RollbackCleanupTestState>,
    }

    impl RollbackCleanupTestRegistration {
        pub(crate) fn assert_claimed(&self) {
            assert!(
                self.state
                    .claimed
                    .load(std::sync::atomic::Ordering::Acquire),
                "rollback cleanup disruption was not consumed"
            );
        }

        pub(crate) async fn wait_until_claimed(&self) {
            while !self
                .state
                .claimed
                .load(std::sync::atomic::Ordering::Acquire)
            {
                let claimed = self.state.claim_entered.notified();
                tokio::pin!(claimed);
                if self
                    .state
                    .claimed
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    break;
                }
                claimed.await;
            }
        }

        pub(crate) fn allow_operation(&self) {
            if !self
                .state
                .begin_released
                .swap(true, std::sync::atomic::Ordering::AcqRel)
            {
                self.state.begin_release.notify_waiters();
            }
        }

        pub(crate) async fn wait_until_detached(&self) {
            while !self
                .state
                .detached_started
                .load(std::sync::atomic::Ordering::Acquire)
            {
                let detached = self.state.detached_entered.notified();
                tokio::pin!(detached);
                if self
                    .state
                    .detached_started
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    break;
                }
                detached.await;
            }
        }
    }

    impl Drop for RollbackCleanupTestRegistration {
        fn drop(&mut self) {
            let mut states = ROLLBACK_CLEANUP_TEST_STATES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if states
                .get(&self.owner)
                .is_some_and(|queued| Arc::ptr_eq(queued, &self.state))
            {
                states.remove(&self.owner);
            }
            drop(states);
            self.state.release();
        }
    }

    fn register_rollback_cleanup_test(
        owner: &str,
        mode: u8,
    ) -> Result<RollbackCleanupTestRegistration, &'static str> {
        assert!((1..=4).contains(&mode));
        let mut states = ROLLBACK_CLEANUP_TEST_STATES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if states.contains_key(owner) {
            return Err("rollback cleanup disruption is already queued");
        }
        let state = Arc::new(RollbackCleanupTestState {
            mode,
            claimed: std::sync::atomic::AtomicBool::new(false),
            claim_entered: tokio::sync::Notify::new(),
            begin_released: std::sync::atomic::AtomicBool::new(mode != 4),
            begin_release: tokio::sync::Notify::new(),
            detached_started: std::sync::atomic::AtomicBool::new(false),
            detached_entered: tokio::sync::Notify::new(),
            detached_released: std::sync::atomic::AtomicBool::new(false),
            detached_release: std::sync::Condvar::new(),
            detached_release_lock: std::sync::Mutex::new(()),
        });
        states.insert(owner.to_owned(), Arc::clone(&state));
        Ok(RollbackCleanupTestRegistration {
            owner: owner.to_owned(),
            state,
        })
    }

    pub(crate) fn set_write_barrier(
        owner: &str,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        WRITE_TEST_BARRIERS
            .lock()
            .expect("write test barriers lock poisoned")
            .insert(
                owner.to_owned(),
                WriteTestBarrier {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                },
            );
        (entered, release)
    }

    pub(crate) fn set_read_barrier(
        owner: &str,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        READ_TEST_BARRIERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                owner.to_owned(),
                WriteTestBarrier {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                },
            );
        (entered, release)
    }

    #[cfg(unix)]
    pub(crate) fn set_commit_tamper(owner: &str) {
        COMMIT_TEST_TAMPERS
            .lock()
            .expect("commit test tampers lock poisoned")
            .insert(owner.to_owned());
    }

    pub(crate) fn set_commit_barrier(
        owner: &str,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        COMMIT_TEST_BARRIERS
            .lock()
            .expect("commit test barriers lock poisoned")
            .insert(
                owner.to_owned(),
                WriteTestBarrier {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                },
            );
        (entered, release)
    }

    #[cfg(unix)]
    pub(crate) fn set_identity_invalidation_barrier(
        owner: &str,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        IDENTITY_INVALIDATION_TEST_BARRIERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                owner.to_owned(),
                WriteTestBarrier {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                },
            );
        (entered, release)
    }

    pub(crate) fn disrupt_next_rollback_cleanup(
        owner: &str,
        mode: u8,
    ) -> RollbackCleanupTestRegistration {
        register_rollback_cleanup_test(owner, mode)
            .expect("rollback cleanup disruption must be unique")
    }

    pub(crate) fn hold_next_detached_rollback(
        owner: &str,
    ) -> Result<RollbackCleanupTestRegistration, &'static str> {
        register_rollback_cleanup_test(owner, 4)
    }

    pub(crate) fn pending_rollback_cleanup_tests() -> usize {
        ROLLBACK_CLEANUP_TEST_STATES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    pub(crate) async fn drop_transaction_without_runtime(pool: &sqlx::SqlitePool) {
        let connection = pool
            .acquire()
            .await
            .expect("acquire no-runtime rollback connection");
        let transaction = claw_sqlite_file_control::begin_manual_pool_transaction(
            connection,
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("begin no-runtime rollback transaction");
        std::thread::spawn(move || drop(transaction));
    }
}

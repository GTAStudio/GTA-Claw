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
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqlitePoolOptions,
    SqliteSynchronous,
};
use sqlx::{Connection, Row, SqliteConnection, SqlitePool};

use crate::error::{database, database_code};
#[cfg(target_os = "linux")]
use crate::linux_protected::{LinuxProtectedSpec, ProtectedNamespace};
#[cfg(target_os = "linux")]
use crate::protected_catalog::{
    self, RecoveredSnapshot, SelectorCell, SlotObservation, SnapshotMetadata,
};
use crate::protected_layout::DATABASE_NAME as LINUX_PROTECTED_DATABASE_NAME;
use crate::{
    AuthenticationRepository, DeviceRepository, SessionRepository, StateError, TaskRepository,
};

const APPLICATION_ID: i64 = 0x4754_4143;
type PoolTransactionConnection =
    claw_sqlite_file_control::ManualTransaction<sqlx::pool::PoolConnection<sqlx::Sqlite>>;
const LATEST_SCHEMA_VERSION: i64 = 2;
const SNAPSHOT_PROVENANCE_OWNER: &str = "gta-claw-standalone-snapshot-v1";
#[cfg(unix)]
const UNIX_LOCK_IDENTITY_XATTR: &str = "user.gta-claw.writer-lock-path";
#[cfg(unix)]
const UNIX_BACKUP_SEAL_XATTR: &str = "user.gta-claw.backup-seal-id";
#[cfg(unix)]
const UNIX_SIDECAR_GENERATION_XATTR: &str = "user.gta-claw.sidecar-generation";
#[cfg(unix)]
const UNIX_SNAPSHOT_STAGING_XATTR: &str = "user.gta-claw.snapshot-staging";
const SNAPSHOT_STAGING_MARKER: &[u8] = b"gta-claw-staging-bound-v1";
const BACKUP_SEAL_MAGIC: &str = "gta-claw-backup-seal-v1";
const MAX_CONFIGURED_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_AUTHENTICATED_SNAPSHOT_BYTES: u64 = 67_108_864;
const SNAPSHOT_MEMORY_UNIT_BYTES: u64 = 1_048_576;
const SNAPSHOT_OPERATION_PEAK_UNITS: u32 =
    ((MAX_AUTHENTICATED_SNAPSHOT_BYTES / SNAPSHOT_MEMORY_UNIT_BYTES) * 3) as u32;
const PROCESS_SNAPSHOT_PEAK_UNITS: usize = SNAPSHOT_OPERATION_PEAK_UNITS as usize * 2;
static BACKUP_CLEANUP_ADMISSION: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);
static RESTORE_CLEANUP_ADMISSION: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(16);
static STATE_OPEN_ADMISSION: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(STATE_OPEN_ADMISSION_LIMIT);
static OPEN_TRANSACTION_ADMISSION: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(OPEN_TRANSACTION_ADMISSION_LIMIT);
static SNAPSHOT_MEMORY_ADMISSION: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(PROCESS_SNAPSHOT_PEAK_UNITS);
#[cfg(test)]
static TEST_OPEN_CONCURRENCY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

#[derive(Clone)]
enum StoreProfile {
    PortablePrivate,
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    LinuxProtected(LinuxProtectedSpec),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConfiguredStoreProfile {
    PortablePrivate,
    LinuxProtected { namespace: PathBuf },
}

#[derive(Clone)]
enum ActiveStoreProfile {
    PortablePrivate,
    #[cfg(target_os = "linux")]
    LinuxProtected(Arc<ProtectedNamespace>),
}

impl ActiveStoreProfile {
    const fn is_protected(&self) -> bool {
        match self {
            Self::PortablePrivate => false,
            #[cfg(target_os = "linux")]
            Self::LinuxProtected(_) => true,
        }
    }

    fn writer_owner(&self) -> Result<String, StateError> {
        match self {
            Self::PortablePrivate => writer_owner(),
            #[cfg(target_os = "linux")]
            Self::LinuxProtected(namespace) => Ok(namespace.writer_owner()),
        }
    }

    fn verify_filesystem(
        &self,
        database_parent: (&Path, &File),
        database: (&Path, &File),
        lock: (&Path, &File),
        lock_identity: Option<&[u8]>,
        validate_sidecars: bool,
    ) -> Result<(), StateError> {
        let (database_parent_path, database_parent) = database_parent;
        let (database_path, database_file) = database;
        let (lock_path, lock_file) = lock;
        match self {
            Self::PortablePrivate => {
                verify_directory_path_identity(database_parent_path, database_parent)
                    .and_then(|()| verify_path_identity(database_path, database_file))
                    .and_then(|()| verify_path_identity(lock_path, lock_file))
                    .and_then(|()| {
                        verify_store_lock_binding(
                            database_path,
                            database_file,
                            lock_path,
                            lock_file,
                            lock_identity,
                        )
                    })
                    .and_then(|()| {
                        if validate_sidecars {
                            validate_sqlite_sidecars(database_path, lock_identity)
                        } else {
                            Ok(())
                        }
                    })
            }
            #[cfg(target_os = "linux")]
            Self::LinuxProtected(namespace) => namespace.verify(),
        }
    }

    fn secure_sidecars(
        &self,
        database_path: &Path,
        lock_identity: Option<&[u8]>,
    ) -> Result<(), StateError> {
        match self {
            Self::PortablePrivate => secure_sqlite_sidecars(database_path, lock_identity),
            #[cfg(target_os = "linux")]
            Self::LinuxProtected(namespace) => namespace.verify(),
        }
    }

    async fn verify_connection(
        &self,
        connection: &mut SqliteConnection,
    ) -> Result<(), sqlx::Error> {
        verify_sqlite_connection_identity(connection).await?;
        #[cfg(target_os = "linux")]
        if let Self::LinuxProtected(namespace) = self {
            namespace
                .verify()
                .map_err(|error| sqlx::Error::Configuration(Box::new(error)))?;
            let vfs = claw_sqlite_file_control::main_database_vfs_name(connection)
                .await
                .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
            if vfs != "unix-excl" {
                return Err(sqlx::Error::Protocol(format!(
                    "LinuxProtected requires exact unix-excl VFS, found {vfs}"
                )));
            }
            #[cfg(test)]
            if FAIL_PROTECTED_PERSIST_WAL.swap(false, std::sync::atomic::Ordering::AcqRel) {
                return Err(sqlx::Error::Protocol(
                    "injected LinuxProtected PERSIST_WAL verification failure".to_owned(),
                ));
            }
            claw_sqlite_file_control::enable_persistent_wal(connection)
                .await
                .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
            let locking_mode = sqlx::query_scalar::<_, String>("PRAGMA locking_mode")
                .fetch_one(&mut *connection)
                .await?;
            if locking_mode != "exclusive" {
                return Err(sqlx::Error::Protocol(format!(
                    "LinuxProtected requires exclusive locking mode, found {locking_mode}"
                )));
            }
            let journal_mode = sqlx::query_scalar::<_, String>("PRAGMA journal_mode")
                .fetch_one(&mut *connection)
                .await?;
            if journal_mode != "wal" {
                return Err(sqlx::Error::Protocol(format!(
                    "LinuxProtected requires WAL journal mode, found {journal_mode}"
                )));
            }
            namespace
                .verify()
                .map_err(|error| sqlx::Error::Configuration(Box::new(error)))?;
        }
        Ok(())
    }

    async fn install_commit_guard(
        &self,
        connection: &mut SqliteConnection,
        database_parent: (&Path, &File),
        database: (&Path, &File),
        lock: (&Path, &File),
        expected_identity: Option<&[u8]>,
        writer_generation: (Arc<AtomicU64>, u64),
    ) -> Result<(), sqlx::Error> {
        match self {
            Self::PortablePrivate => {
                install_store_commit_guard(
                    connection,
                    database_parent,
                    database,
                    lock,
                    expected_identity,
                    writer_generation,
                )
                .await
            }
            #[cfg(target_os = "linux")]
            Self::LinuxProtected(_) => {
                let _ = (
                    database_parent,
                    database,
                    lock,
                    expected_identity,
                    writer_generation,
                );
                claw_sqlite_file_control::install_moved_commit_guard(connection)
                    .await
                    .map_err(|error| sqlx::Error::Protocol(error.to_string()))
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn protected_namespace(&self) -> Option<&Arc<ProtectedNamespace>> {
        match self {
            Self::PortablePrivate => None,
            Self::LinuxProtected(namespace) => Some(namespace),
        }
    }

    #[cfg(target_os = "linux")]
    fn protected_repository_admission(&self) -> Option<Arc<tokio::sync::Semaphore>> {
        self.protected_namespace()
            .map(|namespace| namespace.repository_admission())
    }
}

struct SnapshotMemoryReservation {
    _permit: tokio::sync::SemaphorePermit<'static>,
}

/// Receipt for a validated immutable snapshot in the fixed LinuxProtected catalog.
///
/// The receipt intentionally contains no pathname. Its identity fields bind the
/// catalog generation to the held database and writer-lock objects that were
/// validated when the receipt was produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ProtectedSnapshotReceipt {
    pub(crate) generation: u64,
    pub(crate) slot: u8,
    pub(crate) byte_count: u64,
    pub(crate) digest: [u8; 32],
    database_device: u64,
    database_inode: u64,
    writer_device: u64,
    writer_inode: u64,
    writer_generation: u64,
}

impl ProtectedSnapshotReceipt {
    /// Returns the monotonic catalog generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the fixed catalog slot, either zero or one.
    #[must_use]
    pub const fn slot(&self) -> u8 {
        self.slot
    }

    /// Returns the validated snapshot byte length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_count
    }

    /// Returns the SHA-256 digest of the validated snapshot bytes.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the device number of the held live database.
    #[must_use]
    pub const fn database_device(&self) -> u64 {
        self.database_device
    }

    /// Returns the inode number of the held live database.
    #[must_use]
    pub const fn database_inode(&self) -> u64 {
        self.database_inode
    }

    /// Returns the device number of the held fixed writer lock.
    #[must_use]
    pub const fn writer_device(&self) -> u64 {
        self.writer_device
    }

    /// Returns the inode number of the held fixed writer lock.
    #[must_use]
    pub const fn writer_inode(&self) -> u64 {
        self.writer_inode
    }

    /// Returns the live writer generation bound into the catalog metadata.
    #[must_use]
    pub const fn writer_generation(&self) -> u64 {
        self.writer_generation
    }
}

#[cfg(target_os = "linux")]
fn protected_snapshot_receipt(snapshot: RecoveredSnapshot) -> ProtectedSnapshotReceipt {
    ProtectedSnapshotReceipt {
        generation: snapshot.metadata.generation,
        slot: snapshot.metadata.slot,
        byte_count: snapshot.metadata.byte_length,
        digest: snapshot.metadata.digest,
        database_device: snapshot.metadata.identity.database_device,
        database_inode: snapshot.metadata.identity.database_inode,
        writer_device: snapshot.metadata.identity.writer_device,
        writer_inode: snapshot.metadata.identity.writer_inode,
        writer_generation: snapshot.metadata.identity.writer_generation,
    }
}

#[cfg(target_os = "linux")]
#[cfg_attr(not(test), allow(dead_code))]
struct ProtectedSnapshotCleanupLease {
    namespace: Arc<ProtectedNamespace>,
    slot: u8,
    cleanup_deadline: tokio::time::Instant,
    cleanup_owner: Option<claw_sqlite_file_control::BlockingCleanupOwner>,
    retention: Arc<std::sync::Mutex<Option<ProtectedSnapshotRetention>>>,
    armed: bool,
}

#[cfg(target_os = "linux")]
#[cfg_attr(not(test), allow(dead_code))]
struct ProtectedSnapshotRetention {
    _memory: SnapshotMemoryReservation,
    _admission: tokio::sync::SemaphorePermit<'static>,
    _publication: tokio::sync::OwnedMutexGuard<()>,
}

struct RestoreMaterializationReservation {
    cleanup_owners: Vec<claw_sqlite_file_control::BlockingCleanupOwner>,
    memory: SnapshotMemoryReservation,
    admission: tokio::sync::SemaphorePermit<'static>,
}

type SharedSnapshotRetention = Arc<
    std::sync::Mutex<
        Option<(
            SnapshotMemoryReservation,
            tokio::sync::SemaphorePermit<'static>,
        )>,
    >,
>;
type SharedTerminalRetention = Arc<std::sync::Mutex<Option<Box<dyn Send>>>>;

type StateCleanupJob = Box<
    dyn FnMut(
            &tokio::runtime::Runtime,
            &mut claw_sqlite_file_control::ExternalCleanupPermit,
        ) -> bool
        + Send
        + 'static,
>;

#[cfg(test)]
type StateCleanupRetentionSignal = Option<Arc<std::sync::atomic::AtomicU8>>;
#[cfg(not(test))]
type StateCleanupRetentionSignal = ();
#[cfg(test)]
const NO_STATE_CLEANUP_RETENTION_SIGNAL: StateCleanupRetentionSignal = None;
#[cfg(not(test))]
const NO_STATE_CLEANUP_RETENTION_SIGNAL: StateCleanupRetentionSignal = ();

struct StateCleanupEnvelope {
    job: Option<StateCleanupJob>,
    permit: Option<claw_sqlite_file_control::ExternalCleanupPermit>,
    completion_signal: Option<Arc<std::sync::atomic::AtomicU8>>,
    #[cfg(test)]
    retained_signal: StateCleanupRetentionSignal,
}

struct RetainedStateCleanup {
    envelope: StateCleanupEnvelope,
    retry_at: std::time::Instant,
}

struct StateCleanupQuarantine {
    slots: [Option<RetainedStateCleanup>; MAX_STATE_CLEANUP_JOBS],
    next_retry_slot: usize,
}

struct StateCleanupExecutor {
    sender: std::sync::mpsc::SyncSender<StateCleanupEnvelope>,
    _receiver: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<StateCleanupEnvelope>>>,
}

const STATE_CLEANUP_THREADS: usize = 16;
const STATE_OPEN_ADMISSION_LIMIT: usize = 32;
// Each open can transiently hold its seven-owner reservation plus one
// before-acquire verifier owner. Seven opens consume at most 56 of 64 global
// cleanup slots, preserving eight for unrelated atomic cleanup reservations.
const OPEN_TRANSACTION_ADMISSION_LIMIT: usize = 7;
const MAX_STATE_CLEANUP_JOBS: usize = 64;
const MAX_STATE_CLOSE_RETENTIONS: usize = 64;
const MAX_WRITER_LOCK_CONTENT_BYTES: u64 = 4096;
const SNAPSHOT_CLEANUP_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const SNAPSHOT_CLEANUP_RETRY_TIMEOUT: Duration = Duration::from_millis(250);
const SNAPSHOT_CLEANUP_MAX_ATTEMPTS: usize = 8;
const RETAINED_STATE_CLEANUP_RETRY_INTERVAL: Duration = Duration::from_millis(50);
static STATE_CLEANUP_QUARANTINE: std::sync::LazyLock<std::sync::Mutex<StateCleanupQuarantine>> =
    std::sync::LazyLock::new(|| {
        std::sync::Mutex::new(StateCleanupQuarantine {
            slots: std::array::from_fn(|_| None),
            next_retry_slot: 0,
        })
    });

struct StateCloseRetention {
    _pool: SqlitePool,
    _lock_file: File,
    _process_identity: ProcessIdentityGuard,
    _database_file: File,
    _database_parent: File,
    _pool_identity_handles: PoolIdentityHandleGuard,
    _profile: ActiveStoreProfile,
}

struct PoolIdentityHandles {
    parent: File,
    database: File,
    lock: File,
}

type SharedPoolIdentityHandles = Arc<std::sync::Mutex<Option<PoolIdentityHandles>>>;
type ClonedPoolIdentityHandles = (Arc<File>, Arc<File>, Arc<File>);

struct PoolIdentityHandleGuard {
    shared: SharedPoolIdentityHandles,
}

impl Drop for PoolIdentityHandleGuard {
    fn drop(&mut self) {
        self.shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

fn clone_pool_identity_handles(
    shared: &SharedPoolIdentityHandles,
) -> Result<ClonedPoolIdentityHandles, StateError> {
    let handles = shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let handles = handles.as_ref().ok_or_else(|| StateError::InvalidPath {
        path: PathBuf::new(),
        reason: "state pool identity handles were terminally released",
    })?;
    Ok((
        Arc::new(
            handles
                .parent
                .try_clone()
                .map_err(|error| file_error("clone pool parent identity", Path::new("."), error))?,
        ),
        Arc::new(
            handles.database.try_clone().map_err(|error| {
                file_error("clone pool database identity", Path::new("."), error)
            })?,
        ),
        Arc::new(
            handles
                .lock
                .try_clone()
                .map_err(|error| file_error("clone pool lock identity", Path::new("."), error))?,
        ),
    ))
}

struct StateStoreOwnership {
    pool: SqlitePool,
    lock_file: File,
    process_identity: ProcessIdentityGuard,
    database_file: File,
    database_parent: File,
    close_retention: StateCloseRetentionReservation,
    pool_identity_handles: PoolIdentityHandleGuard,
    profile: ActiveStoreProfile,
}

impl StateStoreOwnership {
    fn retain(self) {
        self.close_retention.retain(StateCloseRetention {
            _pool: self.pool,
            _lock_file: self.lock_file,
            _process_identity: self.process_identity,
            _database_file: self.database_file,
            _database_parent: self.database_parent,
            _pool_identity_handles: self.pool_identity_handles,
            _profile: self.profile,
        });
    }
}

struct StateCloseRetentionSlot {
    reserved: bool,
    retention: Option<StateCloseRetention>,
}

static STATE_CLOSE_RETENTION_SLOTS: std::sync::LazyLock<
    std::sync::Mutex<[StateCloseRetentionSlot; MAX_STATE_CLOSE_RETENTIONS]>,
> = std::sync::LazyLock::new(|| {
    std::sync::Mutex::new(std::array::from_fn(|_| StateCloseRetentionSlot {
        reserved: false,
        retention: None,
    }))
});

struct StateCloseRetentionReservation {
    slot: usize,
    armed: bool,
}

impl StateCloseRetentionReservation {
    fn retain(mut self, retention: StateCloseRetention) {
        let mut slots = STATE_CLOSE_RETENTION_SLOTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slots[self.slot].retention = Some(retention);
        self.armed = false;
    }
}

impl Drop for StateCloseRetentionReservation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut slots = STATE_CLOSE_RETENTION_SLOTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let slot = &mut slots[self.slot];
        if slot.retention.is_none() {
            slot.reserved = false;
        }
    }
}

fn reserve_state_close_retention() -> Result<StateCloseRetentionReservation, StateError> {
    let mut slots = STATE_CLOSE_RETENTION_SLOTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = slots
        .iter()
        .position(|slot| !slot.reserved)
        .ok_or_else(|| {
            database(
                "reserve state close retention",
                sqlx::Error::Protocol("state close retention capacity is exhausted".to_owned()),
            )
        })?;
    slots[slot].reserved = true;
    Ok(StateCloseRetentionReservation { slot, armed: true })
}

fn retain_state_cleanup(envelope: StateCleanupEnvelope) {
    #[cfg(test)]
    let retained_signal = envelope.retained_signal.clone();
    let mut quarantine = STATE_CLEANUP_QUARANTINE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(slot) = quarantine.slots.iter_mut().find(|slot| slot.is_none()) {
        *slot = Some(RetainedStateCleanup {
            envelope,
            retry_at: std::time::Instant::now() + RETAINED_STATE_CLEANUP_RETRY_INTERVAL,
        });
        #[cfg(test)]
        if let Some(signal) = retained_signal {
            signal.store(1, std::sync::atomic::Ordering::Release);
        }
    } else {
        std::mem::forget(envelope);
    }
}

fn take_due_retained_state_cleanup(now: std::time::Instant) -> Option<StateCleanupEnvelope> {
    let mut quarantine = STATE_CLEANUP_QUARANTINE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for offset in 0..MAX_STATE_CLEANUP_JOBS {
        let index = (quarantine.next_retry_slot + offset) % MAX_STATE_CLEANUP_JOBS;
        if quarantine.slots[index]
            .as_ref()
            .is_some_and(|retained| retained.retry_at <= now)
        {
            quarantine.next_retry_slot = (index + 1) % MAX_STATE_CLEANUP_JOBS;
            return quarantine.slots[index]
                .take()
                .map(|retained| retained.envelope);
        }
    }
    None
}

fn run_state_cleanup_envelope(
    runtime: &tokio::runtime::Runtime,
    mut envelope: StateCleanupEnvelope,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let job = envelope
            .job
            .as_mut()
            .expect("state cleanup job remains owned");
        let permit = envelope
            .permit
            .as_mut()
            .expect("state cleanup permit remains owned");
        job(runtime, permit)
    }));
    match result {
        Ok(true) => {
            #[cfg(test)]
            let completion_signal = envelope
                .completion_signal
                .clone()
                .or_else(|| envelope.retained_signal.clone());
            #[cfg(not(test))]
            let completion_signal = envelope.completion_signal.clone();
            let job = envelope
                .job
                .take()
                .expect("completed state cleanup job remains owned");
            let permit = envelope
                .permit
                .take()
                .expect("completed state cleanup permit remains owned");
            let _ = if let Some(signal) = completion_signal {
                permit.retire_with_completion_signal(Box::new(job), signal, 2)
            } else {
                permit.retire(Box::new(job))
            };
        }
        Ok(false) => retain_state_cleanup(envelope),
        Err(panic) => {
            std::mem::forget(panic);
            retain_state_cleanup(envelope);
        }
    }
}

static STATE_CLEANUP_EXECUTOR: std::sync::LazyLock<Result<StateCleanupExecutor, String>> =
    std::sync::LazyLock::new(|| {
        let (sender, receiver) =
            std::sync::mpsc::sync_channel::<StateCleanupEnvelope>(MAX_STATE_CLEANUP_JOBS);
        let receiver = Arc::new(std::sync::Mutex::new(receiver));
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(STATE_CLEANUP_THREADS);
        for index in 0..STATE_CLEANUP_THREADS {
            let receiver = Arc::clone(&receiver);
            let ready_tx = ready_tx.clone();
            std::thread::Builder::new()
                .name(format!("claw-state-cleanup-{index}"))
                .spawn(move || {
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.to_string()));
                            return;
                        }
                    };
                    let _ = ready_tx.send(Ok(()));
                    let mut retained_turn = false;
                    loop {
                        if retained_turn
                            && let Some(envelope) =
                                take_due_retained_state_cleanup(std::time::Instant::now())
                        {
                            retained_turn = false;
                            run_state_cleanup_envelope(&runtime, envelope);
                            continue;
                        }
                        let received = receiver
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv_timeout(RETAINED_STATE_CLEANUP_RETRY_INTERVAL);
                        let envelope = match received {
                            Ok(envelope) => {
                                retained_turn = true;
                                envelope
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                                let Some(envelope) =
                                    take_due_retained_state_cleanup(std::time::Instant::now())
                                else {
                                    continue;
                                };
                                retained_turn = false;
                                envelope
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                        };
                        run_state_cleanup_envelope(&runtime, envelope);
                    }
                })
                .map_err(|error| error.to_string())?;
        }
        drop(ready_tx);
        for _ in 0..STATE_CLEANUP_THREADS {
            ready_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|error| format!("state cleanup executor readiness: {error}"))??;
        }
        Ok(StateCleanupExecutor {
            sender,
            _receiver: receiver,
        })
    });

fn run_open_lifecycle_runtime(
    ready: std::sync::mpsc::SyncSender<Result<tokio::runtime::Handle, String>>,
) {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(STATE_OPEN_ADMISSION_LIMIT)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(error.to_string()));
            return;
        }
    };
    if ready.send(Ok(runtime.handle().clone())).is_err() {
        return;
    }
    runtime.block_on(std::future::pending::<()>());
}

static OPEN_LIFECYCLE_RUNTIME: std::sync::LazyLock<Result<tokio::runtime::Handle, String>> =
    std::sync::LazyLock::new(|| {
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("claw-state-open-lifecycle".to_owned())
            .spawn(move || run_open_lifecycle_runtime(ready_tx))
            .map_err(|error| error.to_string())?;
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| format!("open lifecycle runtime readiness: {error}"))?
    });

async fn ensure_state_cleanup_executor(deadline: tokio::time::Instant) -> Result<(), String> {
    tokio::time::timeout_at(
        deadline,
        tokio::task::spawn_blocking(|| {
            STATE_CLEANUP_EXECUTOR
                .as_ref()
                .map(|_| ())
                .map_err(Clone::clone)
        }),
    )
    .await
    .map_err(|_| "state cleanup executor readiness timed out".to_owned())?
    .map_err(|error| format!("state cleanup executor readiness task: {error}"))?
}

async fn deadline_first<T>(
    deadline: tokio::time::Instant,
    future: impl std::future::Future<Output = T>,
) -> Result<T, ()> {
    if tokio::time::Instant::now() >= deadline {
        return Err(());
    }
    let timer = tokio::time::sleep_until(deadline);
    tokio::pin!(timer);
    tokio::pin!(future);
    let result = tokio::select! {
        biased;
        () = &mut timer => return Err(()),
        result = &mut future => result,
    };
    if tokio::time::Instant::now() >= deadline {
        Err(())
    } else {
        Ok(result)
    }
}

fn handoff_state_payload<Payload>(
    owner: claw_sqlite_file_control::BlockingCleanupOwner,
    payload: Payload,
    cleanup: fn(
        &tokio::runtime::Runtime,
        &mut claw_sqlite_file_control::TerminalCloseBatch,
        &Payload,
    ),
) -> Result<(), String>
where
    Payload: Send + 'static,
{
    handoff_state_payload_decide(owner, payload, move |runtime, terminal_closes, payload| {
        cleanup(runtime, terminal_closes, payload);
        true
    })
}

fn handoff_state_payload_with_completion<Payload>(
    owner: claw_sqlite_file_control::BlockingCleanupOwner,
    payload: Payload,
    completion_signal: Arc<std::sync::atomic::AtomicU8>,
    cleanup: fn(
        &tokio::runtime::Runtime,
        &mut claw_sqlite_file_control::TerminalCloseBatch,
        &Payload,
    ),
) -> Result<(), String>
where
    Payload: Send + 'static,
{
    handoff_state_payload_decide_with_signal(
        owner,
        payload,
        NO_STATE_CLEANUP_RETENTION_SIGNAL,
        Some(completion_signal),
        move |runtime, terminal_closes, payload| {
            cleanup(runtime, terminal_closes, payload);
            true
        },
    )
}

struct StateOwnerRetirementReceipt {
    signal: Arc<std::sync::atomic::AtomicU8>,
}

impl StateOwnerRetirementReceipt {
    fn new() -> Self {
        Self {
            signal: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        }
    }

    fn signal(&self) -> Arc<std::sync::atomic::AtomicU8> {
        Arc::clone(&self.signal)
    }

    async fn wait(
        &self,
        deadline: std::time::Instant,
        operation: &'static str,
    ) -> Result<(), String> {
        while self.signal.load(std::sync::atomic::Ordering::Acquire) != 2 {
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "{operation} owner terminal retirement exceeded its cleanup deadline"
                ));
            }
            tokio::task::yield_now().await;
        }
        Ok(())
    }
}

#[cfg(test)]
fn wait_at_checkpoint_identity_test_gate() {
    let gate = CHECKPOINT_IDENTITY_TEST_CONTROL
        .lock()
        .expect("checkpoint identity test control lock poisoned")
        .as_ref()
        .map(|control| (Arc::clone(&control.entered), Arc::clone(&control.release)));
    if let Some((entered, release)) = gate {
        entered.notify_one();
        while !release.load(std::sync::atomic::Ordering::Acquire) {
            std::thread::yield_now();
        }
    }
}

fn handoff_state_payload_decide<Payload, Cleanup>(
    owner: claw_sqlite_file_control::BlockingCleanupOwner,
    payload: Payload,
    cleanup: Cleanup,
) -> Result<(), String>
where
    Payload: Send + 'static,
    Cleanup: FnMut(
            &tokio::runtime::Runtime,
            &mut claw_sqlite_file_control::TerminalCloseBatch,
            &Payload,
        ) -> bool
        + Send
        + 'static,
{
    handoff_state_payload_decide_with_signal(
        owner,
        payload,
        NO_STATE_CLEANUP_RETENTION_SIGNAL,
        None,
        cleanup,
    )
}

fn handoff_state_payload_decide_with_signal<Payload, Cleanup>(
    owner: claw_sqlite_file_control::BlockingCleanupOwner,
    payload: Payload,
    #[cfg_attr(not(test), allow(unused_variables))] retained_signal: StateCleanupRetentionSignal,
    completion_signal: Option<Arc<std::sync::atomic::AtomicU8>>,
    mut cleanup: Cleanup,
) -> Result<(), String>
where
    Payload: Send + 'static,
    Cleanup: FnMut(
            &tokio::runtime::Runtime,
            &mut claw_sqlite_file_control::TerminalCloseBatch,
            &Payload,
        ) -> bool
        + Send
        + 'static,
{
    let permit = owner.into_external_cleanup()?;
    let envelope = StateCleanupEnvelope {
        job: Some(Box::new(move |runtime, permit| {
            cleanup(runtime, permit.terminal_closes(), &payload)
        })),
        permit: Some(permit),
        completion_signal,
        #[cfg(test)]
        retained_signal,
    };
    let executor = match STATE_CLEANUP_EXECUTOR.as_ref() {
        Ok(executor) => executor,
        Err(error) => {
            retain_state_cleanup(envelope);
            return Err(format!("state cleanup executor unavailable: {error}"));
        }
    };
    match executor.sender.try_send(envelope) {
        Ok(()) => Ok(()),
        Err(
            std::sync::mpsc::TrySendError::Full(envelope)
            | std::sync::mpsc::TrySendError::Disconnected(envelope),
        ) => {
            retain_state_cleanup(envelope);
            Err("state cleanup executor rejected a pre-reserved job".to_owned())
        }
    }
}

async fn reserve_snapshot_memory(
    deadline: tokio::time::Instant,
    operation: &'static str,
    timeout_ms: u64,
) -> Result<SnapshotMemoryReservation, StateError> {
    let permit = tokio::time::timeout_at(
        deadline,
        SNAPSHOT_MEMORY_ADMISSION.acquire_many(SNAPSHOT_OPERATION_PEAK_UNITS),
    )
    .await
    .map_err(|_| StateError::OperationTimedOut {
        operation,
        timeout_ms,
    })?
    .map_err(|_| {
        database(
            "reserve snapshot peak memory",
            sqlx::Error::Protocol("snapshot memory admission closed".to_owned()),
        )
    })?;
    Ok(SnapshotMemoryReservation { _permit: permit })
}

#[cfg(target_os = "linux")]
#[cfg_attr(not(test), allow(dead_code))]
impl ProtectedSnapshotCleanupLease {
    async fn cleanup_slot(&mut self) -> Result<(), StateError> {
        struct ProtectedScrubPayload {
            namespace: Arc<ProtectedNamespace>,
            slot: u8,
            _retention: Arc<std::sync::Mutex<Option<ProtectedSnapshotRetention>>>,
            result: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<Result<(), StateError>>>>,
        }

        if !self.armed {
            return Ok(());
        }
        let owner = self.cleanup_owner.take().ok_or_else(|| {
            database(
                "scrub LinuxProtected snapshot slot",
                sqlx::Error::Protocol("snapshot scrub cleanup owner is missing".to_owned()),
            )
        })?;
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let submitted = handoff_state_payload_decide(
            owner,
            ProtectedScrubPayload {
                namespace: Arc::clone(&self.namespace),
                slot: self.slot,
                _retention: Arc::clone(&self.retention),
                result: std::sync::Mutex::new(Some(result_tx)),
            },
            |_, _, payload| {
                let result = payload.namespace.scrub_slot(payload.slot);
                if let Some(result_tx) = payload
                    .result
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    let _ = result_tx.send(result.clone());
                }
                result.is_ok()
            },
        );
        self.armed = false;
        submitted.map_err(|error| {
            database(
                "submit LinuxProtected snapshot scrub",
                sqlx::Error::Protocol(error),
            )
        })?;
        loop {
            match result_rx.try_recv() {
                Ok(result) => return result,
                Err(std::sync::mpsc::TryRecvError::Empty)
                    if tokio::time::Instant::now() < self.cleanup_deadline =>
                {
                    tokio::task::yield_now().await;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    return Err(StateError::OperationTimedOut {
                        operation: "LinuxProtected snapshot cleanup",
                        timeout_ms: 0,
                    });
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err(database(
                        "receive LinuxProtected snapshot scrub",
                        sqlx::Error::Protocol(
                            "snapshot scrub owner stopped without a result".to_owned(),
                        ),
                    ));
                }
            }
        }
    }

    fn disarm_without_scrub(&mut self) -> Result<(), String> {
        self.armed = false;
        if let Some(owner) = self.cleanup_owner.take() {
            owner.shutdown()?;
        }
        Ok(())
    }

    fn detach_cleanup_internal(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        let Some(owner) = self.cleanup_owner.take() else {
            return;
        };
        let payload = (
            Arc::clone(&self.namespace),
            self.slot,
            Arc::clone(&self.retention),
        );
        let _ = handoff_state_payload_decide(owner, payload, |_, _, payload| {
            let _retention = &payload.2;
            payload.0.scrub_slot(payload.1).is_ok()
        });
    }
}

#[cfg(target_os = "linux")]
impl claw_sqlite_file_control::SnapshotCleanupLease for ProtectedSnapshotCleanupLease {
    fn cleanup(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move { self.cleanup_slot().await.map_err(|error| error.to_string()) })
    }

    fn take_terminal_retention(&mut self) -> Option<Box<dyn Send>> {
        Some(Box::new(Arc::clone(&self.retention)))
    }

    fn detach_cleanup(&mut self) {
        self.detach_cleanup_internal();
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProtectedSnapshotCleanupLease {
    fn drop(&mut self) {
        self.detach_cleanup_internal();
    }
}

async fn run_bounded_filesystem<T, Operation>(
    owner: claw_sqlite_file_control::BlockingCleanupOwner,
    deadline: tokio::time::Instant,
    operation: &'static str,
    timeout_ms: u64,
    work: Operation,
) -> Result<T, StateError>
where
    T: Send + 'static,
    Operation: FnMut() -> Result<T, StateError> + Send + 'static,
{
    run_bounded_filesystem_with_acceptance(owner, deadline, deadline, operation, timeout_ms, work)
        .await
}

async fn run_bounded_filesystem_with_acceptance<T, Operation>(
    owner: claw_sqlite_file_control::BlockingCleanupOwner,
    deadline: tokio::time::Instant,
    acceptance_deadline: tokio::time::Instant,
    operation: &'static str,
    timeout_ms: u64,
    work: Operation,
) -> Result<T, StateError>
where
    T: Send + 'static,
    Operation: FnMut() -> Result<T, StateError> + Send + 'static,
{
    struct FilesystemDelivery<T> {
        result: std::sync::Mutex<Option<Result<T, StateError>>>,
    }

    struct DeliveryDecisionGuard {
        decision: Arc<(std::sync::Mutex<Option<bool>>, std::sync::Condvar)>,
        decided: bool,
    }

    impl DeliveryDecisionGuard {
        fn decide(&mut self, accepted: bool) {
            let (decision, changed) = &*self.decision;
            *decision
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(accepted);
            changed.notify_all();
            self.decided = true;
        }
    }

    impl Drop for DeliveryDecisionGuard {
        fn drop(&mut self) {
            if !self.decided {
                self.decide(false);
            }
        }
    }

    struct FilesystemPayload<T, Operation> {
        work: std::sync::Mutex<Operation>,
        result: std::sync::mpsc::SyncSender<Arc<FilesystemDelivery<T>>>,
        delivery_retention: std::sync::Mutex<Option<Arc<FilesystemDelivery<T>>>>,
        decision: Arc<(std::sync::Mutex<Option<bool>>, std::sync::Condvar)>,
    }

    ensure_state_cleanup_executor(deadline)
        .await
        .map_err(|error| {
            database(
                "prepare bounded filesystem executor",
                sqlx::Error::Protocol(error),
            )
        })?;
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let decision = Arc::new((std::sync::Mutex::new(None), std::sync::Condvar::new()));
    let mut decision_guard = DeliveryDecisionGuard {
        decision: Arc::clone(&decision),
        decided: false,
    };
    handoff_state_payload(
        owner,
        FilesystemPayload {
            work: std::sync::Mutex::new(work),
            result: result_tx,
            delivery_retention: std::sync::Mutex::new(None),
            decision,
        },
        |_, _, payload| {
            let result = payload
                .work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)();
            let delivery = Arc::new(FilesystemDelivery {
                result: std::sync::Mutex::new(Some(result)),
            });
            *payload
                .delivery_retention
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&delivery));
            let _ = payload.result.send(delivery);
            let (decision, changed) = &*payload.decision;
            let mut decision = decision
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while decision.is_none() {
                decision = changed
                    .wait(decision)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        },
    )
    .map_err(|error| {
        database(
            "submit bounded filesystem operation",
            sqlx::Error::Protocol(error),
        )
    })?;
    loop {
        match result_rx.try_recv() {
            Ok(delivery) => {
                if tokio::time::Instant::now() >= acceptance_deadline {
                    decision_guard.decide(false);
                    return Err(StateError::OperationTimedOut {
                        operation,
                        timeout_ms,
                    });
                }
                let mut delivery = delivery
                    .result
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let result = delivery
                    .take()
                    .expect("bounded filesystem result is delivered once");
                if tokio::time::Instant::now() >= acceptance_deadline {
                    *delivery = Some(result);
                    decision_guard.decide(false);
                    return Err(StateError::OperationTimedOut {
                        operation,
                        timeout_ms,
                    });
                }
                decision_guard.decide(true);
                return result;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) if tokio::time::Instant::now() < deadline => {
                tokio::task::yield_now().await;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                decision_guard.decide(false);
                return Err(StateError::OperationTimedOut {
                    operation,
                    timeout_ms,
                });
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                decision_guard.decide(false);
                return Err(database(
                    "receive bounded filesystem operation",
                    sqlx::Error::Protocol(
                        "filesystem operation owner stopped without a result".to_owned(),
                    ),
                ));
            }
        }
    }
}

fn file_control_database(
    operation: &'static str,
    error: claw_sqlite_file_control::FileControlError,
) -> StateError {
    let error = match error {
        claw_sqlite_file_control::FileControlError::CommittedAfterDeadline(cleanup) => {
            return StateError::CommittedAfterDeadline { operation, cleanup };
        }
        claw_sqlite_file_control::FileControlError::CommittedWithCleanupFailure(cleanup) => {
            return StateError::CommittedWithCleanupFailure { operation, cleanup };
        }
        claw_sqlite_file_control::FileControlError::CommitOutcomeUncertain(code, message) => {
            return StateError::CommitOutcomeUncertain {
                operation,
                code,
                message,
            };
        }
        claw_sqlite_file_control::FileControlError::IdentityCommitVetoed(veto, cleanup) => {
            let primary = StateError::InvalidPath {
                path: veto.path().to_owned(),
                reason: veto.reason(),
            };
            return match cleanup {
                Some(cleanup) => StateError::OperationCleanupFailed {
                    operation,
                    primary: Box::new(primary),
                    cleanup,
                },
                None => primary,
            };
        }
        other => other,
    };
    error.code().map_or_else(
        || database(operation, sqlx::Error::Protocol(error.to_string())),
        |code| database_code(operation, code, error.to_string()),
    )
}

fn file_control_with_deadline(
    operation: &'static str,
    error: claw_sqlite_file_control::FileControlError,
    deadline_state: Option<&OpenDeadlineState>,
) -> StateError {
    if error.code() == Some(9)
        && deadline_state.is_some_and(|state| {
            std::time::Instant::now() >= state.work_cutoff
                || state.expired.load(std::sync::atomic::Ordering::Acquire)
                || state.cancelled.load(std::sync::atomic::Ordering::Acquire)
        })
    {
        deadline_state
            .expect("deadline state checked above")
            .timeout_error()
    } else {
        file_control_database(operation, error)
    }
}
#[cfg(test)]
static FAIL_AFTER_PUBLICATION: std::sync::LazyLock<Mutex<std::collections::HashSet<PathBuf>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static CREATE_DESTINATION_BEFORE_PUBLICATION: std::sync::LazyLock<
    Mutex<std::collections::HashSet<PathBuf>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static STALL_HEALTH_PROGRESS: std::sync::LazyLock<Mutex<std::collections::HashSet<PathBuf>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static EXPIRE_PUBLICATION_DEADLINE: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, u8>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static EXPIRE_OUTPUT_CREATION_DEADLINE: std::sync::LazyLock<
    Mutex<std::collections::HashSet<PathBuf>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
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
#[cfg(test)]
static OPEN_POSTCOMMIT_HOLD_AFTER_CANCEL: std::sync::LazyLock<
    Mutex<std::collections::HashSet<PathBuf>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static OPEN_AFTER_ACK_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static OPEN_AFTER_ACK_CANCEL_ON_RELEASE: std::sync::LazyLock<
    Mutex<std::collections::HashSet<PathBuf>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static OPEN_AFTER_ACK_EXPIRE_ON_RELEASE: std::sync::LazyLock<
    Mutex<std::collections::HashSet<PathBuf>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static OPEN_TEST_CLEANUP_BUDGET: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, Duration>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
type OpenTestDeadlineObserver = Arc<Mutex<Option<(tokio::time::Instant, tokio::time::Instant)>>>;
#[cfg(test)]
static OPEN_TEST_DEADLINE_OBSERVERS: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, OpenTestDeadlineObserver>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static OPEN_CLEANUP_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static APPLICATION_ID_READ_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static UNDELIVERED_AFTER_BEGIN_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static UNDELIVERED_AFTER_DELETE_TEST_BARRIER: std::sync::LazyLock<
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
#[cfg(all(test, unix))]
static SNAPSHOT_HARDENING_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, Arc<SnapshotHardeningTestBarrier>>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static RESTORE_READ_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static PUBLISHED_HANDOFF_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static BACKUP_CAPTURE_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, Arc<BackupCaptureTestBarrier>>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static FINAL_CONNECTION_CLOSE_FAILURES: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, FinalConnectionCloseFailure>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static PANIC_CLOSE_AFTER_OWNERSHIP_GUARD: std::sync::LazyLock<
    Mutex<std::collections::HashSet<PathBuf>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(all(test, unix))]
static FAIL_SNAPSHOT_CLEANUP_AFTER_RENAME: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, CountedFailure>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(all(test, unix))]
static FAIL_TRUSTED_SEAL_AFTER_UNLINK: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, CountedFailure>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(all(test, target_os = "linux"))]
static PROTECTED_SNAPSHOT_TEST_FAILURES: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, u8>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(all(test, target_os = "linux"))]
struct ProtectedSnapshotTestGate {
    stage: u8,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    slot: Arc<std::sync::atomic::AtomicU8>,
}
#[cfg(all(test, target_os = "linux"))]
static PROTECTED_SNAPSHOT_TEST_GATES: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, ProtectedSnapshotTestGate>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(all(test, target_os = "linux"))]
static FAIL_PROTECTED_PERSIST_WAL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(all(test, target_os = "linux"))]
fn take_protected_snapshot_test_failure(path: &Path, stage: u8) -> bool {
    let mut failures = PROTECTED_SNAPSHOT_TEST_FAILURES
        .lock()
        .expect("protected snapshot failure map lock poisoned");
    if failures.get(path).copied() == Some(stage) {
        failures.remove(path);
        true
    } else {
        false
    }
}

#[cfg(all(test, target_os = "linux"))]
async fn wait_at_protected_snapshot_test_gate(
    path: &Path,
    stage: u8,
    slot: u8,
    deadline: tokio::time::Instant,
) {
    let gate = PROTECTED_SNAPSHOT_TEST_GATES
        .lock()
        .expect("protected snapshot gate map lock poisoned")
        .get(path)
        .filter(|gate| gate.stage == stage)
        .map(|gate| {
            (
                Arc::clone(&gate.entered),
                Arc::clone(&gate.release),
                Arc::clone(&gate.slot),
            )
        });
    let Some((entered, release, observed_slot)) = gate else {
        return;
    };
    observed_slot.store(slot + 1, std::sync::atomic::Ordering::Release);
    entered.notify_one();
    tokio::select! {
        () = release.notified() => {}
        () = tokio::time::sleep_until(deadline) => {}
    }
    PROTECTED_SNAPSHOT_TEST_GATES
        .lock()
        .expect("protected snapshot gate map lock poisoned")
        .remove(path);
}
#[cfg(test)]
static OPEN_ADMISSION_TEST_BARRIER: std::sync::LazyLock<Mutex<Option<OpenAdmissionTestBarrier>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));
#[cfg(test)]
static OPEN_RESERVED_OWNER_PATHS: std::sync::LazyLock<Mutex<std::collections::HashSet<PathBuf>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static OPEN_RESERVED_OWNER_GATE_REMAINING: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
struct BeforeAcquireOwnerTestBarrier {
    entered: Arc<std::sync::atomic::AtomicUsize>,
    releases: Arc<std::sync::atomic::AtomicUsize>,
}
#[cfg(test)]
static BEFORE_ACQUIRE_OWNER_TEST_BARRIER: std::sync::LazyLock<
    Mutex<Option<BeforeAcquireOwnerTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(None));
#[cfg(test)]
static EARLY_VERIFIER_RETIRE_PATHS: std::sync::LazyLock<Mutex<std::collections::HashSet<PathBuf>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static EARLY_VERIFIER_RETIRE_TEST_BARRIER: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, OpenAdmissionTestBarrier>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
#[derive(Clone)]
struct OwnedCloseCutoffTestControl {
    fallback_timeout: Duration,
    result_entered: Arc<tokio::sync::Notify>,
    result_release: Arc<std::sync::atomic::AtomicBool>,
    retirement_entered: Arc<tokio::sync::Notify>,
    retirement_release: Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(test)]
static OWNED_CLOSE_CUTOFF_TEST_CONTROL: std::sync::LazyLock<
    Mutex<Option<OwnedCloseCutoffTestControl>>,
> = std::sync::LazyLock::new(|| Mutex::new(None));
#[cfg(test)]
#[derive(Clone)]
struct CheckpointIdentityTestControl {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(test)]
static CHECKPOINT_IDENTITY_TEST_CONTROL: std::sync::LazyLock<
    Mutex<Option<CheckpointIdentityTestControl>>,
> = std::sync::LazyLock::new(|| Mutex::new(None));
#[cfg(test)]
static EXPIRED_UNDELIVERED_BEGIN_DISPATCHES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static OPEN_TRANSACTION_WAITERS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
struct OpenTransactionWaiter;

#[cfg(test)]
impl OpenTransactionWaiter {
    fn new() -> Self {
        OPEN_TRANSACTION_WAITERS.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self
    }
}

#[cfg(test)]
impl Drop for OpenTransactionWaiter {
    fn drop(&mut self) {
        OPEN_TRANSACTION_WAITERS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

#[cfg(all(test, unix))]
struct CountedFailure {
    remaining: usize,
    attempts: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(all(test, unix))]
fn take_counted_failure(
    failures: &Mutex<std::collections::HashMap<PathBuf, CountedFailure>>,
    path: &Path,
) -> bool {
    let mut failures = failures
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(failure) = failures.get_mut(path) else {
        return false;
    };
    if failure.remaining == 0 {
        return false;
    }
    failure
        .attempts
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    if failure.remaining != usize::MAX {
        failure.remaining -= 1;
    }
    true
}

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

#[cfg(all(test, unix))]
struct SnapshotHardeningTestBarrier {
    temporary: Arc<Mutex<Option<PathBuf>>>,
    entered: Arc<tokio::sync::Notify>,
    released: std::sync::Mutex<bool>,
    changed: std::sync::Condvar,
}

#[cfg(all(test, unix))]
impl SnapshotHardeningTestBarrier {
    fn release(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.changed.notify_all();
    }
}

#[cfg(test)]
struct BackupCaptureTestBarrier {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<std::sync::atomic::AtomicBool>,
    observed: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
struct OpenAdmissionTestBarrier {
    entered: Arc<std::sync::atomic::AtomicUsize>,
    release: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
fn open_admission_test_barrier_is_active() -> bool {
    OPEN_ADMISSION_TEST_BARRIER
        .lock()
        .expect("open admission test barrier lock poisoned")
        .is_some()
}

#[cfg(test)]
async fn wait_at_open_admission_test_barrier() {
    let barrier = OPEN_ADMISSION_TEST_BARRIER
        .lock()
        .expect("open admission test barrier lock poisoned")
        .as_ref()
        .map(|barrier| (Arc::clone(&barrier.entered), Arc::clone(&barrier.release)));
    if let Some((entered, release)) = barrier {
        entered.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        while !release.load(std::sync::atomic::Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(test)]
impl BackupCaptureTestBarrier {
    async fn wait(&self, deadline_state: &OpenDeadlineState) {
        if !self
            .observed
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.entered.notify_one();
            while !self.release.load(std::sync::atomic::Ordering::Acquire)
                && deadline_state.permits_sqlite_work()
            {
                tokio::task::yield_now().await;
            }
        }
    }
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

/// Filesystem and SQLite security profile selected for a state store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StateProfile {
    /// Service-private state with the existing arbitrary absolute database path.
    PortablePrivate,
    /// Fixed-name state inside a preprovisioned root-owned Linux namespace.
    LinuxProtected,
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
    profile: ConfiguredStoreProfile,
    max_connections: u32,
    busy_timeout: Duration,
    acquire_timeout: Duration,
    open_timeout: Duration,
    operation_timeout: Duration,
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
            profile: ConfiguredStoreProfile::PortablePrivate,
            max_connections: 1,
            busy_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(5),
            open_timeout: Duration::from_secs(30),
            operation_timeout: Duration::from_secs(30),
            close_timeout: Duration::from_millis(1_500),
            synchronous: SynchronousPolicy::Full,
        }
    }

    /// Creates a LinuxProtected configuration from its namespace directory.
    ///
    /// The database, WAL, fixed writer lock, two snapshot slots, metadata
    /// files, and selector are derived internally from the accepted fixed
    /// eight-entry catalog. Runtime open binds the expected file ownership to
    /// the process's effective service UID and GID; those credentials are not
    /// root provisioner credentials. LinuxProtected requires exactly one
    /// connection, and incompatible builder overrides are rejected at open.
    ///
    /// This profile prevents a compromised service UID from substituting
    /// directory entries because the namespace is root-owned and not writable
    /// by the service. It does not prevent direct content writes by a
    /// compromised process that already holds service-file write authority.
    /// Root, kernel, and mount compromise and forensic erasure are non-goals.
    ///
    /// The constructor is available on every platform so configuration code
    /// remains portable. Opening it off Linux returns
    /// [`crate::StateErrorKind::UnsupportedPlatform`].
    #[must_use]
    pub fn linux_protected(namespace: impl Into<PathBuf>) -> Self {
        let namespace = namespace.into();
        let path = namespace.join(LINUX_PROTECTED_DATABASE_NAME);
        Self {
            path,
            profile: ConfiguredStoreProfile::LinuxProtected { namespace },
            max_connections: 1,
            busy_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(5),
            open_timeout: Duration::from_secs(30),
            operation_timeout: Duration::from_secs(30),
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

    /// Sets one overall deadline for each post-open state operation.
    #[must_use]
    pub const fn with_operation_timeout(mut self, operation_timeout: Duration) -> Self {
        self.operation_timeout = operation_timeout;
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

    /// Returns the selected state profile.
    #[must_use]
    pub const fn profile(&self) -> StateProfile {
        match self.profile {
            ConfiguredStoreProfile::PortablePrivate => StateProfile::PortablePrivate,
            ConfiguredStoreProfile::LinuxProtected { .. } => StateProfile::LinuxProtected,
        }
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
    lock_identity: Option<Vec<u8>>,
    ownership: Option<StateStoreOwnership>,
    writer_generation: Arc<AtomicU64>,
    max_connections: u32,
    operation_timeout: Duration,
    busy_timeout: Duration,
    close_timeout: Duration,
    undelivered_cleanup_owner: Option<claw_sqlite_file_control::BlockingCleanupOwner>,
    open_transaction_admission: Option<tokio::sync::SemaphorePermit<'static>>,
    profile: ActiveStoreProfile,
}

impl Drop for StateStore {
    fn drop(&mut self) {
        if let Some(owner) = self.undelivered_cleanup_owner.take() {
            let _ = owner.shutdown();
        }
        self.open_transaction_admission.take();
        if let Some(ownership) = self.ownership.take() {
            ownership.retain();
        }
    }
}

struct StateStoreCloseGuard {
    ownership: Option<StateStoreOwnership>,
    terminal_confirmed: bool,
}

impl StateStoreCloseGuard {
    fn ownership(&self) -> &StateStoreOwnership {
        self.ownership
            .as_ref()
            .expect("close guard retains state store ownership")
    }

    fn confirm_terminal_close(&mut self) {
        self.terminal_confirmed = true;
    }
}

impl Drop for StateStoreCloseGuard {
    fn drop(&mut self) {
        if !self.terminal_confirmed
            && let Some(ownership) = self.ownership.take()
        {
            ownership.retain();
        }
    }
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
    profile: &'store ActiveStoreProfile,
    pub(crate) busy_timeout: Duration,
    pub(crate) operation_timeout: Duration,
    pub(crate) cleanup_timeout: Duration,
}

struct OwnedOperationalIdentity {
    database_parent_path: PathBuf,
    database_parent: File,
    database_path: PathBuf,
    database_file: File,
    lock_path: PathBuf,
    lock_file: File,
    lock_identity: Option<Vec<u8>>,
    profile: ActiveStoreProfile,
}

impl OperationalIdentity<'_> {
    fn verify_generation(self) -> Result<(), StateError> {
        if self.writer_generation.load(Ordering::Acquire) != 1 {
            return Err(StateError::InvalidPath {
                path: self.database_path.to_owned(),
                reason: "state writer generation is no longer live",
            });
        }
        Ok(())
    }

    pub(crate) fn verify_protected(self) -> Result<(), StateError> {
        if self.profile.is_protected() {
            self.verify()
        } else {
            Ok(())
        }
    }

    pub(crate) const fn is_protected(self) -> bool {
        self.profile.is_protected()
    }

    pub(crate) fn protected_repository_admission(self) -> Option<Arc<tokio::sync::Semaphore>> {
        #[cfg(target_os = "linux")]
        {
            self.profile.protected_repository_admission()
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    fn capture_owned(self) -> Result<OwnedOperationalIdentity, StateError> {
        Ok(OwnedOperationalIdentity {
            database_parent_path: self.database_parent_path.to_owned(),
            database_parent: self.database_parent.try_clone().map_err(|error| {
                file_error(
                    "clone state operation directory identity",
                    self.database_parent_path,
                    error,
                )
            })?,
            database_path: self.database_path.to_owned(),
            database_file: self.database_file.try_clone().map_err(|error| {
                file_error(
                    "clone state operation database identity",
                    self.database_path,
                    error,
                )
            })?,
            lock_path: self.lock_path.to_owned(),
            lock_file: self.lock_file.try_clone().map_err(|error| {
                file_error("clone state operation lock identity", self.lock_path, error)
            })?,
            lock_identity: self.lock_identity.map(<[u8]>::to_vec),
            profile: self.profile.clone(),
        })
    }

    pub(crate) fn verify(self) -> Result<(), StateError> {
        self.verify_generation()?;
        self.profile.verify_filesystem(
            (self.database_parent_path, self.database_parent),
            (self.database_path, self.database_file),
            (self.lock_path, self.lock_file),
            self.lock_identity,
            true,
        )
    }
}

impl OwnedOperationalIdentity {
    fn verify(&self) -> Result<(), StateError> {
        self.profile.verify_filesystem(
            (&self.database_parent_path, &self.database_parent),
            (&self.database_path, &self.database_file),
            (&self.lock_path, &self.lock_file),
            self.lock_identity.as_deref(),
            true,
        )
    }
}

#[cfg(unix)]
static PROCESS_IDENTITIES: LazyLock<StdMutex<std::collections::HashSet<(u64, u64)>>> =
    LazyLock::new(|| StdMutex::new(std::collections::HashSet::new()));

struct ProcessIdentityGuard {
    #[cfg(unix)]
    identity: Option<(u64, u64)>,
    #[cfg(windows)]
    lock_file: Option<File>,
}

struct OpenDeadlineState {
    work_cutoff: std::time::Instant,
    deadline: std::time::Instant,
    timeout_ms: u64,
    operation: &'static str,
    busy_timeout: Duration,
    expired: Arc<std::sync::atomic::AtomicBool>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    finished: std::sync::atomic::AtomicBool,
    final_commit_state: std::sync::atomic::AtomicU8,
    open_cleanup_state: std::sync::atomic::AtomicU8,
}

impl OpenDeadlineState {
    fn retain_open_cleanup(&self) -> bool {
        match self.open_cleanup_state.compare_exchange(
            0,
            1,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) | Err(1) => true,
            Err(_) => false,
        }
    }

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

    fn finish_final_commit(&self) -> bool {
        self.final_commit_state
            .compare_exchange(
                2,
                0,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    }

    fn permits_sqlite_work(&self) -> bool {
        if std::time::Instant::now() >= self.work_cutoff {
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
        #[cfg(windows)]
        if let Some(lock_file) = self.lock_file.take() {
            let _ = File::unlock(&lock_file);
        }
    }
}

struct UndeliveredStoreCleanup {
    store: Option<StateStore>,
    open_admission: Option<tokio::sync::SemaphorePermit<'static>>,
    deadline: tokio::time::Instant,
    deadline_state: Arc<OpenDeadlineState>,
}

async fn release_undelivered_store_without_sql(mut store: StateStore) -> Result<(), StateError> {
    let ownership = store.ownership.take().ok_or_else(|| {
        database(
            "release undelivered state store",
            sqlx::Error::Protocol("state store ownership is missing".to_owned()),
        )
    })?;
    let pool = ownership.pool.clone();
    pool.close().await;
    drop(ownership);
    Ok(())
}

fn handoff_undelivered_store(
    owner: claw_sqlite_file_control::BlockingCleanupOwner,
    store: StateStore,
    open_admission: tokio::sync::SemaphorePermit<'static>,
    deadline: tokio::time::Instant,
    deadline_state: Arc<OpenDeadlineState>,
) -> Result<(), StateError> {
    handoff_state_payload_decide(
        owner,
        std::sync::Mutex::new(UndeliveredStoreCleanup {
            store: Some(store),
            open_admission: Some(open_admission),
            deadline,
            deadline_state,
        }),
        |runtime, _, payload| {
            let mut payload = payload
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let deadline = payload.deadline;
            let cleanup = runtime.block_on(close_undelivered_writer_claim(
                payload
                    .store
                    .as_mut()
                    .expect("undelivered store remains owned"),
                deadline,
            ));
            let store = payload
                .store
                .take()
                .expect("undelivered store is consumed once");
            let deadline_state = Arc::clone(&payload.deadline_state);
            let open_admission = payload
                .open_admission
                .take()
                .expect("undelivered open admission remains owned");
            drop(payload);
            let _open_admission = open_admission;
            let terminal = runtime.block_on(release_undelivered_store_without_sql(store));
            deadline_state
                .finished
                .store(true, std::sync::atomic::Ordering::Release);
            let _cleanup_receipt = cleanup;
            let _terminal_receipt = terminal;
            true
        },
    )
    .map_err(|error| {
        database(
            "handoff undelivered state store cleanup",
            sqlx::Error::Protocol(error),
        )
    })
}

#[cfg(test)]
async fn wait_at_undelivered_cleanup_barrier(
    path: &Path,
    barriers: &'static std::sync::LazyLock<
        Mutex<std::collections::HashMap<PathBuf, MigrationTestBarrier>>,
    >,
) {
    let barrier = barriers
        .lock()
        .expect("undelivered cleanup barrier lock poisoned")
        .get(path)
        .map(|barrier| (Arc::clone(&barrier.entered), Arc::clone(&barrier.release)));
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        release.notified().await;
        barriers
            .lock()
            .expect("undelivered cleanup barrier lock poisoned")
            .remove(path);
    }
}

async fn close_undelivered_writer_claim(
    store: &mut StateStore,
    deadline: tokio::time::Instant,
) -> Result<(), StateError> {
    #[cfg(test)]
    wait_at_open_cleanup_test_barrier(store.path()).await;
    let cleanup_deadline = deadline.into_std();
    let work_deadline = cleanup_deadline
        .checked_sub(Duration::from_millis(10))
        .unwrap_or(cleanup_deadline);
    if std::time::Instant::now() >= work_deadline {
        return Err(StateError::OperationTimedOut {
            operation: "begin undelivered claim cleanup",
            timeout_ms: 0,
        });
    }
    let remaining = work_deadline.saturating_duration_since(std::time::Instant::now());
    let timeout_ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
    let connection = tokio::time::timeout_at(
        tokio::time::Instant::from_std(work_deadline),
        store.pool().acquire(),
    )
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
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    #[cfg(test)]
    EXPIRED_UNDELIVERED_BEGIN_DISPATCHES.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let mut transaction =
        claw_sqlite_file_control::begin_manual_pool_transaction_with_restore_deadlines(
            connection,
            work_deadline,
            cleanup_deadline,
            store.busy_timeout,
            store.busy_timeout,
            Some(Arc::clone(&cancelled)),
        )
        .await
        .map_err(|error| file_control_database("begin undelivered claim cleanup", error))?;
    #[cfg(test)]
    wait_at_undelivered_cleanup_barrier(store.path(), &UNDELIVERED_AFTER_BEGIN_TEST_BARRIER).await;
    let released = transaction
        .delete_writer_claim_with_deadline(&store.owner, work_deadline, Arc::clone(&cancelled))
        .await;
    #[cfg(test)]
    wait_at_undelivered_cleanup_barrier(store.path(), &UNDELIVERED_AFTER_DELETE_TEST_BARRIER).await;
    let released = match released {
        Ok(released) => released,
        Err(error) => {
            let primary = file_control_database("release undelivered writer claim", error);
            return match transaction.rollback().await {
                Ok(_) => Err(primary),
                Err(cleanup) => Err(StateError::OperationCleanupFailed {
                    operation: "rollback failed undelivered claim deletion",
                    primary: Box::new(primary),
                    cleanup: cleanup.to_string(),
                }),
            };
        }
    };
    if released != 1 {
        let primary = StateError::InvalidMigrationHistory {
            reason: "undelivered writer claim was not owned by this open lifecycle".to_owned(),
        };
        return match transaction.rollback().await {
            Ok(_) => Err(primary),
            Err(cleanup) => Err(StateError::OperationCleanupFailed {
                operation: "rollback mismatched undelivered claim deletion",
                primary: Box::new(primary),
                cleanup: cleanup.to_string(),
            }),
        };
    }
    let (connection, post_commit_owner) = transaction
        .commit_with_deadline(
            work_deadline,
            cleanup_deadline,
            cancelled,
            store.busy_timeout,
            None,
        )
        .await
        .map_err(|error| file_control_database("commit undelivered claim cleanup", error))?;
    connection
        .close()
        .await
        .map_err(|error| database("close undelivered claim cleanup connection", error))?;
    post_commit_owner.shutdown().map_err(|error| {
        database(
            "release undelivered claim post-COMMIT owner",
            sqlx::Error::Protocol(error),
        )
    })?;
    Ok(())
}

async fn open_timeout_error(
    mut terminal: tokio::sync::oneshot::Receiver<Result<OpenLifecycleTerminal, String>>,
    deadline: tokio::time::Instant,
    deadline_state: &OpenDeadlineState,
    timeout_ms: u64,
) -> StateError {
    let primary = StateError::OperationTimedOut {
        operation: "state store open",
        timeout_ms,
    };
    let terminal_result = tokio::time::timeout_at(deadline, &mut terminal).await;
    let terminal_result = match terminal_result {
        Ok(result) => result,
        Err(_) => {
            if !deadline_state.retain_open_cleanup() {
                return StateError::OperationCleanupFailed {
                    operation: "state store open",
                    primary: Box::new(primary),
                    cleanup:
                        "open cleanup lifecycle retained ownership beyond the absolute open deadline"
                            .to_owned(),
                };
            }
            drop(terminal);
            return primary;
        }
    };
    match terminal_result {
        Ok(Ok(OpenLifecycleTerminal::Delivery(delivery))) => {
            drop(delivery);
            primary
        }
        Ok(Ok(OpenLifecycleTerminal::Cleaned)) => primary,
        Ok(Err(cleanup)) => StateError::OperationCleanupFailed {
            operation: "state store open",
            primary: Box::new(primary),
            cleanup,
        },
        Err(_) => StateError::OperationCleanupFailed {
            operation: "state store open",
            primary: Box::new(primary),
            cleanup: "open lifecycle actor stopped without a terminal receipt".to_owned(),
        },
    }
}

async fn close_pool_after_open_failure(
    pool: &SqlitePool,
    deadline_state: &OpenDeadlineState,
    primary: StateError,
) -> StateError {
    if !deadline_state.retain_open_cleanup() {
        return primary;
    }
    match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline_state.deadline),
        pool.close(),
    )
    .await
    {
        Ok(()) => primary,
        Err(_) => {
            std::future::pending::<()>().await;
            unreachable!("failed-open pool ownership remains retained by the open lifecycle");
        }
    }
}

struct OpenLifecycleActorInput {
    config: StoreConfig,
    profile: StoreProfile,
    close_retention: StateCloseRetentionReservation,
    open_admission: tokio::sync::SemaphorePermit<'static>,
    transaction_admission: tokio::sync::SemaphorePermit<'static>,
    deadline: tokio::time::Instant,
    deadline_state: Arc<OpenDeadlineState>,
    ready: tokio::sync::oneshot::Sender<Result<(), StateError>>,
    delivery_ack: tokio::sync::oneshot::Receiver<()>,
}

struct OpenStoreDelivery {
    store: Option<StateStore>,
    cleanup_owner: Option<claw_sqlite_file_control::BlockingCleanupOwner>,
    open_admission: Option<tokio::sync::SemaphorePermit<'static>>,
    transaction_admission: Option<tokio::sync::SemaphorePermit<'static>>,
    deadline: tokio::time::Instant,
    deadline_state: Arc<OpenDeadlineState>,
}

enum OpenLifecycleTerminal {
    Delivery(Box<OpenStoreDelivery>),
    Cleaned,
}

impl OpenStoreDelivery {
    fn accept(mut self) -> StateStore {
        self.cleanup_owner.take();
        self.open_admission.take();
        self.transaction_admission.take();
        self.store.take().expect("delivered store remains owned")
    }
}

impl Drop for OpenStoreDelivery {
    fn drop(&mut self) {
        let (Some(owner), Some(mut store), Some(open_admission), Some(transaction_admission)) = (
            self.cleanup_owner.take(),
            self.store.take(),
            self.open_admission.take(),
            self.transaction_admission.take(),
        ) else {
            return;
        };
        store.open_transaction_admission = Some(transaction_admission);
        let _ = handoff_undelivered_store(
            owner,
            store,
            open_admission,
            self.deadline,
            Arc::clone(&self.deadline_state),
        );
    }
}

async fn run_open_lifecycle_actor(
    input: OpenLifecycleActorInput,
) -> Result<OpenLifecycleTerminal, StateError> {
    let OpenLifecycleActorInput {
        config,
        profile,
        close_retention,
        open_admission,
        transaction_admission,
        deadline,
        deadline_state,
        ready,
        delivery_ack,
    } = input;
    match StateStore::open_inner(
        config,
        profile,
        Arc::clone(&deadline_state),
        close_retention,
        transaction_admission,
    )
    .await
    {
        Err(error) => {
            let _ = ready.send(Err(error));
            Ok(OpenLifecycleTerminal::Cleaned)
        }
        Ok(mut store) => {
            let undelivered_cleanup_owner = store
                .undelivered_cleanup_owner
                .take()
                .expect("opened store retains its undelivered cleanup owner");
            let _ = deadline_state.retain_open_cleanup();
            #[cfg(test)]
            wait_at_open_postcommit_test_barrier(store.path(), &deadline_state).await;
            if ready.send(Ok(())).is_err() {
                handoff_undelivered_store(
                    undelivered_cleanup_owner,
                    store,
                    open_admission,
                    deadline,
                    deadline_state,
                )?;
                return Ok(OpenLifecycleTerminal::Cleaned);
            }
            if delivery_ack.await.is_err() {
                handoff_undelivered_store(
                    undelivered_cleanup_owner,
                    store,
                    open_admission,
                    deadline,
                    deadline_state,
                )?;
                return Ok(OpenLifecycleTerminal::Cleaned);
            }
            #[cfg(test)]
            wait_at_open_after_ack_test_barrier(store.path(), &deadline_state).await;
            let transaction_admission = store
                .open_transaction_admission
                .take()
                .expect("opened store retains its transaction admission");
            Ok(OpenLifecycleTerminal::Delivery(Box::new(
                OpenStoreDelivery {
                    store: Some(store),
                    cleanup_owner: Some(undelivered_cleanup_owner),
                    open_admission: Some(open_admission),
                    transaction_admission: Some(transaction_admission),
                    deadline,
                    deadline_state,
                },
            )))
        }
    }
}

impl StateStore {
    /// Opens an explicit on-disk database, acquires its writer lock, and migrates forward.
    pub async fn open(config: StoreConfig) -> Result<Self, StateError> {
        let profile = match &config.profile {
            ConfiguredStoreProfile::PortablePrivate => StoreProfile::PortablePrivate,
            ConfiguredStoreProfile::LinuxProtected { namespace } => {
                #[cfg(target_os = "linux")]
                {
                    StoreProfile::LinuxProtected(LinuxProtectedSpec::new(
                        namespace.clone(),
                        rustix::process::geteuid().as_raw(),
                        rustix::process::getegid().as_raw(),
                    ))
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = namespace;
                    return Err(StateError::InvalidValue {
                        field: "state platform",
                        reason: "opening LinuxProtected state requires Linux",
                    });
                }
            }
        };
        Self::open_with_profile(config, profile).await
    }

    #[cfg(target_os = "linux")]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn open_linux_protected(
        config: StoreConfig,
        directory: PathBuf,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, StateError> {
        Self::open_with_profile(
            config,
            StoreProfile::LinuxProtected(LinuxProtectedSpec::new(
                directory,
                expected_uid,
                expected_gid,
            )),
        )
        .await
    }

    async fn open_with_profile(
        config: StoreConfig,
        profile: StoreProfile,
    ) -> Result<Self, StateError> {
        #[cfg(test)]
        let _test_open_permit = if open_admission_test_barrier_is_active() {
            None
        } else {
            Some(
                TEST_OPEN_CONCURRENCY
                    .acquire()
                    .await
                    .expect("test open concurrency semaphore remains live"),
            )
        };
        validate_config(&config)?;
        let close_retention = reserve_state_close_retention()?;
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
            .checked_div(5)
            .unwrap_or(Duration::ZERO)
            .min(Duration::from_millis(100));
        #[cfg(test)]
        let cleanup_budget = {
            let mut cleanup_budget = cleanup_budget;
            if let Ok(path) = resolve_database_path(&config.path)
                && let Some(configured) = OPEN_TEST_CLEANUP_BUDGET
                    .lock()
                    .expect("open test cleanup budget lock poisoned")
                    .remove(&path)
            {
                cleanup_budget = configured.min(config.open_timeout);
            }
            cleanup_budget
        };
        let cancel_at = deadline
            .checked_sub(cleanup_budget)
            .unwrap_or(tokio::time::Instant::now());
        #[cfg(test)]
        if let Ok(path) = resolve_database_path(&config.path)
            && let Some(observer) = OPEN_TEST_DEADLINE_OBSERVERS
                .lock()
                .expect("open test deadline observer lock poisoned")
                .remove(&path)
        {
            *observer
                .lock()
                .expect("open test deadline observation lock poisoned") =
                Some((cancel_at, deadline));
        }
        let deadline_state = Arc::new(OpenDeadlineState {
            work_cutoff: cancel_at.into_std(),
            deadline: deadline.into_std(),
            timeout_ms,
            operation: "state store open",
            busy_timeout: config.busy_timeout,
            expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            finished: std::sync::atomic::AtomicBool::new(false),
            final_commit_state: std::sync::atomic::AtomicU8::new(0),
            open_cleanup_state: std::sync::atomic::AtomicU8::new(0),
        });
        let open_admission = tokio::time::timeout_at(cancel_at, STATE_OPEN_ADMISSION.acquire())
            .await
            .map_err(|_| StateError::OperationTimedOut {
                operation: "state store open",
                timeout_ms,
            })?
            .map_err(|_| {
                database(
                    "acquire state open admission",
                    sqlx::Error::Protocol("state open admission is closed".to_owned()),
                )
            })?;
        #[cfg(test)]
        wait_at_open_admission_test_barrier().await;
        #[cfg(test)]
        let transaction_waiter = OpenTransactionWaiter::new();
        let transaction_admission =
            tokio::time::timeout_at(cancel_at, OPEN_TRANSACTION_ADMISSION.acquire())
                .await
                .map_err(|_| StateError::OperationTimedOut {
                    operation: "state store open",
                    timeout_ms,
                })?
                .map_err(|_| {
                    database(
                        "acquire open transaction admission",
                        sqlx::Error::Protocol("open transaction admission is closed".to_owned()),
                    )
                })?;
        #[cfg(test)]
        drop(transaction_waiter);
        let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel();
        let (delivery_ack_tx, delivery_ack_rx) = tokio::sync::oneshot::channel();
        let (terminal_tx, mut terminal_rx) = tokio::sync::oneshot::channel();
        let mut delivery_ack_tx = Some(delivery_ack_tx);
        let actor_runtime = OPEN_LIFECYCLE_RUNTIME.as_ref().map_err(|error| {
            database(
                "start state open lifecycle actor",
                sqlx::Error::Protocol(error.clone()),
            )
        })?;
        let actor_deadline_state = Arc::clone(&deadline_state);
        actor_runtime.spawn(async move {
            let result = run_open_lifecycle_actor(OpenLifecycleActorInput {
                config,
                profile,
                close_retention,
                open_admission,
                transaction_admission,
                deadline,
                deadline_state: actor_deadline_state,
                ready: ready_tx,
                delivery_ack: delivery_ack_rx,
            })
            .await;
            let _ = terminal_tx.send(result.map_err(|error| error.to_string()));
        });
        let mut cancellation_guard = OperationCancellationGuard::new(Arc::clone(&deadline_state));
        tokio::select! {
            ready = &mut ready_rx => {
                match ready {
                    Ok(Err(error)) => Err(error),
                    Ok(Ok(())) => {
                        if deadline_state
                            .cancelled
                            .load(std::sync::atomic::Ordering::Acquire)
                            || deadline_state
                                .expired
                                .load(std::sync::atomic::Ordering::Acquire)
                            || tokio::time::Instant::now() >= deadline
                        {
                            deadline_state
                                .expired
                                .store(true, std::sync::atomic::Ordering::Release);
                            deadline_state.cancel();
                            drop(delivery_ack_tx.take());
                            let error =
                                open_timeout_error(terminal_rx, deadline, &deadline_state, timeout_ms)
                                    .await;
                            cancellation_guard.disarm();
                            return Err(error);
                        }
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
                        let delivery = tokio::select! {
                            biased;
                            () = tokio::time::sleep_until(deadline) => {
                                deadline_state
                                    .expired
                                    .store(true, std::sync::atomic::Ordering::Release);
                                deadline_state.cancel();
                                let error = open_timeout_error(
                                    terminal_rx,
                                    deadline,
                                    &deadline_state,
                                    timeout_ms,
                                )
                                .await;
                                cancellation_guard.disarm();
                                return Err(error);
                            }
                            delivery = &mut terminal_rx => {
                                delivery
                                    .map_err(|_| {
                                        database(
                                            "receive state open actor terminal receipt",
                                            sqlx::Error::Protocol(
                                                "open lifecycle actor stopped without receipt"
                                                    .to_owned(),
                                            ),
                                        )
                                    })?
                                    .map_err(|cleanup| {
                                        database(
                                            "complete state open actor",
                                            sqlx::Error::Protocol(cleanup),
                                        )
                                    })?
                            }
                        };
                        if deadline_state
                            .cancelled
                            .load(std::sync::atomic::Ordering::Acquire)
                            || deadline_state
                                .expired
                                .load(std::sync::atomic::Ordering::Acquire)
                            || tokio::time::Instant::now() >= deadline
                        {
                            drop(delivery);
                            deadline_state
                                .expired
                                .store(true, std::sync::atomic::Ordering::Release);
                            deadline_state.cancel();
                            cancellation_guard.disarm();
                            return Err(deadline_state.timeout_error());
                        }
                        let store = match delivery {
                            OpenLifecycleTerminal::Delivery(delivery) => delivery.accept(),
                            OpenLifecycleTerminal::Cleaned => {
                                return Err(database(
                                    "deliver opened state store",
                                    sqlx::Error::Protocol(
                                        "open actor cleaned the store before delivery".to_owned(),
                                    ),
                                ));
                            }
                        };
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
                let error =
                    open_timeout_error(terminal_rx, deadline, &deadline_state, timeout_ms).await;
                cancellation_guard.disarm();
                Err(error)
            }
        }
    }

    async fn open_inner(
        config: StoreConfig,
        profile: StoreProfile,
        deadline_state: Arc<OpenDeadlineState>,
        close_retention: StateCloseRetentionReservation,
        transaction_admission: tokio::sync::SemaphorePermit<'static>,
    ) -> Result<Self, StateError> {
        let active_profile = match profile {
            StoreProfile::PortablePrivate => ActiveStoreProfile::PortablePrivate,
            #[cfg(target_os = "linux")]
            StoreProfile::LinuxProtected(spec) => {
                if config.max_connections != 1 {
                    return Err(StateError::InvalidValue {
                        field: "maximum connections",
                        reason: "LinuxProtected requires exactly one connection",
                    });
                }
                let namespace = ProtectedNamespace::open(&spec)?;
                if config.path != namespace.database_path() {
                    return Err(StateError::InvalidPath {
                        path: config.path.clone(),
                        reason: "LinuxProtected database path must be the fixed state.sqlite entry",
                    });
                }
                if spec.directory() != namespace.directory_path() {
                    return Err(StateError::InvalidPath {
                        path: config.path.clone(),
                        reason: "LinuxProtected directory identity changed during activation",
                    });
                }
                ActiveStoreProfile::LinuxProtected(namespace)
            }
        };
        let path = {
            #[cfg(target_os = "linux")]
            if let Some(namespace) = active_profile.protected_namespace() {
                namespace.database_path().to_owned()
            } else {
                resolve_database_path(&config.path)?
            }
            #[cfg(not(target_os = "linux"))]
            {
                resolve_database_path(&config.path)?
            }
        };
        let database_parent = {
            #[cfg(target_os = "linux")]
            if let Some(namespace) = active_profile.protected_namespace() {
                PinnedPrivateDirectory {
                    path: namespace.directory_path().to_owned(),
                    file: namespace.clone_parent()?,
                }
            } else {
                pin_private_directory(&path)?
            }
            #[cfg(not(target_os = "linux"))]
            {
                pin_private_directory(&path)?
            }
        };
        let database_parent_path = database_parent.path.clone();
        let creation_lock = if active_profile.is_protected() {
            None
        } else {
            acquire_creation_lock(&path)?
        };
        let database_file = {
            #[cfg(target_os = "linux")]
            if let Some(namespace) = active_profile.protected_namespace() {
                namespace.clone_database()?
            } else {
                open_database_file(&path)?
            }
            #[cfg(not(target_os = "linux"))]
            {
                open_database_file(&path)?
            }
        };
        let preflight_state = if active_profile.is_protected() {
            active_profile.verify_filesystem(
                (&database_parent_path, &database_parent.file),
                (&path, &database_file),
                (&path, &database_file),
                None,
                true,
            )?;
            #[cfg(target_os = "linux")]
            {
                InspectedDatabase::Existing { schema_version: 0 }
            }
            #[cfg(not(target_os = "linux"))]
            unreachable!("protected profiles are Linux-only")
        } else {
            reject_snapshot_staging_marker(&path, &database_file)?;
            validate_private_database_file(&path, &database_file)?;
            verify_path_identity(&path, &database_file)?;
            reject_hard_link(&path, &database_file)?;
            validate_preflight_sidecars(&path, &database_file)?;
            inspect_database(
                &path,
                &database_file,
                false,
                Some(Arc::clone(&deadline_state)),
            )
            .await?
        };
        prepare_windows_database_identity(&path)?;
        let allow_identity_initialization = (creation_lock.is_some()
            && matches!(preflight_state, InspectedDatabase::Fresh))
            || matches!(
                preflight_state,
                InspectedDatabase::Existing { schema_version: 0 }
            );
        let (lock_path, lock_file, process_identity) = {
            #[cfg(target_os = "linux")]
            if let Some(namespace) = active_profile.protected_namespace() {
                acquire_linux_protected_store_lock(namespace)?
            } else {
                acquire_store_lock(&path, &database_file, allow_identity_initialization)?
            }
            #[cfg(not(target_os = "linux"))]
            {
                acquire_store_lock(&path, &database_file, allow_identity_initialization)?
            }
        };
        if !deadline_state.retain_open_cleanup() {
            return Err(deadline_state.timeout_error());
        }
        drop(creation_lock);
        let lock_identity = if active_profile.is_protected() {
            None
        } else {
            capture_store_lock_identity(&path, &database_file, &lock_path, &lock_file)?
        };
        let owner = active_profile.writer_owner()?;
        let writer_generation = Arc::new(AtomicU64::new(1));
        let locked_state = if active_profile.is_protected() {
            active_profile.verify_filesystem(
                (&database_parent_path, &database_parent.file),
                (&path, &database_file),
                (&lock_path, &lock_file),
                None,
                true,
            )?;
            preflight_state
        } else {
            verify_path_identity(&path, &database_file)?;
            inspect_database(
                &path,
                &database_file,
                false,
                Some(Arc::clone(&deadline_state)),
            )
            .await?
        };

        let remaining = deadline_state
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(deadline_state.timeout_error());
        }
        let mut options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(config.busy_timeout.min(remaining))
            .synchronous(config.synchronous.sqlx());
        if active_profile.is_protected() {
            options = options
                .vfs("unix-excl")
                .locking_mode(SqliteLockingMode::Exclusive);
        }
        let configured_busy_timeout = config.busy_timeout;
        let verified_path = path.clone();
        let verified_parent_path = database_parent_path.clone();
        let verified_lock_path = lock_path.clone();
        let pool_identity_handles = Arc::new(std::sync::Mutex::new(Some(PoolIdentityHandles {
            parent: database_parent.file.try_clone().map_err(|error| {
                file_error("clone state directory handle", &database_parent_path, error)
            })?,
            database: database_file
                .try_clone()
                .map_err(|error| file_error("clone connection identity handle", &path, error))?,
            lock: lock_file
                .try_clone()
                .map_err(|error| file_error("clone writer lock handle", &lock_path, error))?,
        })));
        let pool_identity_guard = PoolIdentityHandleGuard {
            shared: Arc::clone(&pool_identity_handles),
        };
        let connect_identity_handles = Arc::clone(&pool_identity_handles);
        let verified_lock_identity = lock_identity.clone();
        let verified_writer_generation = Arc::clone(&writer_generation);
        let verified_profile = active_profile.clone();
        let connections_ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let connect_ready = Arc::clone(&connections_ready);
        let connect_deadline_state = Arc::clone(&deadline_state);
        let acquire_path = verified_path.clone();
        let acquire_parent_path = verified_parent_path.clone();
        let acquire_lock_path = verified_lock_path.clone();
        let acquire_identity_handles = Arc::clone(&pool_identity_handles);
        let acquire_lock_identity = verified_lock_identity.clone();
        let acquire_writer_generation = Arc::clone(&verified_writer_generation);
        let acquire_profile = active_profile.clone();
        let acquire_ready = Arc::clone(&connections_ready);
        let acquire_deadline_state = Arc::clone(&deadline_state);
        let live_acquire_timeout = config.acquire_timeout;
        let pool_max_connections = if active_profile.is_protected() {
            1
        } else {
            config.max_connections
        };
        let pool = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline_state.deadline),
            SqlitePoolOptions::new()
                .min_connections(1)
                .max_connections(pool_max_connections)
                .acquire_timeout(config.acquire_timeout)
                .after_connect(move |connection, _metadata| {
                    let path = verified_path.clone();
                    let parent_path = verified_parent_path.clone();
                    let lock_path = verified_lock_path.clone();
                    let identity_handles = Arc::clone(&connect_identity_handles);
                    let lock_identity = verified_lock_identity.clone();
                    let writer_generation = Arc::clone(&verified_writer_generation);
                    let profile = verified_profile.clone();
                    let ready = Arc::clone(&connect_ready);
                    let deadline_state = Arc::clone(&connect_deadline_state);
                    Box::pin(async move {
                        let (parent, file, lock_file) =
                            clone_pool_identity_handles(&identity_handles)
                                .map_err(|error| sqlx::Error::Configuration(Box::new(error)))?;
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
                        profile
                            .verify_filesystem(
                                (&parent_path, &parent),
                                (&path, &file),
                                (&lock_path, &lock_file),
                                lock_identity.as_deref(),
                                false,
                            )
                            .map_err(|error| sqlx::Error::Configuration(Box::new(error)))?;
                        profile.verify_connection(connection).await?;
                        if ready.load(std::sync::atomic::Ordering::Acquire) {
                            claw_sqlite_file_control::set_busy_timeout(
                                connection,
                                configured_busy_timeout,
                            )
                            .await
                            .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
                            profile
                                .secure_sidecars(&path, lock_identity.as_deref())
                                .map_err(|error| sqlx::Error::Configuration(Box::new(error)))?;
                            profile
                                .install_commit_guard(
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
                    let lock_path = acquire_lock_path.clone();
                    let identity_handles = Arc::clone(&acquire_identity_handles);
                    let lock_identity = acquire_lock_identity.clone();
                    let writer_generation = Arc::clone(&acquire_writer_generation);
                    let profile = acquire_profile.clone();
                    let ready = Arc::clone(&acquire_ready);
                    let deadline_state = Arc::clone(&acquire_deadline_state);
                    Box::pin(async move {
                        let (parent, file, lock_file) =
                            clone_pool_identity_handles(&identity_handles)
                                .map_err(|error| sqlx::Error::Configuration(Box::new(error)))?;
                        if writer_generation.load(Ordering::Acquire) != 1 {
                            return Err(sqlx::Error::Protocol(
                                "state writer generation is no longer live".to_owned(),
                            ));
                        }
                        if !deadline_state.permits_sqlite_work() {
                            return Err(sqlx::Error::Protocol(
                                "state store open deadline expired before cleanup admission"
                                    .to_owned(),
                            ));
                        }
                        let admission_deadline = if deadline_state
                            .finished
                            .load(std::sync::atomic::Ordering::Acquire)
                        {
                            std::time::Instant::now()
                                .checked_add(live_acquire_timeout)
                                .ok_or_else(|| {
                                    sqlx::Error::Protocol(
                                        "state connection acquire deadline overflowed".to_owned(),
                                    )
                                })?
                        } else {
                            deadline_state.deadline
                        };
                        ensure_state_cleanup_executor(tokio::time::Instant::from_std(
                            admission_deadline,
                        ))
                        .await
                        .map_err(sqlx::Error::Protocol)?;
                        let mut owners =
                            claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
                                "claw-state-before-acquire-identity",
                                1,
                                admission_deadline,
                            )
                            .await
                            .map_err(sqlx::Error::Protocol)?;
                        let owner = owners
                            .pop()
                            .expect("one before-acquire cleanup owner was reserved");
                        #[cfg(test)]
                        if OPEN_RESERVED_OWNER_PATHS
                            .lock()
                            .expect("reserved owner path set lock poisoned")
                            .remove(&path)
                        {
                            let barrier = BEFORE_ACQUIRE_OWNER_TEST_BARRIER
                                .lock()
                                .expect("before-acquire owner barrier lock poisoned")
                                .as_ref()
                                .map(|barrier| {
                                    (Arc::clone(&barrier.entered), Arc::clone(&barrier.releases))
                                });
                            if let Some((entered, releases)) = barrier {
                                entered.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                                loop {
                                    let available =
                                        releases.load(std::sync::atomic::Ordering::Acquire);
                                    if available > 0
                                        && releases
                                            .compare_exchange(
                                                available,
                                                available - 1,
                                                std::sync::atomic::Ordering::AcqRel,
                                                std::sync::atomic::Ordering::Acquire,
                                            )
                                            .is_ok()
                                    {
                                        break;
                                    }
                                    tokio::task::yield_now().await;
                                }
                            }
                        }
                        let verified = Arc::new(std::sync::Mutex::new(None));
                        let verifier_retired = StateOwnerRetirementReceipt::new();
                        struct IdentityVerificationPayload {
                            parent_path: PathBuf,
                            parent: Arc<File>,
                            path: PathBuf,
                            file: Arc<File>,
                            lock_path: PathBuf,
                            lock_file: Arc<File>,
                            lock_identity: Option<Vec<u8>>,
                            profile: ActiveStoreProfile,
                            ready: Arc<std::sync::atomic::AtomicBool>,
                            result: Arc<std::sync::Mutex<Option<Result<(), StateError>>>>,
                        }
                        handoff_state_payload_with_completion(
                            owner,
                            IdentityVerificationPayload {
                                parent_path,
                                parent,
                                path,
                                file,
                                lock_path,
                                lock_file,
                                lock_identity,
                                profile: profile.clone(),
                                ready,
                                result: Arc::clone(&verified),
                            },
                            verifier_retired.signal(),
                            |_, _, payload| {
                                let verified =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        payload.profile.verify_filesystem(
                                            (&payload.parent_path, &payload.parent),
                                            (&payload.path, &payload.file),
                                            (&payload.lock_path, &payload.lock_file),
                                            payload.lock_identity.as_deref(),
                                            payload
                                                .ready
                                                .load(std::sync::atomic::Ordering::Acquire),
                                        )
                                    }))
                                    .unwrap_or_else(
                                        |panic| {
                                            std::mem::forget(panic);
                                            Err(database(
                                                "verify before-acquire filesystem identity",
                                                sqlx::Error::Protocol(
                                                    "filesystem identity verification panicked"
                                                        .to_owned(),
                                                ),
                                            ))
                                        },
                                    );
                                *payload
                                    .result
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                    Some(verified);
                                #[cfg(test)]
                                if EARLY_VERIFIER_RETIRE_PATHS
                                    .lock()
                                    .expect("early verifier retire path set lock poisoned")
                                    .remove(&payload.path)
                                {
                                    let barrier = EARLY_VERIFIER_RETIRE_TEST_BARRIER
                                        .lock()
                                        .expect("early verifier retire barrier lock poisoned")
                                        .get(&payload.path)
                                        .map(|barrier| {
                                            (
                                                Arc::clone(&barrier.entered),
                                                Arc::clone(&barrier.release),
                                            )
                                        });
                                    if let Some((entered, release)) = barrier {
                                        entered.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                                        while !release.load(std::sync::atomic::Ordering::Acquire) {
                                            std::thread::yield_now();
                                        }
                                        EARLY_VERIFIER_RETIRE_TEST_BARRIER
                                            .lock()
                                            .expect("early verifier retire barrier lock poisoned")
                                            .remove(&payload.path);
                                    }
                                }
                            },
                        )
                        .map_err(sqlx::Error::Protocol)?;
                        verifier_retired
                            .wait(admission_deadline, "before-acquire identity verifier")
                            .await
                            .map_err(sqlx::Error::Protocol)?;
                        let verified = verified
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                            .ok_or_else(|| {
                                sqlx::Error::Protocol(
                                    "before-acquire identity owner retired without a result"
                                        .to_owned(),
                                )
                            })?;
                        verified.map_err(|error| sqlx::Error::Configuration(Box::new(error)))?;
                        profile.verify_connection(connection).await?;
                        Ok(true)
                    })
                })
                .connect_with(options),
        )
        .await
        .map_err(|_| deadline_state.timeout_error())?
        .map_err(|error| database("open state database", error))?;
        let pooled_identity = if active_profile.is_protected() {
            active_profile.verify_filesystem(
                (&database_parent_path, &database_parent.file),
                (&path, &database_file),
                (&lock_path, &lock_file),
                lock_identity.as_deref(),
                false,
            )
        } else {
            verify_path_identity(&path, &database_file)
        };
        if let Err(error) = pooled_identity {
            return Err(close_pool_after_open_failure(&pool, &deadline_state, error).await);
        }
        #[cfg(target_os = "linux")]
        let locked_state = if active_profile.is_protected() {
            let inspected = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline_state.work_cutoff),
                async {
                    let mut connection = pool.acquire().await.map_err(|error| {
                        database("acquire LinuxProtected inspection connection", error)
                    })?;
                    let inspected =
                        inspect_database_connection(&mut connection, &path, false).await;
                    drop(connection);
                    inspected
                },
            )
            .await
            .map_err(|_| deadline_state.timeout_error());
            match inspected {
                Ok(Ok(inspected)) => inspected,
                Ok(Err(error)) | Err(error) => {
                    return Err(close_pool_after_open_failure(&pool, &deadline_state, error).await);
                }
            }
        } else {
            locked_state
        };
        #[cfg(target_os = "linux")]
        if let Some(namespace) = active_profile.protected_namespace()
            && let Err(error) = namespace.recover_catalog(
                namespace.catalog_identity(1),
                Some(deadline_state.work_cutoff),
                Some(deadline_state.cancelled.as_ref()),
                deadline_state.timeout_ms,
            )
        {
            return Err(close_pool_after_open_failure(&pool, &deadline_state, error).await);
        }

        async fn initialize_connection_sidecars(
            connection: &mut PoolTransactionConnection,
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
                Ok::<(), sqlx::Error>(())
            }
            .await
        }

        let initial = match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline_state.work_cutoff),
            pool.acquire(),
        )
        .await
        {
            Ok(Ok(initial)) => initial,
            Ok(Err(error)) => {
                let primary = database("acquire initial state connection", error);
                return Err(close_pool_after_open_failure(&pool, &deadline_state, primary).await);
            }
            Err(_) => {
                let primary = deadline_state.timeout_error();
                return Err(close_pool_after_open_failure(&pool, &deadline_state, primary).await);
            }
        };
        let initial_busy_timeout = configured_busy_timeout;
        let mut initial =
            match claw_sqlite_file_control::begin_manual_pool_transaction_with_restore_deadlines(
                initial,
                deadline_state.work_cutoff,
                deadline_state.deadline,
                initial_busy_timeout,
                configured_busy_timeout,
                None,
            )
            .await
            {
                Ok(initial) => initial,
                Err(error) => {
                    let primary =
                        file_control_database("begin SQLite sidecar initialization", error);
                    return Err(
                        close_pool_after_open_failure(&pool, &deadline_state, primary).await,
                    );
                }
            };
        if let Err(error) = initialize_connection_sidecars(&mut initial).await {
            let primary = database("initialize SQLite sidecars", error);
            let rollback = initial.rollback().await;
            let primary = match rollback {
                Ok(_) => primary,
                Err(cleanup) => StateError::OperationCleanupFailed {
                    operation: "initialize SQLite sidecars",
                    primary: Box::new(primary),
                    cleanup: cleanup.to_string(),
                },
            };
            return Err(close_pool_after_open_failure(&pool, &deadline_state, primary).await);
        }
        let initialized = async {
            let (mut initial, post_commit_owner) = initial
                .commit_with_deadline(
                    deadline_state.work_cutoff,
                    deadline_state.deadline,
                    Arc::clone(&deadline_state.cancelled),
                    initial_busy_timeout,
                    None,
                )
                .await
                .map_err(|error| {
                    file_control_database("commit SQLite sidecar initialization", error)
                })?;
            active_profile.secure_sidecars(&path, lock_identity.as_deref())?;
            active_profile
                .install_commit_guard(
                    &mut initial,
                    (&database_parent_path, &database_parent.file),
                    (&path, &database_file),
                    (&lock_path, &lock_file),
                    lock_identity.as_deref(),
                    (Arc::clone(&writer_generation), 1),
                )
                .await
                .map_err(|error| database("install initial commit guard", error))?;
            drop(initial);
            post_commit_owner.shutdown().map_err(|error| {
                database(
                    "release initial post-COMMIT cleanup owner",
                    sqlx::Error::Protocol(error),
                )
            })
        }
        .await;
        if let Err(error) = initialized {
            return Err(close_pool_after_open_failure(&pool, &deadline_state, error).await);
        }
        #[cfg(test)]
        wait_at_open_initialization_test_barrier(&path).await;

        let configured = async {
            let mut configured_connection = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline_state.work_cutoff),
                pool.acquire(),
            )
            .await
            .map_err(|_| deadline_state.timeout_error())?
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
            active_profile.secure_sidecars(&path, lock_identity.as_deref())?;
            active_profile
                .install_commit_guard(
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
            return Err(close_pool_after_open_failure(&pool, &deadline_state, error).await);
        }
        let initialized = match initialize_database(
            &pool,
            &path,
            locked_state,
            &owner,
            Arc::clone(&deadline_state),
            transaction_admission,
        )
        .await
        {
            Ok(initialized) => initialized,
            Err(error) => {
                return Err(close_pool_after_open_failure(&pool, &deadline_state, error).await);
            }
        };
        if active_profile.is_protected()
            && let Err(error) = active_profile
                .secure_sidecars(&path, lock_identity.as_deref())
                .and_then(|()| {
                    active_profile.verify_filesystem(
                        (&database_parent_path, &database_parent.file),
                        (&path, &database_file),
                        (&lock_path, &lock_file),
                        lock_identity.as_deref(),
                        true,
                    )
                })
        {
            return Err(close_pool_after_open_failure(&pool, &deadline_state, error).await);
        }
        #[cfg(target_os = "linux")]
        if let Some(namespace) = active_profile.protected_namespace()
            && let Err(error) = namespace.recover_catalog(
                namespace.catalog_identity(1),
                Some(deadline_state.work_cutoff),
                Some(deadline_state.cancelled.as_ref()),
                deadline_state.timeout_ms,
            )
        {
            return Err(close_pool_after_open_failure(&pool, &deadline_state, error).await);
        }
        connections_ready.store(true, std::sync::atomic::Ordering::Release);
        Ok(Self {
            path,
            database_parent_path,
            lock_path,
            owner,
            recovered_writer: initialized.recovered_writer,
            lock_identity,
            ownership: Some(StateStoreOwnership {
                pool,
                lock_file,
                process_identity,
                database_file,
                database_parent: database_parent.file,
                close_retention,
                pool_identity_handles: pool_identity_guard,
                profile: active_profile.clone(),
            }),
            writer_generation,
            max_connections: pool_max_connections,
            operation_timeout: config.operation_timeout,
            busy_timeout: config.busy_timeout,
            close_timeout: config.close_timeout,
            undelivered_cleanup_owner: Some(initialized.undelivered_cleanup_owner),
            open_transaction_admission: Some(initialized.open_transaction_admission),
            profile: active_profile,
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

    /// Returns the active state security profile.
    #[must_use]
    pub const fn profile(&self) -> StateProfile {
        if self.profile.is_protected() {
            StateProfile::LinuxProtected
        } else {
            StateProfile::PortablePrivate
        }
    }

    fn ownership(&self) -> &StateStoreOwnership {
        self.ownership
            .as_ref()
            .expect("live state store retains ownership")
    }

    fn pool(&self) -> &SqlitePool {
        &self.ownership().pool
    }

    /// Returns the session repository.
    #[must_use]
    pub fn sessions(&self) -> SessionRepository<'_> {
        SessionRepository::new(self.pool(), &self.owner, self.operational_identity())
    }

    /// Returns the device repository.
    #[must_use]
    pub fn devices(&self) -> DeviceRepository<'_> {
        DeviceRepository::new(self.pool(), &self.owner, self.operational_identity())
    }

    /// Returns the authentication repository.
    #[must_use]
    pub fn authentications(&self) -> AuthenticationRepository<'_> {
        AuthenticationRepository::new(self.pool(), &self.owner, self.operational_identity())
    }

    /// Returns the task repository.
    #[must_use]
    pub fn tasks(&self) -> TaskRepository<'_> {
        TaskRepository::new(self.pool(), &self.owner, self.operational_identity())
    }

    fn operational_identity(&self) -> OperationalIdentity<'_> {
        let ownership = self.ownership();
        OperationalIdentity {
            database_parent_path: &self.database_parent_path,
            database_parent: &ownership.database_parent,
            database_path: &self.path,
            database_file: &ownership.database_file,
            lock_path: &self.lock_path,
            lock_file: &ownership.lock_file,
            lock_identity: self.lock_identity.as_deref(),
            writer_generation: &self.writer_generation,
            profile: &self.profile,
            busy_timeout: self.busy_timeout,
            operation_timeout: self.operation_timeout,
            cleanup_timeout: self.close_timeout,
        }
    }

    /// Reads the effective connection and durability settings.
    pub async fn settings(&self) -> Result<StoreSettings, StateError> {
        let mut operation = StoreOperationConnection::acquire(
            self.pool(),
            self.operational_identity(),
            "inspect SQLite settings",
        )
        .await?;
        let row = deadline_first(
            operation.deadline,
            sqlx::query(
                "SELECT
                    (SELECT journal_mode FROM pragma_journal_mode) AS journal_mode,
                    (SELECT foreign_keys FROM pragma_foreign_keys) AS foreign_keys,
                    (SELECT timeout FROM pragma_busy_timeout) AS busy_timeout_ms,
                    (SELECT synchronous FROM pragma_synchronous) AS synchronous",
            )
            .fetch_one(&mut *operation.sqlite()),
        )
        .await;
        let row = match row {
            Ok(Ok(row)) => row,
            Ok(Err(error)) => {
                let primary = if tokio::time::Instant::now() >= operation.deadline {
                    operation.expire()
                } else {
                    database("inspect SQLite settings", error)
                };
                return Err(operation.fail(primary).await);
            }
            Err(_) => {
                let primary = operation.expire();
                return Err(operation.fail(primary).await);
            }
        };
        let settings = StoreSettings {
            journal_mode: row.get("journal_mode"),
            foreign_keys: row.get::<i64, _>("foreign_keys") == 1,
            busy_timeout_ms: row.get("busy_timeout_ms"),
            synchronous: row.get("synchronous"),
            max_connections: self.max_connections,
        };
        operation.finish().await?;
        Ok(settings)
    }

    /// Creates a same-version, transactionally consistent snapshot sealed to
    /// the current machine and service identity.
    pub async fn backup_to(&self, destination: impl AsRef<Path>) -> Result<(), StateError> {
        if self.profile.is_protected() {
            return Err(StateError::InvalidValue {
                field: "state profile operation",
                reason: "arbitrary-path snapshot publication is unavailable for LinuxProtected",
            });
        }
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
        let mut preflight_owners = claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
            "claw-state-backup-entry-preflight",
            1,
            deadline.into_std(),
        )
        .await
        .map_err(|error| {
            if tokio::time::Instant::now() >= deadline {
                StateError::OperationTimedOut {
                    operation: "SQLite backup",
                    timeout_ms,
                }
            } else {
                database(
                    "reserve backup entry preflight owner",
                    sqlx::Error::Protocol(error),
                )
            }
        })?;
        let preflight_owner = preflight_owners
            .pop()
            .expect("backup entry preflight owner");
        let requested_destination = destination.as_ref().to_owned();
        let destination = run_bounded_filesystem(
            preflight_owner,
            deadline,
            "SQLite backup",
            timeout_ms,
            move || {
                ensure_database_artifacts_absent(&requested_destination)?;
                resolve_database_path(&requested_destination)
            },
        )
        .await?;
        let expected_version = tokio::time::timeout_at(deadline, schema_version(self.pool()))
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
        let logical_bytes = tokio::time::timeout_at(
            deadline,
            sqlx::query_scalar::<_, i64>(
                "SELECT page_count * page_size
                 FROM pragma_page_count, pragma_page_size",
            )
            .fetch_one(self.pool()),
        )
        .await
        .map_err(|_| StateError::OperationTimedOut {
            operation: "SQLite backup",
            timeout_ms,
        })?
        .map_err(|error| database("measure backup source size", error))?;
        if logical_bytes < 0
            || u64::try_from(logical_bytes).unwrap_or(u64::MAX) > MAX_AUTHENTICATED_SNAPSHOT_BYTES
        {
            return Err(StateError::InvalidBackup {
                path: self.path.clone(),
                reason: format!(
                    "backup source exceeds {} bytes",
                    MAX_AUTHENTICATED_SNAPSHOT_BYTES
                ),
            });
        }
        backup_pool(
            self.pool(),
            &destination,
            BackupValidationMode::LatestSource,
            deadline,
            timeout_ms,
            Some(self.operational_identity()),
        )
        .await
    }

    /// Publishes a validated snapshot into the fixed LinuxProtected catalog.
    ///
    /// No destination path is accepted or returned. PortablePrivate stores
    /// return [`crate::StateErrorKind::UnsupportedProfileOperation`].
    pub async fn publish_protected_snapshot(&self) -> Result<ProtectedSnapshotReceipt, StateError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(StateError::InvalidValue {
                field: "state profile operation",
                reason: "fixed-catalog snapshot publication requires LinuxProtected",
            })
        }
        #[cfg(target_os = "linux")]
        {
            self.publish_linux_protected_snapshot().await
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn publish_linux_protected_snapshot(
        &self,
    ) -> Result<ProtectedSnapshotReceipt, StateError> {
        let namespace =
            self.profile
                .protected_namespace()
                .cloned()
                .ok_or(StateError::InvalidValue {
                    field: "state profile operation",
                    reason: "fixed-catalog snapshot publication requires LinuxProtected",
                })?;
        let timeout_ms = u64::try_from(self.operation_timeout.as_millis()).map_err(|_| {
            StateError::InvalidValue {
                field: "LinuxProtected snapshot timeout",
                reason: "must fit in milliseconds",
            }
        })?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.operation_timeout)
            .ok_or(StateError::InvalidValue {
                field: "LinuxProtected snapshot timeout",
                reason: "is too large for the monotonic clock",
            })?;
        let cleanup_deadline = deadline
            .checked_add(self.close_timeout.max(Duration::from_secs(5)))
            .ok_or(StateError::InvalidValue {
                field: "LinuxProtected snapshot cleanup timeout",
                reason: "is too large for the monotonic clock",
            })?;
        let deadline_state = Arc::new(OpenDeadlineState {
            work_cutoff: deadline.into_std(),
            deadline: cleanup_deadline.into_std(),
            timeout_ms,
            operation: "LinuxProtected snapshot publication",
            busy_timeout: self.busy_timeout,
            expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            finished: std::sync::atomic::AtomicBool::new(false),
            final_commit_state: std::sync::atomic::AtomicU8::new(0),
            open_cleanup_state: std::sync::atomic::AtomicU8::new(0),
        });
        let mut cancellation_guard = OperationCancellationGuard::new(Arc::clone(&deadline_state));
        let publication =
            tokio::time::timeout_at(deadline, namespace.publication_gate().lock_owned())
                .await
                .map_err(|_| StateError::OperationTimedOut {
                    operation: "LinuxProtected snapshot publication",
                    timeout_ms,
                })?;
        self.operational_identity().verify()?;
        let writer_generation = self.writer_generation.load(Ordering::Acquire);
        if writer_generation != 1 {
            return Err(StateError::InvalidPath {
                path: self.path.clone(),
                reason: "LinuxProtected writer generation is no longer live",
            });
        }
        let catalog_identity = namespace.catalog_identity(writer_generation);

        let snapshot_memory =
            reserve_snapshot_memory(deadline, "LinuxProtected snapshot publication", timeout_ms)
                .await?;
        let admission = tokio::time::timeout_at(deadline, BACKUP_CLEANUP_ADMISSION.acquire())
            .await
            .map_err(|_| StateError::OperationTimedOut {
                operation: "LinuxProtected snapshot publication",
                timeout_ms,
            })?
            .map_err(|_| {
                database(
                    "acquire LinuxProtected snapshot cleanup admission",
                    sqlx::Error::Protocol("snapshot cleanup admission closed".to_owned()),
                )
            })?;
        let mut owners = claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
            "claw-state-linux-protected-snapshot",
            8,
            deadline.into_std(),
        )
        .await
        .map_err(|error| {
            if tokio::time::Instant::now() >= deadline {
                StateError::OperationTimedOut {
                    operation: "LinuxProtected snapshot publication",
                    timeout_ms,
                }
            } else {
                database(
                    "reserve LinuxProtected snapshot owners",
                    sqlx::Error::Protocol(error),
                )
            }
        })?;
        let prepare_owner = owners.pop().expect("catalog prepare owner was reserved");

        let prepare_namespace = Arc::clone(&namespace);
        let prepare_cancelled = Arc::clone(&deadline_state.cancelled);
        let mut preparation = Some((publication, snapshot_memory, admission, owners));
        let (plan, publication, snapshot_memory, admission, mut owners) = run_bounded_filesystem(
            prepare_owner,
            deadline,
            "LinuxProtected snapshot publication",
            timeout_ms,
            move || {
                let (publication, snapshot_memory, admission, owners) = preparation
                    .take()
                    .expect("catalog preparation consumes its retained resources once");
                let current = prepare_namespace.recover_catalog(
                    catalog_identity,
                    Some(deadline.into_std()),
                    Some(prepare_cancelled.as_ref()),
                    timeout_ms,
                )?;
                let plan = prepare_namespace.publication_plan(current)?;
                prepare_namespace.scrub_slot(plan.slot)?;
                Ok((plan, publication, snapshot_memory, admission, owners))
            },
        )
        .await?;
        let selector_owner = owners.pop().expect("selector owner was reserved");
        let metadata_owner = owners.pop().expect("metadata owner was reserved");
        let scrub_owner = owners.pop().expect("slot scrub owner was reserved");
        let finalization_owner = owners.pop().expect("finalization owner was reserved");
        let destination_cleanup_owner = owners
            .pop()
            .expect("destination cleanup owner was reserved");
        let source_cleanup_owner = owners.pop().expect("source cleanup owner was reserved");
        let backup_worker_owner = owners.pop().expect("backup worker owner was reserved");
        debug_assert!(owners.is_empty());
        #[cfg(test)]
        if take_protected_snapshot_test_failure(&self.path, 1) {
            deadline_state.cancel();
            return Err(StateError::OperationTimedOut {
                operation: "LinuxProtected snapshot publication",
                timeout_ms,
            });
        }

        let source = tokio::time::timeout_at(deadline, self.pool().acquire())
            .await
            .map_err(|_| StateError::OperationTimedOut {
                operation: "LinuxProtected snapshot publication",
                timeout_ms,
            })?
            .map_err(|error| database("acquire LinuxProtected snapshot source", error))?;
        let destination = tokio::time::timeout_at(
            deadline,
            SqliteConnection::connect_with(
                &SqliteConnectOptions::new()
                    .in_memory(true)
                    .journal_mode(SqliteJournalMode::Off),
            ),
        )
        .await
        .map_err(|_| StateError::OperationTimedOut {
            operation: "LinuxProtected snapshot publication",
            timeout_ms,
        })?
        .map_err(|error| database("open LinuxProtected in-memory snapshot", error))?;
        let mut source = source;
        let max_pages = bounded_backup_max_pages(&mut source).await?;
        let backup = claw_sqlite_file_control::backup_owned_main_database_with_cleanup_deadline(
            backup_worker_owner,
            source,
            destination,
            (snapshot_memory, admission),
            claw_sqlite_file_control::BackupExecutionContext {
                deadline: deadline.into_std(),
                cancelled: Arc::clone(&deadline_state.cancelled),
                max_pages,
                source_busy_timeout: self.busy_timeout,
                destination_busy_timeout: Duration::ZERO,
            },
            cleanup_deadline.into_std(),
        )
        .await;
        let (source, destination, reservations) = match backup {
            Ok(backup) => backup,
            Err(error) => {
                let namespace = Arc::clone(&namespace);
                let cleanup = run_bounded_filesystem(
                    scrub_owner,
                    cleanup_deadline,
                    "LinuxProtected snapshot cleanup",
                    timeout_ms,
                    move || namespace.scrub_slot(plan.slot),
                )
                .await;
                let primary = file_control_database("copy LinuxProtected logical snapshot", error);
                return Err(match cleanup {
                    Ok(()) => primary,
                    Err(cleanup) => append_operation_cleanup(
                        "LinuxProtected snapshot publication",
                        primary,
                        cleanup.to_string(),
                    ),
                });
            }
        };
        let mut lease = ProtectedSnapshotCleanupLease {
            namespace: Arc::clone(&namespace),
            slot: plan.slot,
            cleanup_deadline,
            cleanup_owner: Some(scrub_owner),
            retention: Arc::new(std::sync::Mutex::new(Some(ProtectedSnapshotRetention {
                _memory: reservations.0,
                _admission: reservations.1,
                _publication: publication,
            }))),
            armed: true,
        };
        let mut source = BackupConnectionGuard::new_cancellable(
            source,
            Arc::clone(&deadline_state),
            source_cleanup_owner,
        );
        let mut destination = OwnedSqliteConnectionGuard::new_cancellable_with_owner(
            destination,
            Some(Arc::clone(&deadline_state)),
            destination_cleanup_owner,
        );
        if let Err(primary) =
            install_open_deadline_handler(&mut destination, Some(Arc::clone(&deadline_state))).await
        {
            let primary = discard_backup_connections_or_error(source, destination, primary).await;
            return Err(match lease.cleanup_slot().await {
                Ok(()) => primary,
                Err(cleanup) => append_operation_cleanup(
                    "LinuxProtected snapshot publication",
                    primary,
                    cleanup.to_string(),
                ),
            });
        }
        if let Err(primary) = validate_backup_connection(
            namespace.slot_path(plan.slot),
            &mut destination,
            BackupValidationMode::LatestSource,
        )
        .await
        {
            let primary = discard_backup_connections_or_error(source, destination, primary).await;
            return Err(match lease.cleanup_slot().await {
                Ok(()) => primary,
                Err(cleanup) => append_operation_cleanup(
                    "LinuxProtected snapshot publication",
                    primary,
                    cleanup.to_string(),
                ),
            });
        }
        let output = match namespace.clone_slot(plan.slot) {
            Ok(output) => output,
            Err(primary) => {
                let primary =
                    discard_backup_connections_or_error(source, destination, primary).await;
                return Err(match lease.cleanup_slot().await {
                    Ok(()) => primary,
                    Err(cleanup) => append_operation_cleanup(
                        "LinuxProtected snapshot publication",
                        primary,
                        cleanup.to_string(),
                    ),
                });
            }
        };
        let (destination, destination_owner) = destination.release_connection();
        if let Err(cleanup) = destination_owner.shutdown() {
            let close = source.discard().await;
            let primary = append_operation_cleanup(
                "LinuxProtected snapshot publication",
                database(
                    "release LinuxProtected destination cleanup owner",
                    sqlx::Error::Protocol(cleanup),
                ),
                format!("source terminal close: {close:?}"),
            );
            return Err(match lease.cleanup_slot().await {
                Ok(()) => primary,
                Err(cleanup) => append_operation_cleanup(
                    "LinuxProtected snapshot publication",
                    primary,
                    cleanup.to_string(),
                ),
            });
        }
        let finalized = claw_sqlite_file_control::finalize_owned_snapshot(
            finalization_owner,
            destination,
            output,
            lease,
            claw_sqlite_file_control::SnapshotFinalizeContext {
                output_path: namespace
                    .slot_path(plan.slot)
                    .to_string_lossy()
                    .into_owned(),
                deadline: deadline.into_std(),
                cancelled: Arc::clone(&deadline_state.cancelled),
                maximum_bytes: usize::try_from(protected_catalog::MAX_SNAPSHOT_BYTES)
                    .expect("snapshot size cap fits usize"),
            },
        )
        .await;
        let (write_receipt, mut lease) = match finalized {
            Ok(finalized) => finalized,
            Err(error) => {
                let close = source.discard().await;
                let primary = file_control_database("finalize LinuxProtected held snapshot", error);
                return Err(
                    if close == claw_sqlite_file_control::TerminalCloseOutcome::Closed {
                        primary
                    } else {
                        append_operation_cleanup(
                            "LinuxProtected snapshot publication",
                            primary,
                            format!("source terminal close: {close:?}"),
                        )
                    },
                );
            }
        };
        let source_identity = self
            .profile
            .verify_connection(&mut source)
            .await
            .map_err(|error| database("reverify LinuxProtected snapshot source connection", error))
            .and_then(|()| self.operational_identity().verify());
        if let Err(primary) = source_identity {
            let close = source.discard().await;
            let primary = if close == claw_sqlite_file_control::TerminalCloseOutcome::Closed {
                primary
            } else {
                append_operation_cleanup(
                    "LinuxProtected snapshot publication",
                    primary,
                    format!("source terminal close: {close:?}"),
                )
            };
            return Err(match lease.cleanup_slot().await {
                Ok(()) => primary,
                Err(cleanup) => append_operation_cleanup(
                    "LinuxProtected snapshot publication",
                    primary,
                    cleanup.to_string(),
                ),
            });
        }
        if let Err(primary) = source.release_reusable() {
            return Err(match lease.cleanup_slot().await {
                Ok(()) => primary,
                Err(cleanup) => append_operation_cleanup(
                    "LinuxProtected snapshot publication",
                    primary,
                    cleanup.to_string(),
                ),
            });
        }
        #[cfg(test)]
        wait_at_protected_snapshot_test_gate(&self.path, 4, plan.slot, deadline).await;

        let observation = SlotObservation {
            byte_length: write_receipt.byte_count,
            digest: write_receipt.digest,
        };
        let metadata = protected_catalog::encode_metadata(SnapshotMetadata {
            slot: plan.slot,
            generation: plan.generation,
            identity: catalog_identity,
            byte_length: write_receipt.byte_count,
            digest: write_receipt.digest,
        });
        let selector = protected_catalog::encode_selector_cell(SelectorCell {
            cell: plan.selector_cell,
            slot: plan.slot,
            generation: plan.generation,
            metadata_digest: protected_catalog::digest(&metadata),
        });
        let metadata_namespace = Arc::clone(&namespace);
        let metadata_cancelled = Arc::clone(&deadline_state.cancelled);
        let mut metadata_lease = Some(lease);
        let mut lease = run_bounded_filesystem(
            metadata_owner,
            deadline,
            "LinuxProtected snapshot publication",
            timeout_ms,
            move || {
                let lease = metadata_lease
                    .take()
                    .expect("metadata worker consumes the cleanup lease once");
                let result = (|| {
                    metadata_namespace.verify_slot(
                        plan.slot,
                        observation,
                        Some(deadline.into_std()),
                        Some(metadata_cancelled.as_ref()),
                        timeout_ms,
                    )?;
                    metadata_namespace.write_metadata(plan.slot, &metadata)?;
                    metadata_namespace.verify()
                })();
                match result {
                    Ok(()) => Ok(lease),
                    Err(error) => Err(error),
                }
            },
        )
        .await?;
        #[cfg(test)]
        if take_protected_snapshot_test_failure(&self.path, 2) {
            namespace.fail_next_scrub();
            let primary = database(
                "inject LinuxProtected metadata failure",
                sqlx::Error::Protocol("injected pre-selector metadata failure".to_owned()),
            );
            return Err(match lease.cleanup_slot().await {
                Ok(()) => primary,
                Err(cleanup) => append_operation_cleanup(
                    "LinuxProtected snapshot publication",
                    primary,
                    cleanup.to_string(),
                ),
            });
        }
        if tokio::time::Instant::now() >= deadline
            || deadline_state
                .cancelled
                .load(std::sync::atomic::Ordering::Acquire)
        {
            let primary = StateError::OperationTimedOut {
                operation: "LinuxProtected snapshot publication",
                timeout_ms,
            };
            return Err(match lease.cleanup_slot().await {
                Ok(()) => primary,
                Err(cleanup) => append_operation_cleanup(
                    "LinuxProtected snapshot publication",
                    primary,
                    cleanup.to_string(),
                ),
            });
        }

        let commit_state = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let worker_state = Arc::clone(&commit_state);
        let selector_namespace = Arc::clone(&namespace);
        let selector_cancelled = Arc::clone(&deadline_state.cancelled);
        let selector_path = namespace.selector_path().to_owned();
        #[cfg(test)]
        let inject_uncertainty = take_protected_snapshot_test_failure(&self.path, 3);
        #[cfg(not(test))]
        let inject_uncertainty = false;
        let mut lease = Some(lease);
        let selector_result = run_bounded_filesystem_with_acceptance(
            selector_owner,
            cleanup_deadline,
            deadline,
            "LinuxProtected snapshot publication",
            timeout_ms,
            move || {
                let mut lease = lease
                    .take()
                    .expect("selector worker consumes the cleanup lease once");
                if selector_cancelled.load(std::sync::atomic::Ordering::Acquire)
                    || std::time::Instant::now() >= deadline.into_std()
                {
                    if let Err(error) = selector_namespace.scrub_slot(plan.slot) {
                        worker_state.store(3, std::sync::atomic::Ordering::Release);
                        return Err(error);
                    }
                    let release = lease.disarm_without_scrub();
                    worker_state.store(3, std::sync::atomic::Ordering::Release);
                    release.map_err(|cleanup| {
                        database(
                            "release precommit LinuxProtected cleanup owner",
                            sqlx::Error::Protocol(cleanup),
                        )
                    })?;
                    return Err(StateError::OperationTimedOut {
                        operation: "LinuxProtected snapshot publication",
                        timeout_ms,
                    });
                }
                if let Err(cleanup) = lease.disarm_without_scrub() {
                    let primary = database(
                        "release LinuxProtected snapshot scrub owner",
                        sqlx::Error::Protocol(cleanup),
                    );
                    worker_state.store(3, std::sync::atomic::Ordering::Release);
                    return match selector_namespace.scrub_slot(plan.slot) {
                        Ok(()) => Err(primary),
                        Err(scrub) => Err(append_operation_cleanup(
                            "LinuxProtected snapshot publication",
                            primary,
                            scrub.to_string(),
                        )),
                    };
                }
                worker_state.store(1, std::sync::atomic::Ordering::Release);
                if let Err(error) =
                    selector_namespace.commit_selector_cell(plan.selector_cell, &selector)
                {
                    return Err(StateError::PublicationUncertain {
                        path: selector_namespace.selector_path().to_owned(),
                        reason: format!("selector commit may be partial: {error}"),
                    });
                }
                if inject_uncertainty {
                    return Err(StateError::PublicationUncertain {
                        path: selector_namespace.selector_path().to_owned(),
                        reason: "injected uncertainty after durable selector commit".to_owned(),
                    });
                }
                let recovered = selector_namespace
                    .recover_catalog(
                        catalog_identity,
                        Some(deadline.into_std()),
                        Some(selector_cancelled.as_ref()),
                        timeout_ms,
                    )
                    .map_err(|error| StateError::PublicationUncertain {
                        path: selector_namespace.selector_path().to_owned(),
                        reason: format!("committed selector failed recovery verification: {error}"),
                    })?
                    .ok_or_else(|| StateError::PublicationUncertain {
                        path: selector_namespace.selector_path().to_owned(),
                        reason: "committed selector recovered no generation".to_owned(),
                    })?;
                if recovered.metadata.generation != plan.generation
                    || recovered.metadata.slot != plan.slot
                    || recovered.metadata.byte_length != observation.byte_length
                    || recovered.metadata.digest != observation.digest
                    || selector_cancelled.load(std::sync::atomic::Ordering::Acquire)
                    || std::time::Instant::now() >= deadline.into_std()
                {
                    return Err(StateError::PublicationUncertain {
                        path: selector_namespace.selector_path().to_owned(),
                        reason: "committed selector failed final generation, identity, or cutoff verification"
                            .to_owned(),
                    });
                }
                worker_state.store(2, std::sync::atomic::Ordering::Release);
                Ok(protected_snapshot_receipt(recovered))
            },
        )
        .await;
        match selector_result {
            Ok(receipt) => {
                cancellation_guard.disarm();
                deadline_state
                    .finished
                    .store(true, std::sync::atomic::Ordering::Release);
                Ok(receipt)
            }
            Err(error)
                if commit_state.load(std::sync::atomic::Ordering::Acquire) == 3
                    && !matches!(error, StateError::PublicationUncertain { .. }) =>
            {
                cancellation_guard.disarm();
                Err(error)
            }
            Err(error @ StateError::PublicationUncertain { .. }) => {
                cancellation_guard.disarm();
                Err(error)
            }
            Err(error) => {
                deadline_state.cancel();
                cancellation_guard.disarm();
                Err(StateError::PublicationUncertain {
                    path: selector_path,
                    reason: format!(
                        "selector worker stopped after publication became possible: {error}"
                    ),
                })
            }
        }
    }

    /// Returns the latest validated receipt from the fixed LinuxProtected catalog.
    ///
    /// The returned immutable value contains no pathname. An empty catalog
    /// returns `Ok(None)`. PortablePrivate stores return
    /// [`crate::StateErrorKind::UnsupportedProfileOperation`].
    pub async fn latest_protected_snapshot_receipt(
        &self,
    ) -> Result<Option<ProtectedSnapshotReceipt>, StateError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(StateError::InvalidValue {
                field: "state profile operation",
                reason: "latest fixed-catalog receipt requires LinuxProtected",
            })
        }
        #[cfg(target_os = "linux")]
        {
            let namespace =
                self.profile
                    .protected_namespace()
                    .cloned()
                    .ok_or(StateError::InvalidValue {
                        field: "state profile operation",
                        reason: "latest fixed-catalog receipt requires LinuxProtected",
                    })?;
            let timeout_ms = u64::try_from(self.operation_timeout.as_millis()).map_err(|_| {
                StateError::InvalidValue {
                    field: "LinuxProtected snapshot receipt timeout",
                    reason: "must fit in milliseconds",
                }
            })?;
            let deadline = tokio::time::Instant::now()
                .checked_add(self.operation_timeout)
                .ok_or(StateError::InvalidValue {
                    field: "LinuxProtected snapshot receipt timeout",
                    reason: "is too large for the monotonic clock",
                })?;
            let _publication =
                tokio::time::timeout_at(deadline, namespace.publication_gate().lock_owned())
                    .await
                    .map_err(|_| StateError::OperationTimedOut {
                        operation: "read latest LinuxProtected snapshot receipt",
                        timeout_ms,
                    })?;
            self.operational_identity().verify()?;
            let writer_generation = self.writer_generation.load(Ordering::Acquire);
            if writer_generation != 1 {
                return Err(StateError::InvalidPath {
                    path: self.path.clone(),
                    reason: "LinuxProtected writer generation is no longer live",
                });
            }
            let identity = namespace.catalog_identity(writer_generation);
            let final_identity = self.operational_identity().capture_owned()?;
            let final_writer_generation = Arc::clone(&self.writer_generation);
            if tokio::time::Instant::now() >= deadline {
                return Err(StateError::OperationTimedOut {
                    operation: "read latest LinuxProtected snapshot receipt",
                    timeout_ms,
                });
            }
            let mut owners = claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
                "claw-state-linux-protected-latest-receipt",
                1,
                deadline.into_std(),
            )
            .await
            .map_err(|error| {
                if tokio::time::Instant::now() >= deadline {
                    StateError::OperationTimedOut {
                        operation: "read latest LinuxProtected snapshot receipt",
                        timeout_ms,
                    }
                } else {
                    database(
                        "reserve latest LinuxProtected receipt owner",
                        sqlx::Error::Protocol(error),
                    )
                }
            })?;
            let owner = owners.pop().expect("latest receipt owner was reserved");
            let receipt_namespace = Arc::clone(&namespace);
            let recovered = run_bounded_filesystem(
                owner,
                deadline,
                "read latest LinuxProtected snapshot receipt",
                timeout_ms,
                move || {
                    let recovered = receipt_namespace.recover_catalog(
                        identity,
                        Some(deadline.into_std()),
                        None,
                        timeout_ms,
                    )?;
                    final_identity.verify()?;
                    if final_writer_generation.load(Ordering::Acquire) != 1 {
                        return Err(StateError::InvalidPath {
                            path: receipt_namespace.database_path().to_owned(),
                            reason: "LinuxProtected writer generation is no longer live",
                        });
                    }
                    if std::time::Instant::now() >= deadline.into_std() {
                        return Err(StateError::OperationTimedOut {
                            operation: "read latest LinuxProtected snapshot receipt",
                            timeout_ms,
                        });
                    }
                    Ok(recovered)
                },
            )
            .await?;
            if tokio::time::Instant::now() >= deadline {
                return Err(StateError::OperationTimedOut {
                    operation: "read latest LinuxProtected snapshot receipt",
                    timeout_ms,
                });
            }
            Ok(recovered.map(protected_snapshot_receipt))
        }
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
        let snapshot_memory =
            reserve_snapshot_memory(deadline, "SQLite restore", timeout_ms).await?;
        let mut restore_cleanup_owners =
            claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
                "claw-state-restore-owner-set",
                13,
                deadline.into_std(),
            )
            .await
            .map_err(|error| {
                if tokio::time::Instant::now() >= deadline {
                    StateError::OperationTimedOut {
                        operation: "SQLite restore",
                        timeout_ms,
                    }
                } else {
                    database(
                        "reserve restore worker and cleanup owners",
                        sqlx::Error::Protocol(error),
                    )
                }
            })?;
        let final_handoff_owner = restore_cleanup_owners
            .pop()
            .expect("restore final handoff owner");
        let source_validation_owner = restore_cleanup_owners
            .pop()
            .expect("restore source validation owner");
        let publication_owner = restore_cleanup_owners
            .pop()
            .expect("restore publication owner");
        let durability_owner = restore_cleanup_owners
            .pop()
            .expect("restore durability owner");
        let destination_preflight_owner = restore_cleanup_owners
            .pop()
            .expect("restore destination preflight owner");
        let source_preflight_owner = restore_cleanup_owners
            .pop()
            .expect("restore source preflight owner");
        let snapshot_cleanup_owner = restore_cleanup_owners
            .pop()
            .expect("restore snapshot cleanup owner");
        let restore_admission =
            tokio::time::timeout_at(deadline, RESTORE_CLEANUP_ADMISSION.acquire())
                .await
                .map_err(|_| StateError::OperationTimedOut {
                    operation: "SQLite restore",
                    timeout_ms,
                })?
                .map_err(|_| {
                    database(
                        "acquire restore cleanup admission",
                        sqlx::Error::Protocol("restore cleanup admission closed".to_owned()),
                    )
                })?;
        let deadline_state = Arc::new(OpenDeadlineState {
            work_cutoff: deadline.into_std(),
            deadline: deadline.into_std(),
            timeout_ms,
            operation: "SQLite restore",
            busy_timeout: MAX_CONFIGURED_TIMEOUT,
            expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            finished: std::sync::atomic::AtomicBool::new(false),
            final_commit_state: std::sync::atomic::AtomicU8::new(0),
            open_cleanup_state: std::sync::atomic::AtomicU8::new(0),
        });
        let requested_backup = backup.as_ref().to_owned();
        let (backup, backup_snapshot) = run_bounded_filesystem(
            source_preflight_owner,
            deadline,
            "SQLite restore",
            timeout_ms,
            move || {
                let backup = resolve_snapshot_source_path(&requested_backup)?;
                let backup_file = open_existing_file_no_follow(&backup)?;
                verify_path_identity(&backup, &backup_file)?;
                reject_hard_link(&backup, &backup_file)?;
                let snapshot = PinnedSnapshot::from_file(&backup, backup_file)?;
                Ok((backup, snapshot))
            },
        )
        .await?;
        let validation_deadline_state = Arc::clone(&deadline_state);
        let mut backup_snapshot = Some(backup_snapshot);
        let (backup_snapshot, sealed_digest) = run_bounded_filesystem(
            source_validation_owner,
            deadline,
            "SQLite restore",
            timeout_ms,
            move || {
                let digest = validate_standalone_snapshot_source_pinned(
                    backup_snapshot
                        .as_ref()
                        .expect("restore source snapshot remains owned"),
                    Some(Arc::clone(&validation_deadline_state)),
                )?;
                Ok((
                    backup_snapshot
                        .take()
                        .expect("restore source snapshot is delivered once"),
                    digest,
                ))
            },
        )
        .await?;
        let requested_destination = destination.as_ref().to_owned();
        let mut snapshot_cleanup_owner = Some(snapshot_cleanup_owner);
        let destination_deadline_state = Arc::clone(&deadline_state);
        let (destination, destination_directory, temporary_guard) = run_bounded_filesystem(
            destination_preflight_owner,
            deadline,
            "SQLite restore",
            timeout_ms,
            move || {
                ensure_database_artifacts_absent(&requested_destination)?;
                let destination = resolve_database_path(&requested_destination)?;
                ensure_database_artifacts_absent(&destination)?;
                let destination_directory = pin_private_directory(&destination)?;
                let guard = SnapshotCleanupGuard::new_pinned(
                    &destination,
                    &destination_directory,
                    snapshot_cleanup_owner
                        .take()
                        .expect("restore snapshot cleanup owner is consumed once"),
                    Some(&destination_deadline_state),
                )?;
                Ok((destination, destination_directory, guard))
            },
        )
        .await?;
        #[cfg(test)]
        wait_at_restore_read_test_barrier(&destination).await;
        let temporary = destination.clone();
        let mut cancellation_guard = OperationCancellationGuard::new(Arc::clone(&deadline_state));
        let (mut temporary_guard, restore_receipt) = snapshot_database(
            &backup,
            &backup_snapshot.file,
            &temporary,
            Some(&sealed_digest),
            Some(Arc::clone(&deadline_state)),
            temporary_guard,
            RestoreMaterializationReservation {
                cleanup_owners: restore_cleanup_owners,
                memory: snapshot_memory,
                admission: restore_admission,
            },
        )
        .await?;
        let pinned = match PinnedSnapshot::open_cleanup(&temporary) {
            Ok(pinned) => pinned,
            Err(error) => {
                return Err(cleanup_snapshot_guard_or_error(&mut temporary_guard, error).await);
            }
        };
        if let Err(error) = temporary_guard.bind_file(&pinned.file) {
            drop(pinned);
            return Err(cleanup_snapshot_guard_or_error(&mut temporary_guard, error).await);
        }
        #[cfg(test)]
        if tokio::time::timeout_at(
            deadline,
            wait_at_snapshot_test_barrier(&destination, &temporary),
        )
        .await
        .is_err()
        {
            drop(pinned);
            return Err(cleanup_snapshot_guard_or_error(
                &mut temporary_guard,
                deadline_state.timeout_error(),
            )
            .await);
        }
        let durability_destination = destination.clone();
        let durability_temporary = temporary.clone();
        let mut pinned = Some(pinned);
        let mut temporary_guard = Some(temporary_guard);
        let durability = run_bounded_filesystem(
            durability_owner,
            deadline,
            "SQLite restore",
            timeout_ms,
            move || {
                let result = (|| {
                    let identity_guard = initialize_restored_store_identity(
                        &durability_temporary,
                        &pinned
                            .as_ref()
                            .expect("restore durability snapshot remains owned")
                            .file,
                        &durability_destination,
                    )?;
                    pinned
                        .as_ref()
                        .expect("restore durability snapshot remains owned")
                        .sync()?;
                    if tokio::time::Instant::now() >= deadline {
                        return Err(StateError::OperationTimedOut {
                            operation: "SQLite restore",
                            timeout_ms,
                        });
                    }
                    Ok(identity_guard)
                })();
                Ok(match result {
                    Ok(identity_guard) => Ok((
                        pinned
                            .take()
                            .expect("restore durability snapshot is delivered once"),
                        identity_guard,
                        temporary_guard
                            .take()
                            .expect("restore durability guard is delivered once"),
                    )),
                    Err(error) => Err((
                        error,
                        pinned
                            .take()
                            .expect("failed restore durability snapshot is delivered once"),
                        temporary_guard
                            .take()
                            .expect("failed restore durability guard is delivered once"),
                    )),
                })
            },
        )
        .await?;
        let (pinned, identity_guard, temporary_guard) = match durability {
            Ok(durable) => durable,
            Err((error, pinned, mut guard)) => {
                drop(pinned);
                return Err(cleanup_snapshot_guard_or_error(&mut guard, error).await);
            }
        };
        let publication_destination = destination.clone();
        let publication_deadline_state = Arc::clone(&deadline_state);
        let mut pinned = Some(pinned);
        let mut temporary_guard = Some(temporary_guard);
        let mut identity_guard = Some(identity_guard);
        let publication = run_bounded_filesystem_with_acceptance(
            publication_owner,
            deadline + Duration::from_secs(1),
            deadline,
            "SQLite restore",
            timeout_ms,
            move || {
                let result = publish_bound_snapshot(
                    pinned
                        .as_ref()
                        .expect("restore publication snapshot remains owned"),
                    temporary_guard
                        .as_mut()
                        .expect("restore publication guard remains owned"),
                    &publication_destination,
                    "SQLite restore",
                    Some((deadline, timeout_ms)),
                    Some(&publication_deadline_state),
                    &destination_directory,
                );
                Ok(match result {
                    Ok(()) => {
                        let handoff =
                            validate_published_snapshot_handoff(
                                &publication_destination,
                                &pinned
                                    .as_ref()
                                    .expect("restore publication snapshot remains owned")
                                    .file,
                            )
                            .and_then(
                                |()| {
                                    pinned
                                        .as_ref()
                                        .expect("restore publication snapshot remains owned")
                                        .verify()?;
                                    if pinned
                                        .as_ref()
                                        .expect("restore publication snapshot remains owned")
                                        .file
                                        .metadata()
                                        .map_err(|error| {
                                            file_error(
                                                "inspect published restored snapshot size",
                                                &publication_destination,
                                                error,
                                            )
                                        })?
                                        .len()
                                        != restore_receipt.byte_count
                                        || file_digest_with_deadline(
                                            &pinned
                                                .as_ref()
                                                .expect("restore publication snapshot remains owned")
                                                .file,
                                            Some(&publication_deadline_state),
                                        )? != restore_receipt.digest
                                        || snapshot_is_staging(
                                            &publication_destination,
                                            &pinned
                                                .as_ref()
                                                .expect("restore publication snapshot remains owned")
                                                .file,
                                        )?
                                    {
                                        return Err(StateError::InvalidBackup {
                                            path: publication_destination.clone(),
                                            reason: "published restore failed final content/marker verification"
                                                .to_owned(),
                                        });
                                    }
                                    if tokio::time::Instant::now() >= deadline
                                        || take_publication_deadline_expiration(
                                            &publication_destination,
                                            4,
                                        )
                                    {
                                        Err(StateError::OperationTimedOut {
                                            operation: "SQLite restore",
                                            timeout_ms,
                                        })
                                    } else {
                                        Ok(())
                                    }
                                },
                            );
                        match handoff {
                            Ok(()) => {
                                identity_guard
                                    .as_mut()
                                    .expect("restore identity guard remains owned")
                                    .mark_published();
                                Ok((
                                    pinned
                                        .take()
                                        .expect("published restore snapshot is delivered once"),
                                    temporary_guard
                                        .take()
                                        .expect("published restore guard is delivered once"),
                                    identity_guard
                                        .take()
                                        .expect("published restore identity is delivered once"),
                                ))
                            }
                            Err(error) => {
                                identity_guard
                                    .as_mut()
                                    .expect("restore identity guard remains owned")
                                    .mark_published();
                                temporary_guard
                                    .as_mut()
                                    .expect("restore publication guard remains owned")
                                    .mark_publication_uncertain();
                                Err((
                                    StateError::PublicationUncertain {
                                        path: publication_destination.clone(),
                                        reason: format!(
                                            "published restore failed final identity/deadline validation: {error}"
                                        ),
                                    },
                                    pinned
                                        .take()
                                        .expect("uncertain restore snapshot is delivered once"),
                                    temporary_guard
                                        .take()
                                        .expect("uncertain restore guard is delivered once"),
                                ))
                            }
                        }
                    }
                    Err(error @ StateError::PublicationUncertain { .. }) => {
                        identity_guard
                            .as_mut()
                            .expect("restore identity guard remains owned")
                            .mark_published();
                        Err((
                            error,
                            pinned
                                .take()
                                .expect("uncertain restore snapshot is delivered once"),
                            temporary_guard
                                .take()
                                .expect("uncertain restore guard is delivered once"),
                        ))
                    }
                    Err(error) => {
                        let error = match identity_guard
                            .as_mut()
                            .expect("restore identity guard remains owned")
                            .cleanup()
                        {
                            Ok(()) => error,
                            Err(cleanup) => append_operation_cleanup(
                                "SQLite restore",
                                error,
                                format!("restored lock cleanup failed: {cleanup}"),
                            ),
                        };
                        Err((
                            error,
                            pinned
                                .take()
                                .expect("failed restore publication snapshot is delivered once"),
                            temporary_guard
                                .take()
                                .expect("failed restore publication guard is delivered once"),
                        ))
                    }
                })
            },
        )
        .await;
        let publication = match publication {
            Ok(publication) => publication,
            Err(error) => {
                return Err(StateError::PublicationUncertain {
                    path: destination,
                    reason: format!(
                        "restore publication executor stopped after publication became possible: {error}"
                    ),
                });
            }
        };
        let (pinned, temporary_guard, identity_guard) = match publication {
            Ok(published) => published,
            Err((error, pinned, mut temporary_guard)) => {
                if matches!(error, StateError::PublicationUncertain { .. }) {
                    cancellation_guard.disarm();
                    temporary_guard.mark_publication_uncertain();
                    drop(pinned);
                    return Err(error);
                }
                drop(pinned);
                return Err(cleanup_snapshot_guard_or_error(&mut temporary_guard, error).await);
            }
        };
        #[cfg(test)]
        wait_at_published_handoff_test_barrier(&destination).await;
        let final_destination = destination.clone();
        let final_deadline_state = Arc::clone(&deadline_state);
        let mut pinned = Some(pinned);
        let mut temporary_guard = Some(temporary_guard);
        let mut identity_guard = Some(identity_guard);
        let final_handoff = run_bounded_filesystem_with_acceptance(
            final_handoff_owner,
            deadline + Duration::from_secs(1),
            deadline,
            "SQLite restore",
            timeout_ms,
            move || {
                let result = validate_published_snapshot_handoff(
                    &final_destination,
                    &pinned
                        .as_ref()
                        .expect("final restore snapshot remains owned")
                        .file,
                )
                .and_then(|()| {
                    pinned
                        .as_ref()
                        .expect("final restore snapshot remains owned")
                        .verify()?;
                    if pinned
                        .as_ref()
                        .expect("final restore snapshot remains owned")
                        .file
                        .metadata()
                        .map_err(|error| {
                            file_error(
                                "inspect final restored snapshot size",
                                &final_destination,
                                error,
                            )
                        })?
                        .len()
                        != restore_receipt.byte_count
                        || file_digest_with_deadline(
                            &pinned
                                .as_ref()
                                .expect("final restore snapshot remains owned")
                                .file,
                            Some(&final_deadline_state),
                        )? != restore_receipt.digest
                        || snapshot_is_staging(
                            &final_destination,
                            &pinned
                                .as_ref()
                                .expect("final restore snapshot remains owned")
                                .file,
                        )?
                        || tokio::time::Instant::now() >= deadline
                    {
                        return Err(StateError::OperationTimedOut {
                            operation: "SQLite restore",
                            timeout_ms,
                        });
                    }
                    Ok(())
                });
                let result = result.and_then(|()| {
                    temporary_guard
                        .as_mut()
                        .expect("final restore guard remains owned")
                        .disarm()
                });
                Ok(match result {
                    Ok(()) => Ok((
                        pinned
                            .take()
                            .expect("final restore snapshot is delivered once"),
                        temporary_guard
                            .take()
                            .expect("final restore guard is delivered once"),
                        identity_guard
                            .take()
                            .expect("final restore identity is delivered once"),
                    )),
                    Err(error) => Err((
                        error,
                        pinned
                            .take()
                            .expect("failed final restore snapshot is delivered once"),
                        temporary_guard
                            .take()
                            .expect("failed final restore guard is delivered once"),
                        identity_guard
                            .take()
                            .expect("failed final restore identity is delivered once"),
                    )),
                })
            },
        )
        .await;
        let (pinned, _temporary_guard, mut identity_guard) = match final_handoff {
            Ok(Ok(result)) => result,
            Ok(Err((error, pinned, mut guard, identity_guard))) => {
                guard.mark_publication_uncertain();
                drop((pinned, identity_guard));
                cancellation_guard.disarm();
                return Err(StateError::PublicationUncertain {
                    path: destination,
                    reason: format!("published restore failed caller handoff: {error}"),
                });
            }
            Err(error) => {
                cancellation_guard.disarm();
                return Err(StateError::PublicationUncertain {
                    path: destination,
                    reason: format!("published restore caller handoff stopped: {error}"),
                });
            }
        };
        drop(pinned);
        cancellation_guard.disarm();
        identity_guard.disarm();
        Ok(())
    }

    /// Runs SQLite structural and referential integrity checks.
    pub async fn health(&self) -> Result<HealthReport, StateError> {
        let mut operation = StoreOperationConnection::acquire(
            self.pool(),
            self.operational_identity(),
            "inspect SQLite health",
        )
        .await?;
        let result = deadline_first(operation.deadline, async {
            sqlx::query("BEGIN")
                .execute(&mut *operation.sqlite())
                .await
                .map_err(|error| database("begin health snapshot", error))?;
            let mut migration_errors =
                migration_health_errors_connection(operation.sqlite()).await?;
            let persisted_owner = sqlx::query_scalar::<_, String>(
                "SELECT owner FROM claw_writer_lock WHERE singleton = 1",
            )
            .fetch_optional(&mut *operation.sqlite())
            .await
            .map_err(|error| database("read health application writer", error))?;
            if persisted_owner.as_deref() != Some(self.owner.as_str()) {
                migration_errors
                    .push("application writer ownership does not match the live store".to_owned());
            }
            #[cfg(test)]
            if STALL_HEALTH_PROGRESS
                .lock()
                .expect("health progress failpoint lock poisoned")
                .remove(&self.path)
            {
                let _ = sqlx::query_scalar::<_, i64>(
                    "WITH RECURSIVE spin(value) AS (
                         VALUES(1)
                         UNION ALL
                         SELECT value + 1 FROM spin
                     )
                     SELECT COUNT(*) FROM spin",
                )
                .fetch_one(&mut *operation.sqlite())
                .await
                .map_err(|error| database("run injected health progress query", error))?;
            }
            let results = sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
                .fetch_all(&mut *operation.sqlite())
                .await
                .map_err(|error| database("run SQLite integrity check", error))?;
            let integrity_errors = results
                .into_iter()
                .filter(|result| result != "ok")
                .collect();
            let foreign_key_violations =
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pragma_foreign_key_check")
                    .fetch_one(&mut *operation.sqlite())
                    .await
                    .map_err(|error| database("run foreign key check", error))?;
            let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
                .fetch_one(&mut *operation.sqlite())
                .await
                .map_err(|error| database("read health application id", error))?;
            let schema_version =
                sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM claw_schema_migrations")
                    .fetch_one(&mut *operation.sqlite())
                    .await
                    .map_err(|error| database("read health schema version", error))?;
            let user_version = sqlx::query_scalar::<_, i64>("PRAGMA user_version")
                .fetch_one(&mut *operation.sqlite())
                .await
                .map_err(|error| database("read health user version", error))?;
            if user_version != schema_version {
                migration_errors.push(format!(
                    "SQLite user_version {user_version} does not match migration version {schema_version}"
                ));
            }
            sqlx::query("COMMIT")
                .execute(&mut *operation.sqlite())
                .await
                .map_err(|error| database("commit health snapshot", error))?;
            Ok::<_, StateError>(HealthReport {
                application_id,
                schema_version,
                supported_schema_version: LATEST_SCHEMA_VERSION,
                integrity_errors,
                foreign_key_violations,
                migration_errors,
            })
        })
        .await;
        let report = match result {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => {
                let error = if tokio::time::Instant::now() >= operation.deadline {
                    operation.expire()
                } else {
                    error
                };
                return Err(operation.fail(error).await);
            }
            Err(_) => {
                let error = operation.expire();
                return Err(operation.fail(error).await);
            }
        };
        operation.finish().await?;
        Ok(report)
    }

    /// Checkpoints and truncates the WAL.
    pub async fn checkpoint(&self) -> Result<CheckpointReport, StateError> {
        let mut operation = StoreOperationConnection::acquire_checkpoint(
            self.pool(),
            self.operational_identity(),
            "checkpoint SQLite WAL",
        )
        .await?;
        let work_deadline = operation.deadline.into_std();
        let cleanup_deadline = work_deadline
            .checked_add(operation.identity.cleanup_timeout)
            .ok_or(StateError::InvalidValue {
                field: "checkpoint cleanup timeout",
                reason: "is too large for the monotonic clock",
            })?;
        let connection = operation.take_checkpoint_connection();
        let worker_owner = operation.take_checkpoint_worker_owner();
        let checkpoint = claw_sqlite_file_control::checkpoint_owned_connection(
            worker_owner,
            connection,
            claw_sqlite_file_control::CheckpointExecutionContext {
                work_deadline,
                cleanup_deadline,
                busy_timeout: operation.identity.busy_timeout,
                restore_busy_timeout: operation.identity.busy_timeout,
                cancelled: Arc::clone(&operation.deadline_state.cancelled),
            },
        )
        .await;
        let checkpoint = match checkpoint {
            Ok(checkpoint) => checkpoint,
            Err(cleanup) => {
                let primary = if std::time::Instant::now() >= work_deadline {
                    operation.expire()
                } else {
                    file_control_database("checkpoint SQLite WAL", cleanup.clone())
                };
                return Err(operation.fail_without_connection(append_operation_cleanup(
                    "checkpoint SQLite WAL",
                    primary,
                    cleanup.to_string(),
                )));
            }
        };
        let result = match checkpoint {
            claw_sqlite_file_control::OwnedCheckpointOutcome::Reusable { connection, result } => {
                operation.restore_checkpoint_connection(connection);
                result
            }
            claw_sqlite_file_control::OwnedCheckpointOutcome::Terminal { error, close } => {
                let primary =
                    if error.code() == Some(9) && std::time::Instant::now() >= work_deadline {
                        operation.expire()
                    } else {
                        file_control_database("checkpoint SQLite WAL", error)
                    };
                return Err(operation.fail_without_connection(compose_terminal_close(
                    "checkpoint SQLite WAL",
                    primary,
                    close,
                )));
            }
        };
        #[cfg(all(test, unix))]
        wait_at_checkpoint_test_barrier(&self.path).await;
        if let Err(error) = operation.verify_checkpoint_identity(cleanup_deadline).await {
            return Err(operation.fail(error).await);
        }
        let report = match result {
            Ok(report) => CheckpointReport {
                busy: report.busy,
                log_frames: report.log_frames,
                checkpointed_frames: report.checkpointed_frames,
            },
            Err(error) => {
                let primary = if error.code() == Some(9)
                    && (std::time::Instant::now() >= work_deadline
                        || operation
                            .deadline_state
                            .cancelled
                            .load(std::sync::atomic::Ordering::Acquire))
                {
                    operation.expire()
                } else {
                    file_control_database("checkpoint SQLite WAL", error)
                };
                return Err(operation.fail(primary).await);
            }
        };
        if std::time::Instant::now() >= work_deadline {
            let primary = operation.expire();
            return Err(operation.fail(primary).await);
        }
        operation.finish().await?;
        Ok(report)
    }

    /// Checkpoints, closes all pooled connections, and releases the writer lock.
    pub async fn close(self) -> Result<CheckpointReport, StateError> {
        self.close_inner(false).await
    }

    async fn close_inner(
        mut self,
        application_lock_already_released: bool,
    ) -> Result<CheckpointReport, StateError> {
        let close_started = tokio::time::Instant::now();
        let deadline = close_started + self.close_timeout;
        let mut checkpoint_cleanup_tail = self
            .close_timeout
            .checked_div(5)
            .unwrap_or(Duration::ZERO)
            .min(Duration::from_millis(100));
        if checkpoint_cleanup_tail.is_zero() {
            checkpoint_cleanup_tail = self.close_timeout.min(Duration::from_nanos(1));
        }
        let checkpoint_work_cutoff = deadline
            .checked_sub(checkpoint_cleanup_tail)
            .unwrap_or(close_started);
        let mut ownership = StateStoreCloseGuard {
            ownership: self.ownership.take(),
            terminal_confirmed: false,
        };
        #[cfg(test)]
        if PANIC_CLOSE_AFTER_OWNERSHIP_GUARD
            .lock()
            .expect("close panic failpoint lock poisoned")
            .remove(&self.path)
        {
            panic!("injected panic after state close ownership guard");
        }
        #[cfg(target_os = "linux")]
        let _protected_publication = if let Some(namespace) = self.profile.protected_namespace() {
            match tokio::time::timeout_at(deadline, namespace.publication_gate().lock_owned()).await
            {
                Ok(publication) => Some(publication),
                Err(_) => {
                    return Err(StateError::CloseDegraded {
                        checkpoint_completed: false,
                        application_lock_released: application_lock_already_released,
                        final_connection_closed: false,
                        pool_closed: false,
                        os_lock_released: false,
                        reason: "LinuxProtected publication worker did not retire before the immutable close deadline; all store ownership remains retained"
                            .to_owned(),
                    });
                }
            }
        } else {
            None
        };
        let mut reasons = Vec::new();
        let identity_valid = match self.profile.verify_filesystem(
            (
                &self.database_parent_path,
                &ownership.ownership().database_parent,
            ),
            (&self.path, &ownership.ownership().database_file),
            (&self.lock_path, &ownership.ownership().lock_file),
            self.lock_identity.as_deref(),
            false,
        ) {
            Ok(()) => true,
            Err(error) => {
                reasons.push(format!("database identity unavailable: {error}"));
                false
            }
        };
        let mut checkpoint_owner = if identity_valid {
            // Close needs one worker owner, leaving seven of the eight peak headroom slots.
            match claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
                "claw-state-close-checkpoint",
                1,
                checkpoint_work_cutoff.into_std(),
            )
            .await
            {
                Ok(mut owners) => owners.pop(),
                Err(error) => {
                    reasons.push(format!("reserve close checkpoint owner failed: {error}"));
                    None
                }
            }
        } else {
            None
        };
        let mut connection = if identity_valid {
            match tokio::time::timeout_at(
                checkpoint_work_cutoff,
                ownership.ownership().pool.acquire(),
            )
            .await
            {
                Ok(Ok(connection)) => Some(connection),
                Ok(Err(error)) => {
                    reasons.push(format!(
                        "acquire final close connection failed: {}",
                        database("acquire final close connection", error)
                    ));
                    None
                }
                Err(_) => {
                    reasons.push(
                        "acquire final close connection exceeded checkpoint work cutoff".to_owned(),
                    );
                    None
                }
            }
        } else {
            None
        };
        let final_connection_required = connection.is_some();

        let closing_pool = ownership.ownership().pool.clone();
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

        let mut checkpoint_terminal_closed = false;
        let checkpoint = if let Some(worker_owner) = checkpoint_owner.take() {
            if let Some(checkpoint_connection) = connection.take() {
                match claw_sqlite_file_control::checkpoint_owned_connection(
                    worker_owner,
                    checkpoint_connection,
                    claw_sqlite_file_control::CheckpointExecutionContext {
                        work_deadline: checkpoint_work_cutoff.into_std(),
                        cleanup_deadline: deadline.into_std(),
                        busy_timeout: self.busy_timeout,
                        restore_busy_timeout: self.busy_timeout,
                        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    },
                )
                .await
                {
                    Ok(claw_sqlite_file_control::OwnedCheckpointOutcome::Reusable {
                        connection: returned,
                        result,
                    }) => {
                        connection = Some(returned);
                        match result {
                            Ok(report) if report.busy == 0 => Some(CheckpointReport {
                                busy: report.busy,
                                log_frames: report.log_frames,
                                checkpointed_frames: report.checkpointed_frames,
                            }),
                            Ok(report) => {
                                reasons.push(format!(
                                    "checkpoint remained busy with {} WAL frames and {} checkpointed frames",
                                    report.log_frames, report.checkpointed_frames
                                ));
                                None
                            }
                            Err(error)
                                if error.code() == Some(9)
                                    && std::time::Instant::now()
                                        >= checkpoint_work_cutoff.into_std() =>
                            {
                                reasons.push(
                                    "checkpoint exceeded its immutable work cutoff".to_owned(),
                                );
                                None
                            }
                            Err(error) => {
                                reasons.push(format!("checkpoint failed: {error}"));
                                None
                            }
                        }
                    }
                    Ok(claw_sqlite_file_control::OwnedCheckpointOutcome::Terminal {
                        error,
                        close,
                    }) => {
                        checkpoint_terminal_closed =
                            close == claw_sqlite_file_control::TerminalCloseOutcome::Closed;
                        reasons.push(format!(
                            "checkpoint connection was terminally discarded: {error}; close={close:?}"
                        ));
                        None
                    }
                    Err(error) => {
                        reasons.push(format!(
                            "checkpoint worker retained terminal ownership: {error}"
                        ));
                        None
                    }
                }
            } else {
                let _ = worker_owner.shutdown();
                None
            }
        } else {
            None
        };
        let mut cleanup_identity_valid = identity_valid;
        if connection.is_some()
            && let Err(error) = self.profile.verify_filesystem(
                (
                    &self.database_parent_path,
                    &ownership.ownership().database_parent,
                ),
                (&self.path, &ownership.ownership().database_file),
                (&self.lock_path, &ownership.ownership().lock_file),
                self.lock_identity.as_deref(),
                true,
            )
        {
            cleanup_identity_valid = false;
            reasons.push(format!(
                "post-checkpoint database identity unavailable: {error}"
            ));
        }
        let writer_cleanup_tail = checkpoint_cleanup_tail
            .checked_div(5)
            .filter(|tail| !tail.is_zero())
            .unwrap_or_else(|| checkpoint_cleanup_tail.min(Duration::from_nanos(1)));
        let writer_work_cutoff = deadline
            .checked_sub(writer_cleanup_tail)
            .unwrap_or(checkpoint_work_cutoff);
        let application_lock_released = if application_lock_already_released {
            true
        } else if cleanup_identity_valid {
            if let Some(writer_connection) = connection.take() {
                let release = release_close_writer_claim(
                    writer_connection,
                    &self.owner,
                    writer_work_cutoff.into_std(),
                    deadline.into_std(),
                    self.busy_timeout,
                )
                .await;
                connection = release.connection;
                if let Some(reason) = release.reason {
                    reasons.push(reason.to_string());
                }
                release.released
            } else {
                false
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
            checkpoint_terminal_closed
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
        let pool_closed =
            pool_drain_completed && (!final_connection_required || final_connection_closed);
        let terminal_identity_valid = if pool_closed && self.profile.is_protected() {
            match self.profile.verify_filesystem(
                (
                    &self.database_parent_path,
                    &ownership.ownership().database_parent,
                ),
                (&self.path, &ownership.ownership().database_file),
                (&self.lock_path, &ownership.ownership().lock_file),
                self.lock_identity.as_deref(),
                true,
            ) {
                Ok(()) => true,
                Err(error) => {
                    reasons.push(format!(
                        "terminal LinuxProtected namespace verification failed: {error}"
                    ));
                    false
                }
            }
        } else {
            true
        };
        let os_lock_released = if pool_closed && terminal_identity_valid {
            #[cfg(windows)]
            {
                true
            }
            #[cfg(not(windows))]
            {
                match File::unlock(&ownership.ownership().lock_file) {
                    Ok(()) => true,
                    Err(error) => {
                        reasons.push(format!(
                            "OS identity lock release failed: {}",
                            file_error("release writer lock", &self.lock_path, error)
                        ));
                        false
                    }
                }
            }
        } else {
            reasons.push(if pool_closed {
                "OS identity ownership retained because terminal namespace identity was not confirmed"
                    .to_owned()
            } else {
                "OS identity ownership retained because terminal pool completion was not confirmed"
                    .to_owned()
            });
            false
        };
        if pool_closed && terminal_identity_valid {
            ownership.confirm_terminal_close();
        }
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

struct CloseWriterRelease {
    connection: Option<sqlx::pool::PoolConnection<sqlx::Sqlite>>,
    released: bool,
    reason: Option<StateError>,
}

async fn release_close_writer_claim(
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    owner: &str,
    work_deadline: std::time::Instant,
    cleanup_deadline: std::time::Instant,
    busy_timeout: Duration,
) -> CloseWriterRelease {
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let begin_busy_timeout =
        busy_timeout.min(work_deadline.saturating_duration_since(std::time::Instant::now()));
    let mut transaction =
        match claw_sqlite_file_control::begin_manual_pool_transaction_with_restore_deadlines(
            connection,
            work_deadline,
            cleanup_deadline,
            begin_busy_timeout,
            busy_timeout,
            Some(Arc::clone(&cancelled)),
        )
        .await
        {
            Ok(transaction) => transaction,
            Err(error) => {
                return CloseWriterRelease {
                    connection: None,
                    released: false,
                    reason: Some(file_control_database(
                        "begin application writer release transaction",
                        error,
                    )),
                };
            }
        };
    let released = transaction
        .delete_writer_claim_with_deadline(owner, work_deadline, Arc::clone(&cancelled))
        .await;
    let released = match released {
        Ok(1) => true,
        Ok(_) => {
            let primary = StateError::InvalidMigrationHistory {
                reason: "application writer lock ownership changed unexpectedly".to_owned(),
            };
            return match transaction.rollback_with_deadline(cleanup_deadline).await {
                Ok(connection) => CloseWriterRelease {
                    connection: Some(connection),
                    released: false,
                    reason: Some(primary),
                },
                Err(cleanup) => CloseWriterRelease {
                    connection: None,
                    released: false,
                    reason: Some(append_operation_cleanup(
                        "rollback mismatched close writer deletion",
                        primary,
                        cleanup.to_string(),
                    )),
                },
            };
        }
        Err(error) => {
            let primary = file_control_database("release application writer lock", error);
            return match transaction.rollback_with_deadline(cleanup_deadline).await {
                Ok(connection) => CloseWriterRelease {
                    connection: Some(connection),
                    released: false,
                    reason: Some(primary),
                },
                Err(cleanup) => CloseWriterRelease {
                    connection: None,
                    released: false,
                    reason: Some(append_operation_cleanup(
                        "rollback failed close writer deletion",
                        primary,
                        cleanup.to_string(),
                    )),
                },
            };
        }
    };
    let commit = transaction
        .commit_with_deadline(
            work_deadline,
            cleanup_deadline,
            cancelled,
            busy_timeout,
            None,
        )
        .await;
    match commit {
        Ok((connection, post_commit_owner)) => match post_commit_owner.shutdown() {
            Ok(()) => CloseWriterRelease {
                connection: Some(connection),
                released,
                reason: None,
            },
            Err(cleanup) => CloseWriterRelease {
                connection: Some(connection),
                released,
                reason: Some(database(
                    "release application writer post-COMMIT owner",
                    sqlx::Error::Protocol(cleanup),
                )),
            },
        },
        Err(error) => CloseWriterRelease {
            connection: None,
            released: false,
            reason: Some(file_control_database(
                "commit application writer release transaction",
                error,
            )),
        },
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
    preserve_on_drop: bool,
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

    fn mark_published(&mut self) {
        self.preserve_on_drop = true;
    }
}

#[cfg(unix)]
impl Drop for RestoredIdentityGuard {
    fn drop(&mut self) {
        if self.armed {
            if self.preserve_on_drop {
                self.disarm();
            } else {
                let _ = self.cleanup();
            }
        }
    }
}

#[cfg(windows)]
struct RestoredIdentityGuard {
    identity_file: Option<File>,
    armed: bool,
    preserve_on_drop: bool,
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

    fn mark_published(&mut self) {
        self.preserve_on_drop = true;
    }
}

#[cfg(windows)]
impl Drop for RestoredIdentityGuard {
    fn drop(&mut self) {
        if self.armed {
            if self.preserve_on_drop {
                self.disarm();
            } else {
                let _ = self.cleanup();
            }
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

    fn mark_published(&mut self) {}
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
        preserve_on_drop: false,
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
        preserve_on_drop: false,
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

fn validate_published_snapshot_handoff(path: &Path, expected: &File) -> Result<(), StateError> {
    let file = open_existing_file_no_follow(path)?;
    if !files_share_identity_from_handles_portable(expected, &file)? {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "published snapshot path no longer names the held object",
        });
    }
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
        "operation timeout",
        config.operation_timeout,
        MAX_CONFIGURED_TIMEOUT,
    )?;
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
            reason: "state directory does not have the exact protected service DACL",
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
            reason: "state database does not have the exact protected service DACL",
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
fn secure_private_snapshot_file(path: &Path, file: &File) -> Result<(), StateError> {
    use std::os::unix::fs::PermissionsExt as _;

    verify_path_identity(path, file)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| file_error("secure private SQLite artifact", path, error))?;
    verify_path_identity(path, file)?;
    validate_private_database_file(path, file)
}

#[cfg(windows)]
fn secure_private_snapshot_file(path: &Path, file: &File) -> Result<(), StateError> {
    verify_path_identity(path, file)?;
    claw_sqlite_file_control::secure_new_windows_file(file).map_err(|_| {
        StateError::InvalidPath {
            path: path.to_owned(),
            reason: "private SQLite artifact security descriptor could not be applied",
        }
    })?;
    verify_path_identity(path, file)?;
    validate_private_database_file(path, file)
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
fn secure_private_snapshot_file(path: &Path, _file: &File) -> Result<(), StateError> {
    Err(StateError::InvalidPath {
        path: path.to_owned(),
        reason: "private SQLite artifacts are unsupported on this platform",
    })
}

#[cfg(not(windows))]
fn create_private_snapshot_file(path: &Path) -> Result<File, StateError> {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| file_error("create bound snapshot output", path, error))
}

#[cfg(windows)]
fn create_private_snapshot_file(path: &Path) -> Result<File, StateError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        WRITE_DAC, WRITE_OWNER,
    };

    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| file_error("create bound snapshot output", path, error))
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

#[cfg(not(windows))]
fn open_cleanup_snapshot_file_no_follow(path: &Path) -> Result<File, StateError> {
    open_existing_file_no_follow(path)
}

#[cfg(windows)]
fn open_cleanup_snapshot_file_no_follow(path: &Path) -> Result<File, StateError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| file_error("open cleanup snapshot handle", path, error))?;
    reject_windows_reparse(
        path,
        &file
            .metadata()
            .map_err(|error| file_error("inspect cleanup snapshot handle", path, error))?,
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
        let expected = claw_sqlite_file_control::unix_sidecar_generation_record(
            database,
            &sidecar,
            &generation,
        );
        if actual != expected {
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
        let expected = claw_sqlite_file_control::unix_sidecar_generation_record(
            database, &sidecar, generation,
        );
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| file_error("secure SQLite sidecar", &sidecar, error))?;
        validate_private_database_file(&sidecar, &file)?;
        match file
            .get_xattr(UNIX_SIDECAR_GENERATION_XATTR)
            .map_err(|error| file_error("read SQLite sidecar generation", &sidecar, error))?
        {
            Some(current) if current != expected => {
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
                    &expected,
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
        let expected = claw_sqlite_file_control::unix_sidecar_generation_record(
            database, &sidecar, generation,
        );
        validate_private_database_file(&sidecar, &file)?;
        let current = file
            .get_xattr(UNIX_SIDECAR_GENERATION_XATTR)
            .map_err(|error| file_error("verify SQLite sidecar generation", &sidecar, error))?
            .ok_or_else(|| StateError::InvalidPath {
                path: sidecar.clone(),
                reason: "SQLite sidecar generation is missing",
            })?;
        if current != expected {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotPublicationState {
    StagingBound,
    PublicationInFlight,
    Published,
    PublicationUncertain,
    Reclaimed,
}

struct SnapshotCleanupRetryBudget {
    deadline: std::time::Instant,
    attempts_remaining: usize,
}

impl SnapshotCleanupRetryBudget {
    fn new() -> Self {
        let now = std::time::Instant::now();
        Self {
            deadline: now
                .checked_add(SNAPSHOT_CLEANUP_RETRY_TIMEOUT)
                .unwrap_or(now),
            attempts_remaining: SNAPSHOT_CLEANUP_MAX_ATTEMPTS,
        }
    }

    fn wait_for_retry(&mut self) -> bool {
        self.attempts_remaining = self.attempts_remaining.saturating_sub(1);
        if self.attempts_remaining == 0 {
            return false;
        }
        let now = std::time::Instant::now();
        if now >= self.deadline {
            return false;
        }
        std::thread::sleep(
            self.deadline
                .saturating_duration_since(now)
                .min(SNAPSHOT_CLEANUP_RETRY_INTERVAL),
        );
        std::time::Instant::now() < self.deadline
    }
}

struct SnapshotCleanupGuard {
    path: PathBuf,
    pinned_parent: Option<File>,
    expected_file: Option<File>,
    state: SnapshotPublicationState,
    memory_reservation: Option<SnapshotMemoryReservation>,
    operation_admission: Option<tokio::sync::SemaphorePermit<'static>>,
    shared_retention: Option<SharedSnapshotRetention>,
    cleanup_owner: Option<claw_sqlite_file_control::BlockingCleanupOwner>,
    #[cfg(test)]
    retained_signal: Option<Arc<std::sync::atomic::AtomicU8>>,
    #[cfg(unix)]
    quarantine_name: Option<String>,
    #[cfg(unix)]
    quarantine_reservation: Option<File>,
    #[cfg(unix)]
    quarantine_active: bool,
    #[cfg(unix)]
    quarantined_file: Option<File>,
}

struct SnapshotCleanupPayload {
    path: PathBuf,
    pinned_parent: Option<File>,
    expected_file: Option<File>,
    state: SnapshotPublicationState,
    memory_reservation: Option<SnapshotMemoryReservation>,
    operation_admission: Option<tokio::sync::SemaphorePermit<'static>>,
    shared_retention: Option<SharedSnapshotRetention>,
    #[cfg(test)]
    retained_signal: Option<Arc<std::sync::atomic::AtomicU8>>,
    #[cfg(unix)]
    quarantine_name: Option<String>,
    #[cfg(unix)]
    quarantine_reservation: Option<File>,
    #[cfg(unix)]
    quarantine_active: bool,
    #[cfg(unix)]
    quarantined_file: Option<File>,
}

impl SnapshotCleanupPayload {
    fn into_guard(self) -> SnapshotCleanupGuard {
        SnapshotCleanupGuard {
            path: self.path,
            pinned_parent: self.pinned_parent,
            expected_file: self.expected_file,
            state: self.state,
            memory_reservation: self.memory_reservation,
            operation_admission: self.operation_admission,
            shared_retention: self.shared_retention,
            cleanup_owner: None,
            #[cfg(test)]
            retained_signal: self.retained_signal,
            #[cfg(unix)]
            quarantine_name: self.quarantine_name,
            #[cfg(unix)]
            quarantine_reservation: self.quarantine_reservation,
            #[cfg(unix)]
            quarantine_active: self.quarantine_active,
            #[cfg(unix)]
            quarantined_file: self.quarantined_file,
        }
    }
}

struct BackupStagingLease {
    snapshot: SnapshotCleanupGuard,
    admission_permit: Option<tokio::sync::SemaphorePermit<'static>>,
    memory_reservation: Option<SnapshotMemoryReservation>,
}

impl BackupStagingLease {
    fn move_retention_to_snapshot(&mut self) {
        if self.snapshot.operation_admission.is_none() {
            self.snapshot.operation_admission = self.admission_permit.take();
        }
        if self.snapshot.memory_reservation.is_none() {
            self.snapshot.memory_reservation = self.memory_reservation.take();
        }
    }

    fn bind_file(&mut self, file: &File) -> Result<(), StateError> {
        self.snapshot.bind_file(file)
    }

    async fn cleanup(&mut self) -> Result<(), StateError> {
        self.move_retention_to_snapshot();
        self.snapshot.cleanup().await
    }

    fn disarm_published(&mut self) -> Result<(), StateError> {
        self.snapshot.disarm()
    }

    fn mark_publication_uncertain(&mut self) {
        self.snapshot.mark_publication_uncertain();
    }
}

impl Drop for BackupStagingLease {
    fn drop(&mut self) {
        self.move_retention_to_snapshot();
    }
}

impl claw_sqlite_file_control::SnapshotCleanupLease for BackupStagingLease {
    fn cleanup(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            BackupStagingLease::cleanup(self)
                .await
                .map_err(|error| error.to_string())
        })
    }

    fn take_terminal_retention(&mut self) -> Option<Box<dyn Send>> {
        let memory = self.memory_reservation.take();
        let admission = self.admission_permit.take();
        (memory.is_some() || admission.is_some())
            .then(|| Box::new((memory, admission)) as Box<dyn Send>)
    }

    fn detach_cleanup(&mut self) {
        self.move_retention_to_snapshot();
        self.snapshot.detach_cleanup();
    }
}

async fn cleanup_backup_staging_or_error(
    lease: &mut BackupStagingLease,
    primary: StateError,
) -> StateError {
    match lease.cleanup().await {
        Ok(()) => primary,
        Err(cleanup) => append_operation_cleanup(
            "SQLite backup",
            primary,
            format!("pinned staging cleanup failed: {cleanup}"),
        ),
    }
}

impl SnapshotCleanupGuard {
    fn new_pinned(
        path: &Path,
        parent: &PinnedPrivateDirectory,
        cleanup_owner: claw_sqlite_file_control::BlockingCleanupOwner,
        deadline_state: Option<&OpenDeadlineState>,
    ) -> Result<Self, StateError> {
        #[cfg(not(unix))]
        let _ = deadline_state;
        let pinned_parent = parent
            .file
            .try_clone()
            .map_err(|error| file_error("clone cleanup directory handle", &parent.path, error))?;
        #[cfg(unix)]
        let (quarantine_name, quarantine_reservation) =
            reserve_snapshot_quarantine(parent, deadline_state)?;
        Ok(Self {
            path: path.to_owned(),
            pinned_parent: Some(pinned_parent),
            expected_file: None,
            state: SnapshotPublicationState::StagingBound,
            memory_reservation: None,
            operation_admission: None,
            shared_retention: None,
            cleanup_owner: Some(cleanup_owner),
            #[cfg(test)]
            retained_signal: None,
            #[cfg(unix)]
            quarantine_name: Some(quarantine_name),
            #[cfg(unix)]
            quarantine_reservation: Some(quarantine_reservation),
            #[cfg(unix)]
            quarantine_active: false,
            #[cfg(unix)]
            quarantined_file: None,
        })
    }

    fn bind_file(&mut self, file: &File) -> Result<(), StateError> {
        if let Some(expected) = self.expected_file.as_ref() {
            if !files_share_identity_from_handles_portable(expected, file)? {
                return Err(StateError::InvalidPath {
                    path: self.path.clone(),
                    reason: "snapshot cleanup identity rebinding was rejected",
                });
            }
            return Ok(());
        }
        let expected = file
            .try_clone()
            .map_err(|error| file_error("clone cleanup identity handle", &self.path, error))?;
        #[cfg(windows)]
        reject_windows_reparse(
            &self.path,
            &expected.metadata().map_err(|error| {
                file_error("inspect cleanup identity handle", &self.path, error)
            })?,
        )?;
        self.expected_file = Some(expected);
        Ok(())
    }

    fn disarm(&mut self) -> Result<(), StateError> {
        self.state = SnapshotPublicationState::Published;
        #[cfg(unix)]
        self.release_quarantine_reservation()?;
        Ok(())
    }

    fn begin_publication(&mut self) {
        assert_eq!(self.state, SnapshotPublicationState::StagingBound);
        self.state = SnapshotPublicationState::PublicationInFlight;
    }

    fn clear_staging_marker(&self) -> Result<(), StateError> {
        let expected = self
            .expected_file
            .as_ref()
            .ok_or_else(|| StateError::InvalidPath {
                path: self.path.clone(),
                reason: "snapshot staging identity is not bound",
            })?;
        clear_snapshot_staging(&self.path, expected)
    }

    fn mark_publication_uncertain(&mut self) {
        self.state = SnapshotPublicationState::PublicationUncertain;
    }

    #[cfg(unix)]
    fn release_quarantine_reservation(&mut self) -> Result<(), StateError> {
        let Some(name) = self.quarantine_name.take() else {
            return Ok(());
        };
        let reservation =
            self.quarantine_reservation
                .take()
                .ok_or_else(|| StateError::InvalidPath {
                    path: self.path.clone(),
                    reason: "snapshot quarantine reservation handle is missing",
                })?;
        let parent = self
            .pinned_parent
            .as_ref()
            .ok_or_else(|| StateError::InvalidPath {
                path: self.path.clone(),
                reason: "snapshot quarantine parent is not pinned",
            })?;
        File::unlock(&reservation).map_err(|error| {
            file_error("unlock snapshot quarantine reservation", &self.path, error)
        })?;
        rustix::fs::unlinkat(parent, name.as_str(), rustix::fs::AtFlags::empty()).map_err(
            |error| {
                file_error(
                    "release snapshot quarantine reservation",
                    &self.path,
                    error.into(),
                )
            },
        )?;
        parent.sync_all().map_err(|error| {
            file_error(
                "sync released snapshot quarantine reservation",
                &self.path,
                error,
            )
        })
    }

    fn take_cleanup_payload(&mut self) -> Option<SnapshotCleanupPayload> {
        if self.state != SnapshotPublicationState::StagingBound {
            self.cleanup_owner.take();
            return None;
        }
        self.state = SnapshotPublicationState::Reclaimed;
        Some(SnapshotCleanupPayload {
            path: std::mem::take(&mut self.path),
            pinned_parent: self.pinned_parent.take(),
            expected_file: self.expected_file.take(),
            state: SnapshotPublicationState::StagingBound,
            memory_reservation: self.memory_reservation.take(),
            operation_admission: self.operation_admission.take(),
            shared_retention: self.shared_retention.take(),
            #[cfg(test)]
            retained_signal: self.retained_signal.take(),
            #[cfg(unix)]
            quarantine_name: self.quarantine_name.take(),
            #[cfg(unix)]
            quarantine_reservation: self.quarantine_reservation.take(),
            #[cfg(unix)]
            quarantine_active: self.quarantine_active,
            #[cfg(unix)]
            quarantined_file: self.quarantined_file.take(),
        })
    }

    fn detach_cleanup(&mut self) {
        let (Some(payload), Some(owner)) = (self.take_cleanup_payload(), self.cleanup_owner.take())
        else {
            return;
        };
        #[cfg(test)]
        let retained_signal = payload.retained_signal.clone();
        #[cfg(not(test))]
        let retained_signal = ();
        let guard = payload.into_guard();
        let _ = handoff_state_payload_decide_with_signal(
            owner,
            std::sync::Mutex::new(guard),
            retained_signal,
            None,
            |_, _, guard| {
                let mut guard = guard
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                cleanup_snapshot_with_bounded_retries(&mut guard, |_| {})
            },
        );
    }

    async fn cleanup(&mut self) -> Result<(), StateError> {
        let (Some(payload), Some(owner)) = (self.take_cleanup_payload(), self.cleanup_owner.take())
        else {
            return Ok(());
        };
        struct SnapshotCleanupWorker {
            guard: std::sync::Mutex<SnapshotCleanupGuard>,
            result: std::sync::mpsc::SyncSender<Result<(), StateError>>,
            undelivered: std::sync::Mutex<Option<Result<(), StateError>>>,
        }
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(0);
        #[cfg(test)]
        let retained_signal = payload.retained_signal.clone();
        #[cfg(not(test))]
        let retained_signal = ();
        handoff_state_payload_decide_with_signal(
            owner,
            SnapshotCleanupWorker {
                guard: std::sync::Mutex::new(payload.into_guard()),
                result: result_tx,
                undelivered: std::sync::Mutex::new(None),
            },
            retained_signal,
            None,
            |_, _, payload| {
                let mut guard = payload
                    .guard
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                cleanup_snapshot_with_bounded_retries(&mut guard, |result| {
                    if let Err(result) = payload.result.send(result) {
                        *payload
                            .undelivered
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result.0);
                    }
                })
            },
        )
        .map_err(|error| {
            database(
                "submit SQLite snapshot cleanup",
                sqlx::Error::Protocol(error),
            )
        })?;
        let cutoff = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            match result_rx.try_recv() {
                Ok(result) => return result,
                Err(std::sync::mpsc::TryRecvError::Empty) if std::time::Instant::now() < cutoff => {
                    tokio::task::yield_now().await;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    return Err(StateError::OperationTimedOut {
                        operation: "SQLite snapshot cleanup",
                        timeout_ms: 1_000,
                    });
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err(database(
                        "receive SQLite snapshot cleanup",
                        sqlx::Error::Protocol(
                            "snapshot cleanup owner stopped without a result".to_owned(),
                        ),
                    ));
                }
            }
        }
    }

    fn cleanup_now(&mut self) -> Result<(), StateError> {
        if self.state != SnapshotPublicationState::StagingBound {
            return Ok(());
        }
        if self.expected_file.is_none() {
            if database_artifacts(&self.path)
                .into_iter()
                .all(|artifact| !path_entry_exists(&artifact).unwrap_or(true))
            {
                #[cfg(unix)]
                self.release_quarantine_reservation()?;
                self.state = SnapshotPublicationState::Reclaimed;
                return Ok(());
            }
            return Err(StateError::InvalidPath {
                path: self.path.clone(),
                reason: "snapshot cleanup refused because file identity is unbound",
            });
        }
        #[cfg(unix)]
        if !self.quarantine_active
            && let (Some(parent), Some(expected_file)) =
                (self.pinned_parent.as_ref(), self.expected_file.as_ref())
        {
            verify_child_identity_at(parent, &self.path, expected_file)?;
        }
        #[cfg(all(not(unix), not(windows)))]
        if let Some(expected_file) = &self.expected_file {
            verify_path_identity(&self.path, expected_file)?;
        }
        #[cfg(all(not(unix), not(windows)))]
        let _pinned_parent_lifetime = self.pinned_parent.as_ref();
        #[cfg(not(windows))]
        let artifacts = database_artifacts(&self.path);
        #[cfg(not(windows))]
        for sidecar in artifacts.iter().skip(1) {
            if path_entry_exists(sidecar)? {
                return Err(StateError::InvalidPath {
                    path: sidecar.clone(),
                    reason: "snapshot cleanup quarantined an unbound SQLite sidecar",
                });
            }
        }
        #[cfg(unix)]
        {
            let expected = self.expected_file.as_ref().expect("identity checked above");
            let parent = self
                .pinned_parent
                .as_ref()
                .ok_or_else(|| StateError::InvalidPath {
                    path: self.path.clone(),
                    reason: "snapshot cleanup parent is not pinned",
                })?;
            let name = self
                .path
                .file_name()
                .ok_or_else(|| StateError::InvalidPath {
                    path: self.path.clone(),
                    reason: "snapshot cleanup child has no file name",
                })?;
            let quarantine = self
                .quarantine_name
                .as_ref()
                .ok_or_else(|| StateError::InvalidPath {
                    path: self.path.clone(),
                    reason: "snapshot quarantine capacity was not pre-reserved",
                })?
                .clone();
            if !self.quarantine_active {
                expected
                    .set_len(1)
                    .and_then(|()| expected.sync_all())
                    .map_err(|error| {
                        file_error("mark active snapshot quarantine", &self.path, error)
                    })?;
                rustix::fs::renameat(parent, name, parent, quarantine.as_str()).map_err(
                    |error| {
                        file_error(
                            "quarantine pinned snapshot through held parent",
                            &self.path,
                            error.into(),
                        )
                    },
                )?;
                self.quarantine_active = true;
            }
            if self.quarantined_file.is_none() {
                let quarantined = rustix::fs::openat(
                    parent,
                    quarantine.as_str(),
                    rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::NONBLOCK,
                    rustix::fs::Mode::empty(),
                )
                .map(File::from)
                .map_err(|error| {
                    file_error(
                        "open quarantined snapshot identity",
                        &self.path,
                        error.into(),
                    )
                })?;
                quarantined.try_lock().map_err(|error| match error {
                    std::fs::TryLockError::WouldBlock => StateError::InvalidPath {
                        path: self.path.clone(),
                        reason: "quarantined snapshot identity is already locked",
                    },
                    std::fs::TryLockError::Error(error) => {
                        file_error("lock quarantined snapshot identity", &self.path, error)
                    }
                })?;
                if !files_share_identity_from_handles_portable(expected, &quarantined)? {
                    return Err(StateError::InvalidPath {
                        path: self.path.clone(),
                        reason: "quarantined snapshot did not match the bound identity",
                    });
                }
                self.quarantined_file = Some(quarantined);
            }
            let quarantined = self
                .quarantined_file
                .as_ref()
                .expect("active quarantine identity remains retained");
            let reservation =
                self.quarantine_reservation
                    .as_ref()
                    .ok_or_else(|| StateError::InvalidPath {
                        path: self.path.clone(),
                        reason: "snapshot quarantine reservation handle is missing",
                    })?;
            expected
                .set_len(0)
                .and_then(|()| expected.sync_all())
                .map_err(|error| {
                    file_error("reclaim quarantined snapshot blocks", &self.path, error)
                })?;
            #[cfg(test)]
            if take_counted_failure(&FAIL_SNAPSHOT_CLEANUP_AFTER_RENAME, &self.path) {
                return Err(StateError::InvalidPath {
                    path: self.path.clone(),
                    reason: "injected failure after snapshot quarantine rename",
                });
            }
            parent.sync_all().map_err(|error| {
                file_error(
                    "sync durable snapshot quarantine directory",
                    &self.path,
                    error,
                )
            })?;
            File::unlock(reservation).map_err(|error| {
                file_error(
                    "unlock replaced snapshot quarantine reservation",
                    &self.path,
                    error,
                )
            })?;
            File::unlock(quarantined).map_err(|error| {
                file_error("unlock reclaimed snapshot quarantine", &self.path, error)
            })?;
            self.quarantined_file.take();
            self.quarantine_reservation.take();
            self.quarantine_name.take();
            self.quarantine_active = false;
            self.state = SnapshotPublicationState::Reclaimed;
            Ok(())
        }
        #[cfg(windows)]
        {
            let expected = self
                .expected_file
                .as_ref()
                .expect("snapshot cleanup identity remains owned");
            expected
                .set_len(0)
                .and_then(|()| expected.sync_all())
                .map_err(|error| {
                    file_error("scrub held snapshot cleanup artifact", &self.path, error)
                })?;
            let deletion =
                claw_sqlite_file_control::reopen_file_for_deletion(expected).map_err(|error| {
                    file_error(
                        "derive held snapshot cleanup deletion handle",
                        &self.path,
                        std::io::Error::other(error.to_string()),
                    )
                })?;
            claw_sqlite_file_control::delete_file_by_handle(&deletion).map_err(|error| {
                file_error(
                    "mark held snapshot cleanup artifact for deletion",
                    &self.path,
                    std::io::Error::other(error.to_string()),
                )
            })?;
            self.expected_file.take();
            drop(deletion);
            self.state = SnapshotPublicationState::Reclaimed;
            Ok(())
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            for artifact in artifacts.into_iter().take(1) {
                loop {
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
                        Err(error) => {
                            return Err(file_error(
                                "remove snapshot cleanup artifact",
                                &artifact,
                                error,
                            ));
                        }
                    }
                }
            }
            self.state = SnapshotPublicationState::Reclaimed;
            Ok(())
        }
    }
}

fn cleanup_snapshot_with_bounded_retries(
    guard: &mut SnapshotCleanupGuard,
    report_first: impl FnOnce(Result<(), StateError>),
) -> bool {
    let mut budget = SnapshotCleanupRetryBudget::new();
    let first = guard.cleanup_now();
    let mut failed = first.is_err();
    report_first(first);
    while failed {
        if !budget.wait_for_retry() {
            return false;
        }
        failed = guard.cleanup_now().is_err();
    }
    true
}

#[cfg(unix)]
fn snapshot_quarantine_usage(parent: &Path) -> Result<(usize, u64), StateError> {
    let mut entries = 0_usize;
    let mut residual_bytes = 0_u64;
    for entry in std::fs::read_dir(parent)
        .map_err(|error| file_error("read snapshot quarantine directory", parent, error))?
    {
        let entry =
            entry.map_err(|error| file_error("read snapshot quarantine entry", parent, error))?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(".gta-claw-quarantine-")
        {
            continue;
        }
        let length = entry
            .metadata()
            .map_err(|error| file_error("inspect snapshot quarantine entry", &entry.path(), error))?
            .len();
        if length == 0 {
            continue;
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| StateError::InvalidPath {
                path: parent.to_owned(),
                reason: "snapshot quarantine entry count overflowed",
            })?;
        residual_bytes =
            residual_bytes
                .checked_add(length)
                .ok_or_else(|| StateError::InvalidPath {
                    path: parent.to_owned(),
                    reason: "snapshot quarantine residual byte count overflowed",
                })?;
    }
    Ok((entries, residual_bytes))
}

#[cfg(unix)]
fn ensure_snapshot_quarantine_deadline(
    deadline_state: Option<&OpenDeadlineState>,
) -> Result<(), StateError> {
    if let Some(deadline_state) = deadline_state
        && !deadline_state.permits_sqlite_work()
    {
        return Err(deadline_state.timeout_error());
    }
    Ok(())
}

#[cfg(unix)]
fn claim_reusable_snapshot_quarantine_slot(
    parent: &PinnedPrivateDirectory,
    name: &str,
    deadline_state: Option<&OpenDeadlineState>,
) -> Result<Option<File>, StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let file = match rustix::fs::openat(
        &parent.file,
        name,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(file_error(
                "open reusable snapshot quarantine slot",
                &parent.path,
                error.into(),
            ));
        }
    };
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
        Err(std::fs::TryLockError::Error(error)) => {
            return Err(file_error(
                "lock reusable snapshot quarantine slot",
                &parent.path,
                error,
            ));
        }
    }
    let metadata = file.metadata().map_err(|error| {
        file_error(
            "inspect reusable snapshot quarantine slot",
            &parent.path,
            error,
        )
    })?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != 0 {
        File::unlock(&file).map_err(|error| {
            file_error(
                "unlock rejected snapshot quarantine slot",
                &parent.path,
                error,
            )
        })?;
        return Ok(None);
    }
    ensure_snapshot_quarantine_deadline(deadline_state)?;
    file.set_len(1)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            file_error(
                "claim reusable snapshot quarantine slot",
                &parent.path,
                error,
            )
        })?;
    parent.file.sync_all().map_err(|error| {
        file_error("sync claimed snapshot quarantine slot", &parent.path, error)
    })?;
    Ok(Some(file))
}

#[cfg(unix)]
fn lock_snapshot_quarantine_quota(
    parent: &PinnedPrivateDirectory,
    deadline_state: Option<&OpenDeadlineState>,
) -> Result<File, StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let file = rustix::fs::openat(
        &parent.file,
        ".gta-claw-quarantine-reservation.lock",
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CREATE,
        rustix::fs::Mode::from_bits_retain(0o600),
    )
    .map(File::from)
    .map_err(|error| {
        file_error(
            "open snapshot quarantine quota lock",
            &parent.path,
            error.into(),
        )
    })?;
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                if let Some(deadline_state) = deadline_state
                    && !deadline_state.permits_sqlite_work()
                {
                    return Err(deadline_state.timeout_error());
                }
                let remaining = deadline_state.map_or(MAX_CONFIGURED_TIMEOUT, |state| {
                    state
                        .work_cutoff
                        .saturating_duration_since(std::time::Instant::now())
                });
                if remaining.is_zero() {
                    return Err(deadline_state.map_or(
                        StateError::OperationTimedOut {
                            operation: "reserve snapshot quarantine",
                            timeout_ms: u64::try_from(MAX_CONFIGURED_TIMEOUT.as_millis())
                                .expect("timeout fits u64"),
                        },
                        OpenDeadlineState::timeout_error,
                    ));
                }
                std::thread::sleep(remaining.min(Duration::from_millis(1)));
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(file_error(
                    "lock snapshot quarantine quota",
                    &parent.path,
                    error,
                ));
            }
        }
    }
    ensure_snapshot_quarantine_deadline(deadline_state)?;
    let metadata = file.metadata().map_err(|error| {
        file_error(
            "inspect snapshot quarantine quota lock",
            &parent.path,
            error,
        )
    })?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(StateError::InvalidPath {
            path: parent.path.clone(),
            reason: "snapshot quarantine quota lock identity is unsafe",
        });
    }
    Ok(file)
}

#[cfg(unix)]
fn reserve_snapshot_quarantine(
    parent: &PinnedPrivateDirectory,
    deadline_state: Option<&OpenDeadlineState>,
) -> Result<(String, File), StateError> {
    const MAX_QUARANTINE_ENTRIES: usize = 64;
    const MAX_QUARANTINE_RESIDUAL_BYTES: u64 = MAX_AUTHENTICATED_SNAPSHOT_BYTES;

    let _quota_lock = lock_snapshot_quarantine_quota(parent, deadline_state)?;
    ensure_snapshot_quarantine_deadline(deadline_state)?;
    let (entries, residual_bytes) = snapshot_quarantine_usage(&parent.path)?;
    ensure_snapshot_quarantine_deadline(deadline_state)?;
    if entries >= MAX_QUARANTINE_ENTRIES || residual_bytes > MAX_QUARANTINE_RESIDUAL_BYTES {
        return Err(StateError::InvalidPath {
            path: parent.path.clone(),
            reason: "snapshot quarantine quota is exhausted",
        });
    }
    for index in 0..MAX_QUARANTINE_ENTRIES {
        ensure_snapshot_quarantine_deadline(deadline_state)?;
        let name = format!(".gta-claw-quarantine-slot-{index:02}");
        match rustix::fs::openat(
            &parent.file,
            name.as_str(),
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL,
            rustix::fs::Mode::from_bits_retain(0o600),
        ) {
            Ok(file) => {
                let file = File::from(file);
                if let Err(error) = ensure_snapshot_quarantine_deadline(deadline_state) {
                    let _ = rustix::fs::unlinkat(
                        &parent.file,
                        name.as_str(),
                        rustix::fs::AtFlags::empty(),
                    );
                    return Err(error);
                }
                file.try_lock().map_err(|error| match error {
                    std::fs::TryLockError::WouldBlock => StateError::InvalidPath {
                        path: parent.path.clone(),
                        reason: "snapshot quarantine reservation is already locked",
                    },
                    std::fs::TryLockError::Error(error) => {
                        file_error("lock snapshot quarantine reservation", &parent.path, error)
                    }
                })?;
                if let Err(error) = ensure_snapshot_quarantine_deadline(deadline_state) {
                    let _ = File::unlock(&file);
                    let _ = rustix::fs::unlinkat(
                        &parent.file,
                        name.as_str(),
                        rustix::fs::AtFlags::empty(),
                    );
                    return Err(error);
                }
                file.set_len(1)
                    .and_then(|()| file.sync_all())
                    .map_err(|error| {
                        file_error("sync snapshot quarantine reservation", &parent.path, error)
                    })?;
                parent.file.sync_all().map_err(|error| {
                    file_error(
                        "sync snapshot quarantine reservation directory",
                        &parent.path,
                        error,
                    )
                })?;
                return Ok((name, file));
            }
            Err(rustix::io::Errno::EXIST) => {
                if let Some(file) =
                    claim_reusable_snapshot_quarantine_slot(parent, &name, deadline_state)?
                {
                    return Ok((name, file));
                }
            }
            Err(error) => {
                return Err(file_error(
                    "reserve snapshot quarantine capacity",
                    &parent.path,
                    error.into(),
                ));
            }
        }
    }
    Err(StateError::InvalidPath {
        path: parent.path.clone(),
        reason: "snapshot quarantine quota is exhausted",
    })
}

#[cfg(test)]
mod open_deadline_tests {
    use super::*;

    fn run_in_isolated_child(test_name: &str, marker: &str) -> bool {
        if std::env::var_os(marker).is_some() {
            return false;
        }
        let status =
            std::process::Command::new(std::env::current_exe().expect("resolve state test binary"))
                .arg("--exact")
                .arg(test_name)
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env(marker, "1")
                .status()
                .expect("run isolated state test");
        assert!(status.success(), "isolated state test failed: {test_name}");
        true
    }

    #[test]
    fn dropped_open_runtime_readiness_receiver_stops_all_workers() {
        let (ready, receiver) = std::sync::mpsc::sync_channel(1);
        drop(receiver);
        std::thread::Builder::new()
            .name("open-runtime-readiness-test".to_owned())
            .spawn(move || run_open_lifecycle_runtime(ready))
            .expect("spawn isolated open runtime readiness thread")
            .join()
            .expect("dropped readiness receiver stops the open runtime");
    }

    #[tokio::test]
    async fn bootstrap_pool_acquire_uses_the_immutable_work_cutoff() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open bootstrap acquire pool");
        let held = pool.acquire().await.expect("hold bootstrap pool capacity");
        let work_cutoff = std::time::Instant::now() + Duration::from_millis(50);
        let deadline_state = Arc::new(OpenDeadlineState {
            work_cutoff,
            deadline: work_cutoff + Duration::from_millis(500),
            timeout_ms: 50,
            operation: "state store open",
            busy_timeout: Duration::from_secs(1),
            expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            finished: std::sync::atomic::AtomicBool::new(false),
            final_commit_state: std::sync::atomic::AtomicU8::new(0),
            open_cleanup_state: std::sync::atomic::AtomicU8::new(0),
        });
        let started = std::time::Instant::now();
        let error = initialize_fresh_database(
            &pool,
            Path::new("bootstrap-acquire.sqlite"),
            "bootstrap-acquire-owner",
            deadline_state,
            OPEN_TRANSACTION_ADMISSION
                .acquire()
                .await
                .expect("reserve bootstrap test transaction admission"),
        )
        .await
        .expect_err("held pool capacity consumes the bootstrap work cutoff");
        assert!(matches!(
            error,
            StateError::OperationTimedOut {
                operation: "state store open",
                timeout_ms: 50,
            }
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        drop(held);
        pool.close().await;
    }

    #[tokio::test]
    async fn migration_application_id_acquire_uses_the_immutable_work_cutoff() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open migration acquire pool");
        sqlx::query("PRAGMA application_id = 1196704067")
            .execute(&pool)
            .await
            .expect("seed migration application id");
        let held = pool.acquire().await.expect("hold migration pool capacity");
        let work_cutoff = std::time::Instant::now() + Duration::from_millis(50);
        let deadline_state = Arc::new(OpenDeadlineState {
            work_cutoff,
            deadline: work_cutoff + Duration::from_millis(500),
            timeout_ms: 50,
            operation: "state store open",
            busy_timeout: Duration::from_secs(1),
            expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            finished: std::sync::atomic::AtomicBool::new(false),
            final_commit_state: std::sync::atomic::AtomicU8::new(0),
            open_cleanup_state: std::sync::atomic::AtomicU8::new(0),
        });
        let error = initialize_database(
            &pool,
            Path::new("migration-acquire.sqlite"),
            InspectedDatabase::Existing { schema_version: 0 },
            "migration-acquire-owner",
            deadline_state,
            OPEN_TRANSACTION_ADMISSION
                .acquire()
                .await
                .expect("reserve migration test transaction admission"),
        )
        .await
        .expect_err("held pool capacity consumes the migration work cutoff");
        assert!(matches!(
            error,
            StateError::OperationTimedOut {
                operation: "state store open",
                timeout_ms: 50,
            }
        ));
        drop(held);
        pool.close().await;
    }

    #[tokio::test]
    async fn application_id_read_crossing_cutoff_never_starts_migration() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open gated application-id pool");
        sqlx::query("PRAGMA application_id = 1196704067")
            .execute(&pool)
            .await
            .expect("seed gated application id");
        let path = PathBuf::from("gated-application-id.sqlite");
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        APPLICATION_ID_READ_TEST_BARRIER
            .lock()
            .expect("application-id barrier lock poisoned")
            .insert(
                path.clone(),
                MigrationTestBarrier {
                    entered: Arc::clone(&entered),
                    release,
                },
            );
        let work_cutoff = std::time::Instant::now() + Duration::from_millis(50);
        let deadline_state = Arc::new(OpenDeadlineState {
            work_cutoff,
            deadline: work_cutoff + Duration::from_millis(500),
            timeout_ms: 50,
            operation: "state store open",
            busy_timeout: Duration::from_secs(1),
            expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            finished: std::sync::atomic::AtomicBool::new(false),
            final_commit_state: std::sync::atomic::AtomicU8::new(0),
            open_cleanup_state: std::sync::atomic::AtomicU8::new(0),
        });
        let error = initialize_database(
            &pool,
            &path,
            InspectedDatabase::Existing { schema_version: 0 },
            "gated-application-id-owner",
            deadline_state,
            OPEN_TRANSACTION_ADMISSION
                .acquire()
                .await
                .expect("reserve application-id test transaction admission"),
        )
        .await
        .expect_err("application-id dispatch is rejected after its work cutoff");
        assert!(matches!(
            error,
            StateError::OperationTimedOut {
                operation: "state store open",
                timeout_ms: 50,
            }
        ));
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("application-id gate was entered after lease acquisition");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'claw_writer_lock'"
            )
            .fetch_one(&pool)
            .await
            .expect("inspect gated migration schema"),
            0
        );
        pool.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn owned_connection_close_uses_one_immutable_fallback_cutoff() {
        if run_in_isolated_child(
            "store::open_deadline_tests::owned_connection_close_uses_one_immutable_fallback_cutoff",
            "GTA_CLAW_OWNED_CLOSE_CUTOFF_CHILD",
        ) {
            return;
        }

        struct GateGuard {
            result_release: Arc<std::sync::atomic::AtomicBool>,
            retirement_release: Arc<std::sync::atomic::AtomicBool>,
        }

        impl Drop for GateGuard {
            fn drop(&mut self) {
                self.result_release
                    .store(true, std::sync::atomic::Ordering::Release);
                self.retirement_release
                    .store(true, std::sync::atomic::Ordering::Release);
                OWNED_CLOSE_CUTOFF_TEST_CONTROL
                    .lock()
                    .expect("owned close cutoff control lock poisoned")
                    .take();
            }
        }

        let result_entered = Arc::new(tokio::sync::Notify::new());
        let result_release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let retirement_entered = Arc::new(tokio::sync::Notify::new());
        let retirement_release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *OWNED_CLOSE_CUTOFF_TEST_CONTROL
            .lock()
            .expect("owned close cutoff control lock poisoned") =
            Some(OwnedCloseCutoffTestControl {
                fallback_timeout: Duration::from_millis(500),
                result_entered: Arc::clone(&result_entered),
                result_release: Arc::clone(&result_release),
                retirement_entered: Arc::clone(&retirement_entered),
                retirement_release: Arc::clone(&retirement_release),
            });
        let _guard = GateGuard {
            result_release: Arc::clone(&result_release),
            retirement_release: Arc::clone(&retirement_release),
        };

        let connection = SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open owned close cutoff connection");
        let cleanup_owner =
            claw_sqlite_file_control::BlockingCleanupOwner::acquire("owned-close-cutoff-test")
                .await
                .expect("reserve owned close cutoff owner");
        let connection =
            OwnedSqliteConnectionGuard::new_cancellable_with_owner(connection, None, cleanup_owner);
        let started = std::time::Instant::now();
        let close = tokio::spawn(connection.close());
        tokio::time::timeout(Duration::from_secs(1), result_entered.notified())
            .await
            .expect("owned close reaches delayed result gate");
        tokio::time::sleep(Duration::from_millis(350)).await;
        result_release.store(true, std::sync::atomic::Ordering::Release);
        tokio::time::timeout(Duration::from_secs(1), retirement_entered.notified())
            .await
            .expect("owned close reaches retirement gate after result delivery");
        let error = tokio::time::timeout(Duration::from_millis(300), close)
            .await
            .expect("retirement wait reuses the original fallback cutoff")
            .expect("owned close cutoff task joins")
            .expect_err("stalled retirement exceeds the immutable cutoff");
        assert!(
            error
                .to_string()
                .contains("owner terminal retirement exceeded its cleanup deadline"),
            "delivered close result preserves retirement error precedence: {error}"
        );
        assert!(
            started.elapsed() < Duration::from_millis(650),
            "result and retirement waits share one absolute fallback cutoff"
        );

        retirement_release.store(true, std::sync::atomic::Ordering::Release);
        let all = claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
            "owned-close-cutoff-capacity-proof",
            64,
            std::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .expect("stalled owned close terminalizes after release");
        for owner in all {
            owner
                .shutdown()
                .expect("release owned close cutoff capacity proof");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_writer_failure_paths_use_absolute_rollback_deadline() {
        if run_in_isolated_child(
            "store::open_deadline_tests::close_writer_failure_paths_use_absolute_rollback_deadline",
            "GTA_CLAW_CLOSE_WRITER_ROLLBACK_CHILD",
        ) {
            return;
        }

        for failure in ["row-count", "statement"] {
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect("sqlite::memory:")
                .await
                .expect("open close writer rollback pool");
            if failure == "row-count" {
                sqlx::raw_sql(
                    "CREATE TABLE claw_writer_lock(
                        singleton INTEGER PRIMARY KEY,
                        owner TEXT NOT NULL,
                        acquired_at_ms INTEGER NOT NULL
                     );
                     INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
                     VALUES (1, 'actual-owner', 1);",
                )
                .execute(&pool)
                .await
                .expect("seed mismatched close writer row");
            }
            let connection = pool
                .acquire()
                .await
                .expect("acquire close writer rollback connection");
            let started = std::time::Instant::now();
            let work_deadline = started + Duration::from_millis(200);
            let cleanup_deadline = started + Duration::from_secs(1);
            tokio::time::sleep(Duration::from_millis(150)).await;
            let release = release_close_writer_claim(
                connection,
                "wrong-owner",
                work_deadline,
                cleanup_deadline,
                Duration::from_secs(1),
            )
            .await;
            assert!(!release.released);
            assert!(release.connection.is_some());
            let reason = release
                .reason
                .expect("close writer deletion failure remains typed");
            if failure == "row-count" {
                assert!(matches!(reason, StateError::InvalidMigrationHistory { .. }));
            } else {
                let StateError::Database(failure) = reason else {
                    panic!("statement deletion failure remains a typed database error");
                };
                assert_eq!(failure.operation(), "release application writer lock");
            }
            let mut replacement = release
                .connection
                .expect("successful absolute rollback returns the owned connection");
            if failure == "row-count" {
                assert_eq!(
                    sqlx::query_scalar::<_, String>(
                        "SELECT owner FROM claw_writer_lock WHERE singleton = 1"
                    )
                    .fetch_one(&mut *replacement)
                    .await
                    .expect("read rolled-back stale writer claim"),
                    "actual-owner",
                    "mismatched writer deletion remains rolled back"
                );
            } else {
                assert_eq!(
                    sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM sqlite_schema
                         WHERE type = 'table' AND name = 'claw_writer_lock'"
                    )
                    .fetch_one(&mut *replacement)
                    .await
                    .expect("inspect statement-error rollback schema"),
                    0
                );
            }
            drop(replacement);
            pool.close().await;
        }
    }
}

#[cfg(all(test, unix))]
mod snapshot_quarantine_tests {
    use super::*;

    fn private_tempdir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("create private test directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure private test directory");
        directory
    }

    fn run_ignored_in_isolated_child(test_name: &str, marker: &str) -> bool {
        if std::env::var_os(marker).is_some() {
            return false;
        }
        let status =
            std::process::Command::new(std::env::current_exe().expect("resolve state test binary"))
                .arg("--exact")
                .arg(test_name)
                .arg("--ignored")
                .arg("--test-threads=1")
                .env(marker, "1")
                .status()
                .expect("run isolated snapshot cleanup test");
        assert!(
            status.success(),
            "isolated snapshot cleanup test failed: {test_name}"
        );
        true
    }

    async fn staging_cleanup_guard(path: &Path) -> SnapshotCleanupGuard {
        let parent = pin_private_directory(path).expect("pin snapshot cleanup directory");
        let cleanup_owner =
            claw_sqlite_file_control::BlockingCleanupOwner::acquire("snapshot-retry-test")
                .await
                .expect("reserve snapshot retry cleanup owner");
        let mut guard = SnapshotCleanupGuard::new_pinned(path, &parent, cleanup_owner, None)
            .expect("create snapshot retry guard");
        let file = create_bound_snapshot_output(
            path,
            Some(&mut guard),
            std::time::Instant::now() + Duration::from_secs(1),
            None,
            "snapshot cleanup retry test",
            1_000,
        )
        .expect("create bound snapshot retry fixture");
        file.set_len(4096)
            .and_then(|()| file.sync_all())
            .expect("persist snapshot retry fixture");
        guard
    }

    fn fail_snapshot_cleanup_after_rename(
        path: &Path,
        remaining: usize,
    ) -> Arc<std::sync::atomic::AtomicUsize> {
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let previous = FAIL_SNAPSHOT_CLEANUP_AFTER_RENAME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                path.to_owned(),
                CountedFailure {
                    remaining,
                    attempts: Arc::clone(&attempts),
                },
            );
        assert!(previous.is_none(), "snapshot cleanup failpoint is unique");
        attempts
    }

    async fn wait_for_quarantine_usage(parent: &Path, expected: (usize, u64)) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if snapshot_quarantine_usage(parent).expect("inspect snapshot quarantine")
                    == expected
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("snapshot quarantine reaches expected usage");
    }

    fn retained_state_cleanup_count() -> usize {
        STATE_CLEANUP_QUARANTINE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .slots
            .iter()
            .filter(|entry| entry.is_some())
            .count()
    }

    #[test]
    fn concurrent_reservations_cannot_exceed_residual_quota() {
        let directory = private_tempdir();
        let database = directory.path().join("state.sqlite");
        let parent = pin_private_directory(&database).expect("pin quarantine quota directory");
        for index in 0..63 {
            std::fs::write(
                directory
                    .path()
                    .join(format!(".gta-claw-quarantine-legacy-{index:02}")),
                b"active",
            )
            .expect("create active quarantine residual");
        }
        let start = std::sync::Barrier::new(3);
        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                start.wait();
                reserve_snapshot_quarantine(&parent, None)
            });
            let second = scope.spawn(|| {
                start.wait();
                reserve_snapshot_quarantine(&parent, None)
            });
            start.wait();
            (
                first.join().expect("first reservation thread joins"),
                second.join().expect("second reservation thread joins"),
            )
        });
        assert_eq!(
            usize::from(first.is_ok()) + usize::from(second.is_ok()),
            1,
            "only one reservation may consume the final quarantine slot"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "run explicitly by the P03b transient cleanup-capacity gate"]
    async fn transient_post_rename_cleanup_releases_all_capacity() {
        const CHILD_ENV: &str = "GTA_CLAW_TRANSIENT_SNAPSHOT_CLEANUP_CHILD";
        if run_ignored_in_isolated_child(
            "store::snapshot_quarantine_tests::transient_post_rename_cleanup_releases_all_capacity",
            CHILD_ENV,
        ) {
            return;
        }

        let directory = private_tempdir();
        let mut cleanups = tokio::task::JoinSet::new();
        for index in 0..16 {
            let path = directory
                .path()
                .join(format!("transient-cleanup-{index:02}.sqlite"));
            let mut guard = staging_cleanup_guard(&path).await;
            let attempts = fail_snapshot_cleanup_after_rename(&path, 1);
            cleanups.spawn(async move {
                let result = guard.cleanup().await;
                (path, attempts, result)
            });
        }

        let mut paths = Vec::new();
        while let Some(joined) = cleanups.join_next().await {
            let (path, attempts, result) = joined.expect("transient cleanup task joins");
            assert!(matches!(
                result,
                Err(StateError::InvalidPath {
                    reason: "injected failure after snapshot quarantine rename",
                    ..
                })
            ));
            assert_eq!(
                attempts.load(std::sync::atomic::Ordering::Acquire),
                1,
                "each transient failure is injected exactly once"
            );
            paths.push(path);
        }
        wait_for_quarantine_usage(directory.path(), (0, 0)).await;
        assert!(
            paths.iter().all(|path| !path.exists()),
            "every renamed staging path remains absent"
        );
        assert_eq!(
            retained_state_cleanup_count(),
            0,
            "successful retries cannot enter fail-closed retention"
        );

        let owners = claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
            "snapshot-retry-capacity-proof",
            MAX_STATE_CLEANUP_JOBS,
            std::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .expect("transient retries release complete cleanup capacity");
        for owner in owners {
            owner
                .shutdown()
                .expect("release transient capacity proof owner");
        }
    }

    #[tokio::test]
    #[ignore = "run explicitly by the P03b persistent cleanup-retention gate"]
    async fn persistent_post_rename_cleanup_is_bounded_and_retains_capacity() {
        const CHILD_ENV: &str = "GTA_CLAW_PERSISTENT_SNAPSHOT_CLEANUP_CHILD";
        if run_ignored_in_isolated_child(
            "store::snapshot_quarantine_tests::persistent_post_rename_cleanup_is_bounded_and_retains_capacity",
            CHILD_ENV,
        ) {
            return;
        }

        let directory = private_tempdir();
        let path = directory.path().join("persistent-cleanup.sqlite");
        let mut guard = staging_cleanup_guard(&path).await;
        let attempts = fail_snapshot_cleanup_after_rename(&path, usize::MAX);
        let started = std::time::Instant::now();
        assert!(matches!(
            guard.cleanup().await,
            Err(StateError::InvalidPath {
                reason: "injected failure after snapshot quarantine rename",
                ..
            })
        ));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the first persistent cleanup failure is surfaced promptly"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while attempts.load(std::sync::atomic::Ordering::Acquire)
                < SNAPSHOT_CLEANUP_MAX_ATTEMPTS
                || retained_state_cleanup_count() != 1
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("persistent cleanup exhausts into fail-closed retention");
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::Acquire),
            SNAPSHOT_CLEANUP_MAX_ATTEMPTS,
            "persistent cleanup stops at its explicit attempt bound"
        );
        assert!(
            started.elapsed() < SNAPSHOT_CLEANUP_RETRY_TIMEOUT + Duration::from_secs(1),
            "persistent cleanup cannot occupy a worker indefinitely"
        );
        assert!(
            !path.exists(),
            "the original staging name remains quarantined"
        );
        assert_eq!(
            snapshot_quarantine_usage(directory.path()).expect("inspect retained quarantine"),
            (0, 0),
            "retry exhaustion cannot leave residual snapshot bytes"
        );
        let quarantine_name = std::fs::read_dir(directory.path())
            .expect("read retained quarantine directory")
            .map(|entry| entry.expect("read retained quarantine entry"))
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".gta-claw-quarantine-slot-")
            })
            .expect("retained quarantine slot exists")
            .file_name();
        let parent =
            pin_private_directory(&path).expect("pin retained snapshot quarantine directory");
        assert!(
            claim_reusable_snapshot_quarantine_slot(
                &parent,
                quarantine_name
                    .to_str()
                    .expect("quarantine slot name is UTF-8"),
                None,
            )
            .expect("probe retained quarantine slot")
            .is_none(),
            "retry exhaustion retains the quarantined identity lock"
        );

        let owners = claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
            "snapshot-retained-capacity-proof",
            MAX_STATE_CLEANUP_JOBS - 1,
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect("exactly one cleanup owner remains retained");
        for owner in owners {
            owner
                .shutdown()
                .expect("release persistent capacity proof owner");
        }
        assert!(
            claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
                "snapshot-retained-full-capacity-rejection",
                MAX_STATE_CLEANUP_JOBS,
                std::time::Instant::now() + Duration::from_millis(50),
            )
            .await
            .is_err(),
            "retained cleanup ownership prevents unsafe full-capacity admission"
        );
    }
}

#[cfg(all(test, unix))]
mod trusted_backup_seal_cleanup_tests {
    use super::*;

    fn trusted_seal_fixture(
        path: &Path,
        remaining_failures: usize,
    ) -> (TrustedBackupSeal, Arc<std::sync::atomic::AtomicUsize>) {
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .expect("create trusted seal cleanup fixture");
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let previous = FAIL_TRUSTED_SEAL_AFTER_UNLINK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                path.to_owned(),
                CountedFailure {
                    remaining: remaining_failures,
                    attempts: Arc::clone(&attempts),
                },
            );
        assert!(previous.is_none(), "trusted seal failpoint is unique");
        (
            TrustedBackupSeal {
                path: path.to_owned(),
                file: Some(file),
                deleted: false,
                armed: true,
            },
            attempts,
        )
    }

    #[test]
    fn transient_post_unlink_failure_resumes_at_parent_sync() {
        let directory = tempfile::tempdir().expect("transient seal cleanup directory");
        let path = directory.path().join("transient-seal.record");
        let (mut seal, attempts) = trusted_seal_fixture(&path, 1);

        assert!(matches!(
            seal.cleanup(),
            Err(StateError::InvalidPath {
                reason: "injected failure after trusted backup seal unlink",
                ..
            })
        ));
        assert!(!path.exists(), "trusted seal was unlinked before failure");
        assert!(seal.deleted, "successful unlink is recorded");
        assert!(
            seal.file.is_some(),
            "identity retention survives failed sync"
        );
        assert!(seal.armed, "failed cleanup remains armed");
        seal.cleanup()
            .expect("transient seal cleanup resumes with parent sync");
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::Acquire),
            1,
            "resumed cleanup cannot repeat the unlink"
        );
        assert!(
            seal.file.is_none(),
            "completed cleanup releases identity retention"
        );
        assert!(!seal.armed, "completed cleanup disarms the seal");
    }

    #[test]
    fn persistent_post_unlink_failure_returns_without_reunlinking() {
        let directory = tempfile::tempdir().expect("persistent seal cleanup directory");
        let path = directory.path().join("persistent-seal.record");
        let (mut seal, attempts) = trusted_seal_fixture(&path, usize::MAX);

        let started = std::time::Instant::now();
        assert!(matches!(
            seal.cleanup(),
            Err(StateError::InvalidPath {
                reason: "injected failure after trusted backup seal unlink",
                ..
            })
        ));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "persistent seal cleanup returns without an internal retry loop"
        );
        assert!(
            !path.exists(),
            "persistent failure cannot restore the seal path"
        );
        assert!(seal.deleted, "persistent cleanup retains the unlink state");
        assert!(
            seal.file.is_some(),
            "persistent cleanup retains the identity handle"
        );
        assert!(
            seal.armed,
            "persistent cleanup remains armed for a later attempt"
        );
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::Acquire),
            1,
            "one cleanup call performs one bounded parent-sync attempt"
        );

        FAIL_TRUSTED_SEAL_AFTER_UNLINK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&path)
            .expect("persistent seal failpoint remains registered")
            .remaining = 0;
        seal.cleanup()
            .expect("persistent seal cleanup resumes once sync can proceed");
        assert!(seal.file.is_none());
        assert!(!seal.armed);
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
        self.detach_cleanup();
    }
}

impl claw_sqlite_file_control::SnapshotCleanupLease for SnapshotCleanupGuard {
    fn cleanup(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            SnapshotCleanupGuard::cleanup(self)
                .await
                .map_err(|error| error.to_string())
        })
    }

    fn take_terminal_retention(&mut self) -> Option<Box<dyn Send>> {
        if let Some(shared) = self.shared_retention.as_ref() {
            return Some(Box::new(Arc::clone(shared)));
        }
        let memory = self.memory_reservation.take();
        let admission = self.operation_admission.take();
        (memory.is_some() || admission.is_some())
            .then(|| Box::new((memory, admission)) as Box<dyn Send>)
    }

    fn detach_cleanup(&mut self) {
        SnapshotCleanupGuard::detach_cleanup(self);
    }
}

async fn cleanup_snapshot_guard_or_error(
    guard: &mut SnapshotCleanupGuard,
    primary: StateError,
) -> StateError {
    match guard.cleanup().await {
        Ok(()) => primary,
        Err(cleanup) => append_operation_cleanup(
            "SQLite snapshot cleanup",
            primary,
            format!("pinned cleanup failed: {cleanup}"),
        ),
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
    cleanup_owner: Option<claw_sqlite_file_control::BlockingCleanupOwner>,
    retirement_fence: Option<Arc<std::sync::atomic::AtomicU8>>,
}

impl BackupConnectionGuard {
    fn new_cancellable(
        connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
        cancellation: Arc<OpenDeadlineState>,
        cleanup_owner: claw_sqlite_file_control::BlockingCleanupOwner,
    ) -> Self {
        Self {
            connection: Some(connection),
            cancellation: Some(cancellation),
            cleanup_owner: Some(cleanup_owner),
            retirement_fence: None,
        }
    }

    fn retain_until(&mut self, signal: Arc<std::sync::atomic::AtomicU8>) {
        assert!(
            self.retirement_fence.replace(signal).is_none(),
            "connection retirement fence is installed once"
        );
    }

    fn release_reusable(mut self) -> Result<(), StateError> {
        self.cancellation = None;
        if let Some(signal) = self.retirement_fence.take() {
            assert_eq!(
                signal.load(std::sync::atomic::Ordering::Acquire),
                2,
                "reusable connection waits for verification retirement"
            );
        }
        let connection = self
            .connection
            .take()
            .expect("reusable backup connection remains live");
        self.cleanup_owner
            .take()
            .expect("reusable backup cleanup owner remains live")
            .shutdown()
            .map_err(|error| {
                database(
                    "release reusable backup cleanup owner",
                    sqlx::Error::Protocol(error),
                )
            })?;
        drop(connection);
        Ok(())
    }

    async fn discard(mut self) -> claw_sqlite_file_control::TerminalCloseOutcome {
        if let Some(cancellation) = &self.cancellation {
            cancellation
                .cancelled
                .store(true, std::sync::atomic::Ordering::Release);
        }
        if let (Some(connection), Some(cleanup_owner)) =
            (self.connection.take(), self.cleanup_owner.take())
        {
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let retirement_fence = self.retirement_fence.take();
            if handoff_state_payload(
                cleanup_owner,
                std::sync::Mutex::new((Some(connection), Some(done_tx), retirement_fence)),
                |_runtime, terminal_closes, payload| {
                    let mut payload = payload
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(signal) = payload.2.take() {
                        while signal.load(std::sync::atomic::Ordering::Acquire) != 2 {
                            std::thread::yield_now();
                        }
                    }
                    let permit = terminal_closes
                        .take_permit()
                        .expect("discard close capacity was pre-reserved");
                    let connection = payload.0.take().expect("discard connection remains owned");
                    let done_tx = payload.1.take().expect("discard result remains owned");
                    let result = permit.close(connection);
                    let _ = done_tx.send(result);
                },
            )
            .is_err()
            {
                return claw_sqlite_file_control::TerminalCloseOutcome::Quarantined;
            }
            return tokio::time::timeout(std::time::Duration::from_secs(1), done_rx)
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(claw_sqlite_file_control::TerminalCloseOutcome::Quarantined);
        }
        claw_sqlite_file_control::TerminalCloseOutcome::Closed
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
        if let Some(connection) = self.connection.take()
            && let Some(cleanup_owner) = self.cleanup_owner.take()
        {
            if let Some(cancellation) = &self.cancellation {
                cancellation
                    .cancelled
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            let retirement_fence = self.retirement_fence.take();
            let _ = handoff_state_payload(
                cleanup_owner,
                std::sync::Mutex::new((Some(connection), retirement_fence)),
                |_runtime, terminal_closes, payload| {
                    let mut payload = payload
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(signal) = payload.1.take() {
                        while signal.load(std::sync::atomic::Ordering::Acquire) != 2 {
                            std::thread::yield_now();
                        }
                    }
                    let permit = terminal_closes
                        .take_permit()
                        .expect("backup drop close capacity was pre-reserved");
                    let _ = permit.close(
                        payload
                            .0
                            .take()
                            .expect("dropped backup connection remains owned"),
                    );
                },
            );
        }
    }
}

pub(crate) struct ProtectedConnectionGuard {
    connection: Option<sqlx::pool::PoolConnection<sqlx::Sqlite>>,
    cleanup_owner: Option<claw_sqlite_file_control::BlockingCleanupOwner>,
}

impl ProtectedConnectionGuard {
    pub(crate) fn new(
        connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
        cleanup_owner: claw_sqlite_file_control::BlockingCleanupOwner,
    ) -> Self {
        Self {
            connection: Some(connection),
            cleanup_owner: Some(cleanup_owner),
        }
    }

    pub(crate) async fn accept(mut self) -> Result<(), String> {
        let owner = self
            .cleanup_owner
            .take()
            .expect("protected connection cleanup owner remains live");
        if let Err(error) = owner.shutdown() {
            let mut connection = self
                .connection
                .take()
                .expect("protected connection remains live after owner failure");
            connection.close_on_drop();
            return match connection.close().await {
                Ok(()) => Err(error),
                Err(close) => Err(format!(
                    "{error}; protected connection close after owner failure: {close}"
                )),
            };
        }
        drop(
            self.connection
                .take()
                .expect("accepted protected connection remains live"),
        );
        Ok(())
    }

    pub(crate) async fn discard_until(
        mut self,
        cleanup_deadline: std::time::Instant,
    ) -> claw_sqlite_file_control::TerminalCloseOutcome {
        let (Some(connection), Some(cleanup_owner)) =
            (self.connection.take(), self.cleanup_owner.take())
        else {
            return claw_sqlite_file_control::TerminalCloseOutcome::Closed;
        };
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let retirement = StateOwnerRetirementReceipt::new();
        if handoff_state_payload_with_completion(
            cleanup_owner,
            std::sync::Mutex::new((Some(connection), Some(done_tx))),
            retirement.signal(),
            |_runtime, terminal_closes, payload| {
                let mut payload = payload
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let permit = terminal_closes
                    .take_permit()
                    .expect("protected discard capacity was pre-reserved");
                let connection = payload
                    .0
                    .take()
                    .expect("protected discard connection remains owned");
                let done_tx = payload
                    .1
                    .take()
                    .expect("protected discard result remains owned");
                let _ = done_tx.send(permit.close(connection));
            },
        )
        .is_err()
        {
            return claw_sqlite_file_control::TerminalCloseOutcome::Quarantined;
        }
        let close =
            tokio::time::timeout_at(tokio::time::Instant::from_std(cleanup_deadline), done_rx)
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(claw_sqlite_file_control::TerminalCloseOutcome::Quarantined);
        if retirement
            .wait(cleanup_deadline, "protected repository connection cleanup")
            .await
            .is_err()
        {
            claw_sqlite_file_control::TerminalCloseOutcome::Quarantined
        } else {
            close
        }
    }
}

impl std::ops::Deref for ProtectedConnectionGuard {
    type Target = SqliteConnection;

    fn deref(&self) -> &Self::Target {
        self.connection
            .as_ref()
            .expect("protected connection remains live")
            .as_ref()
    }
}

impl std::ops::DerefMut for ProtectedConnectionGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connection
            .as_mut()
            .expect("protected connection remains live")
            .as_mut()
    }
}

impl Drop for ProtectedConnectionGuard {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take()
            && let Some(cleanup_owner) = self.cleanup_owner.take()
        {
            let _ = handoff_state_payload(
                cleanup_owner,
                std::sync::Mutex::new(Some(connection)),
                |_runtime, terminal_closes, payload| {
                    let permit = terminal_closes
                        .take_permit()
                        .expect("protected drop close capacity was pre-reserved");
                    let connection = payload
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                        .expect("dropped protected connection remains owned");
                    let _ = permit.close(connection);
                },
            );
        }
    }
}

struct StoreOperationConnection<'store> {
    connection: Option<BackupConnectionGuard>,
    identity: OperationalIdentity<'store>,
    deadline_state: Arc<OpenDeadlineState>,
    deadline: tokio::time::Instant,
    final_identity: Option<OwnedOperationalIdentity>,
    final_identity_owner: Option<claw_sqlite_file_control::BlockingCleanupOwner>,
    checkpoint_worker_owner: Option<claw_sqlite_file_control::BlockingCleanupOwner>,
}

fn compose_terminal_close(
    operation: &'static str,
    primary: StateError,
    close: claw_sqlite_file_control::TerminalCloseOutcome,
) -> StateError {
    if close == claw_sqlite_file_control::TerminalCloseOutcome::Closed {
        primary
    } else {
        append_operation_cleanup(
            operation,
            primary,
            format!("terminal connection close: {close:?}"),
        )
    }
}

impl<'store> StoreOperationConnection<'store> {
    async fn acquire(
        pool: &'store SqlitePool,
        identity: OperationalIdentity<'store>,
        operation: &'static str,
    ) -> Result<Self, StateError> {
        Self::acquire_internal(pool, identity, operation, false).await
    }

    async fn acquire_checkpoint(
        pool: &'store SqlitePool,
        identity: OperationalIdentity<'store>,
        operation: &'static str,
    ) -> Result<Self, StateError> {
        // Four atomic owners (worker, connection cleanup, and two identity checks)
        // fit within the eight slots preserved by the seven-open peak.
        Self::acquire_internal(pool, identity, operation, true).await
    }

    async fn acquire_internal(
        pool: &'store SqlitePool,
        identity: OperationalIdentity<'store>,
        operation: &'static str,
        reserve_checkpoint_worker: bool,
    ) -> Result<Self, StateError> {
        let timeout_ms = u64::try_from(identity.operation_timeout.as_millis()).unwrap_or(u64::MAX);
        let deadline = tokio::time::Instant::now()
            .checked_add(identity.operation_timeout)
            .ok_or(StateError::InvalidValue {
                field: "state operation timeout",
                reason: "is too large for the monotonic clock",
            })?;
        let deadline_state = Arc::new(OpenDeadlineState {
            work_cutoff: deadline.into_std(),
            deadline: deadline.into_std(),
            timeout_ms,
            operation,
            busy_timeout: identity.busy_timeout,
            expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            finished: std::sync::atomic::AtomicBool::new(false),
            final_commit_state: std::sync::atomic::AtomicU8::new(0),
            open_cleanup_state: std::sync::atomic::AtomicU8::new(0),
        });
        let mut owners = claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
            "claw-state-operation-connection",
            if reserve_checkpoint_worker { 4 } else { 3 },
            deadline.into_std(),
        )
        .await
        .map_err(|error| {
            if tokio::time::Instant::now() >= deadline {
                deadline_state.timeout_error()
            } else {
                database(
                    "reserve state operation cleanup owner",
                    sqlx::Error::Protocol(error),
                )
            }
        })?;
        let checkpoint_worker_owner = reserve_checkpoint_worker.then(|| {
            owners
                .pop()
                .expect("state checkpoint worker owner was reserved")
        });
        let final_identity_owner = owners.pop().expect("final state identity owner");
        let initial_identity_owner = owners.pop().expect("initial state identity owner");
        let cleanup_owner = owners.pop().expect("state operation cleanup owner");
        let initial_identity = identity.capture_owned()?;
        let final_identity = identity.capture_owned()?;
        run_bounded_filesystem(
            initial_identity_owner,
            deadline,
            operation,
            timeout_ms,
            move || initial_identity.verify(),
        )
        .await?;
        identity.verify_generation()?;
        if tokio::time::Instant::now() >= deadline {
            return Err(deadline_state.timeout_error());
        }
        let connection = tokio::time::timeout_at(deadline, pool.acquire())
            .await
            .map_err(|_| deadline_state.timeout_error())?
            .map_err(|error| database("acquire state operation connection", error))?;
        let mut connection = BackupConnectionGuard::new_cancellable(
            connection,
            Arc::clone(&deadline_state),
            cleanup_owner,
        );
        let installed = tokio::time::timeout_at(
            deadline,
            install_open_deadline_handler(&mut connection, Some(Arc::clone(&deadline_state))),
        )
        .await;
        if let Err(error) = installed
            .map_err(|_| deadline_state.timeout_error())
            .and_then(std::convert::identity)
        {
            let close =
                tokio::time::timeout_at(deadline + identity.cleanup_timeout, connection.discard())
                    .await
                    .unwrap_or(claw_sqlite_file_control::TerminalCloseOutcome::Quarantined);
            return Err(compose_terminal_close(operation, error, close));
        }
        let verified = tokio::time::timeout_at(
            deadline,
            identity.profile.verify_connection(&mut connection),
        )
        .await;
        if let Err(primary) = verified
            .map_err(|_| deadline_state.timeout_error())
            .and_then(|result| {
                result.map_err(|error| database("verify state operation SQLite identity", error))
            })
        {
            let close =
                tokio::time::timeout_at(deadline + identity.cleanup_timeout, connection.discard())
                    .await
                    .unwrap_or(claw_sqlite_file_control::TerminalCloseOutcome::Quarantined);
            return Err(compose_terminal_close(operation, primary, close));
        }
        Ok(Self {
            connection: Some(connection),
            identity,
            deadline_state,
            deadline,
            final_identity: Some(final_identity),
            final_identity_owner: Some(final_identity_owner),
            checkpoint_worker_owner,
        })
    }

    fn sqlite(&mut self) -> &mut SqliteConnection {
        self.connection
            .as_mut()
            .expect("state operation connection remains owned")
    }

    fn take_checkpoint_connection(&mut self) -> sqlx::pool::PoolConnection<sqlx::Sqlite> {
        self.connection
            .as_mut()
            .expect("checkpoint operation guard remains owned")
            .connection
            .take()
            .expect("checkpoint connection remains owned")
    }

    fn restore_checkpoint_connection(
        &mut self,
        connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    ) {
        assert!(
            self.connection
                .as_mut()
                .expect("checkpoint operation guard remains owned")
                .connection
                .replace(connection)
                .is_none(),
            "checkpoint connection is restored once"
        );
    }

    fn take_checkpoint_worker_owner(&mut self) -> claw_sqlite_file_control::BlockingCleanupOwner {
        self.checkpoint_worker_owner
            .take()
            .expect("checkpoint worker owner remains reserved")
    }

    fn expire(&self) -> StateError {
        self.deadline_state
            .expired
            .store(true, std::sync::atomic::Ordering::Release);
        self.deadline_state.cancel();
        self.deadline_state.timeout_error()
    }

    async fn discard(
        &self,
        connection: BackupConnectionGuard,
    ) -> claw_sqlite_file_control::TerminalCloseOutcome {
        tokio::time::timeout_at(
            self.deadline + self.identity.cleanup_timeout,
            connection.discard(),
        )
        .await
        .unwrap_or(claw_sqlite_file_control::TerminalCloseOutcome::Quarantined)
    }

    async fn verify_checkpoint_identity(
        &mut self,
        cleanup_deadline: std::time::Instant,
    ) -> Result<(), StateError> {
        struct CheckpointIdentityPayload {
            identity: OwnedOperationalIdentity,
            result: Arc<std::sync::Mutex<Option<Result<(), StateError>>>>,
        }

        let identity = self
            .final_identity
            .take()
            .expect("checkpoint final identity remains owned");
        let identity_owner = self
            .final_identity_owner
            .take()
            .expect("checkpoint final identity owner remains reserved");
        let retirement = StateOwnerRetirementReceipt::new();
        self.connection
            .as_mut()
            .expect("checkpoint connection guard remains owned")
            .retain_until(retirement.signal());
        let result = Arc::new(std::sync::Mutex::new(None));
        handoff_state_payload_with_completion(
            identity_owner,
            CheckpointIdentityPayload {
                identity,
                result: Arc::clone(&result),
            },
            retirement.signal(),
            |_, _, payload| {
                #[cfg(test)]
                wait_at_checkpoint_identity_test_gate();
                *payload
                    .result
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(payload.identity.verify());
            },
        )
        .map_err(|cleanup| StateError::OperationCleanupFailed {
            operation: self.deadline_state.operation,
            primary: Box::new(database(
                "handoff checkpoint identity verification",
                sqlx::Error::Protocol(cleanup.clone()),
            )),
            cleanup,
        })?;
        if let Err(cleanup) = retirement
            .wait(
                cleanup_deadline,
                "checkpoint filesystem identity verification",
            )
            .await
        {
            return Err(StateError::OperationCleanupFailed {
                operation: self.deadline_state.operation,
                primary: Box::new(self.deadline_state.timeout_error()),
                cleanup,
            });
        }
        let verified = result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| {
                database(
                    "checkpoint filesystem identity verification",
                    sqlx::Error::Protocol(
                        "checkpoint identity owner retired without a result".to_owned(),
                    ),
                )
            })?;
        verified?;
        self.identity.verify_generation()?;
        if std::time::Instant::now() >= self.deadline.into_std() {
            return Err(self.expire());
        }
        Ok(())
    }

    async fn finish(mut self) -> Result<(), StateError> {
        let mut connection = self
            .connection
            .take()
            .expect("finished state operation connection remains owned");
        if tokio::time::Instant::now() >= self.deadline {
            let error = self.expire();
            let close = self.discard(connection).await;
            return Err(compose_terminal_close(
                self.deadline_state.operation,
                error,
                close,
            ));
        }
        let verified = tokio::time::timeout_at(
            self.deadline,
            self.identity.profile.verify_connection(&mut connection),
        )
        .await;
        let verified = match verified {
            Ok(result) => {
                result.map_err(|error| database("reverify state operation SQLite identity", error))
            }
            Err(_) => Err(self.expire()),
        };
        if let Err(error) = verified {
            let close = self.discard(connection).await;
            return Err(compose_terminal_close(
                self.deadline_state.operation,
                error,
                close,
            ));
        }
        let verified = if let (Some(final_identity), Some(final_identity_owner)) =
            (self.final_identity.take(), self.final_identity_owner.take())
        {
            run_bounded_filesystem(
                final_identity_owner,
                self.deadline,
                self.deadline_state.operation,
                self.deadline_state.timeout_ms,
                move || final_identity.verify(),
            )
            .await
            .and_then(|()| self.identity.verify_generation())
        } else {
            self.identity.verify_generation()
        };
        if let Err(error) = verified {
            let close = self.discard(connection).await;
            return Err(compose_terminal_close(
                self.deadline_state.operation,
                error,
                close,
            ));
        }
        if tokio::time::Instant::now() >= self.deadline {
            let error = self.expire();
            let close = self.discard(connection).await;
            return Err(compose_terminal_close(
                self.deadline_state.operation,
                error,
                close,
            ));
        }
        self.deadline_state
            .finished
            .store(true, std::sync::atomic::Ordering::Release);
        connection.release_reusable()
    }

    async fn fail(mut self, primary: StateError) -> StateError {
        self.deadline_state.cancel();
        let connection = self
            .connection
            .take()
            .expect("failed state operation connection remains owned");
        let close = self.discard(connection).await;
        if close == claw_sqlite_file_control::TerminalCloseOutcome::Closed {
            primary
        } else {
            append_operation_cleanup(
                self.deadline_state.operation,
                primary,
                format!("terminal connection close: {close:?}"),
            )
        }
    }

    fn fail_without_connection(self, primary: StateError) -> StateError {
        self.deadline_state.cancel();
        primary
    }
}

struct OwnedSqliteConnectionGuard {
    connection: Option<SqliteConnection>,
    cancellation: Option<Arc<OpenDeadlineState>>,
    cleanup_owner: Option<claw_sqlite_file_control::BlockingCleanupOwner>,
    backup_lease: Option<BackupStagingLease>,
    backup_output: Option<File>,
    shared_terminal_retention: Option<SharedSnapshotRetention>,
}

struct OwnedConnectionClosePayload {
    connection: Option<SqliteConnection>,
    backup_lease: Option<BackupStagingLease>,
    backup_output: Option<File>,
    shared_terminal_retention: Option<SharedSnapshotRetention>,
    terminal_retention: Option<SharedTerminalRetention>,
    result: Option<
        std::sync::mpsc::SyncSender<(
            claw_sqlite_file_control::TerminalCloseOutcome,
            Option<BackupStagingLease>,
        )>,
    >,
}

fn close_owned_connection_payload(
    payload: &mut OwnedConnectionClosePayload,
    terminal_closes: &mut claw_sqlite_file_control::TerminalCloseBatch,
) -> claw_sqlite_file_control::TerminalCloseOutcome {
    let permit = terminal_closes
        .take_permit()
        .expect("owned connection close capacity was pre-reserved");
    let connection = payload
        .connection
        .take()
        .expect("owned close connection remains live");
    let result = if let Some(retention) = payload.shared_terminal_retention.take() {
        permit.close_with_shared_retention(connection, retention)
    } else {
        permit.close_with_shared_retention(
            connection,
            payload
                .terminal_retention
                .take()
                .expect("owned close terminal retention remains owned"),
        )
    };
    payload.backup_output.take();
    result
}

#[cfg(test)]
fn owned_close_fallback_timeout() -> Duration {
    OWNED_CLOSE_CUTOFF_TEST_CONTROL
        .lock()
        .expect("owned close cutoff control lock poisoned")
        .as_ref()
        .map_or(Duration::from_secs(1), |control| control.fallback_timeout)
}

#[cfg(test)]
fn wait_at_owned_close_result_test_gate() {
    let gate = OWNED_CLOSE_CUTOFF_TEST_CONTROL
        .lock()
        .expect("owned close cutoff control lock poisoned")
        .as_ref()
        .map(|control| {
            (
                Arc::clone(&control.result_entered),
                Arc::clone(&control.result_release),
            )
        });
    if let Some((entered, release)) = gate {
        entered.notify_one();
        while !release.load(std::sync::atomic::Ordering::Acquire) {
            std::thread::yield_now();
        }
    }
}

#[cfg(test)]
fn wait_at_owned_close_retirement_test_gate() {
    let gate = OWNED_CLOSE_CUTOFF_TEST_CONTROL
        .lock()
        .expect("owned close cutoff control lock poisoned")
        .as_ref()
        .map(|control| {
            (
                Arc::clone(&control.retirement_entered),
                Arc::clone(&control.retirement_release),
            )
        });
    if let Some((entered, release)) = gate {
        entered.notify_one();
        while !release.load(std::sync::atomic::Ordering::Acquire) {
            std::thread::yield_now();
        }
    }
}

impl OwnedSqliteConnectionGuard {
    fn new_cancellable_with_owner(
        connection: SqliteConnection,
        cancellation: Option<Arc<OpenDeadlineState>>,
        cleanup_owner: claw_sqlite_file_control::BlockingCleanupOwner,
    ) -> Self {
        Self {
            connection: Some(connection),
            cancellation,
            cleanup_owner: Some(cleanup_owner),
            backup_lease: None,
            backup_output: None,
            shared_terminal_retention: None,
        }
    }

    fn attach_backup_resources(&mut self, lease: BackupStagingLease, output: File) {
        assert!(self.backup_lease.replace(lease).is_none());
        assert!(self.backup_output.replace(output).is_none());
    }

    fn attach_shared_terminal_retention(&mut self, retention: SharedSnapshotRetention) {
        assert!(self.shared_terminal_retention.replace(retention).is_none());
    }

    fn release_connection(
        mut self,
    ) -> (
        SqliteConnection,
        claw_sqlite_file_control::BlockingCleanupOwner,
    ) {
        self.cancellation = None;
        (
            self.connection
                .take()
                .expect("released SQLite connection remains live"),
            self.cleanup_owner
                .take()
                .expect("released SQLite cleanup owner remains live"),
        )
    }

    fn release_to_worker(
        mut self,
    ) -> Result<(SqliteConnection, File, BackupStagingLease), StateError> {
        self.cancellation = None;
        let connection = self
            .connection
            .take()
            .expect("validated backup connection remains live");
        let lease = self
            .backup_lease
            .take()
            .expect("validated backup lease remains owned");
        let output = self
            .backup_output
            .take()
            .expect("validated backup output remains owned");
        self.cleanup_owner
            .take()
            .expect("validated backup cleanup owner remains owned")
            .shutdown()
            .map_err(|error| {
                database(
                    "release backup validation cleanup owner",
                    sqlx::Error::Protocol(error),
                )
            })?;
        Ok((connection, output, lease))
    }

    async fn close(mut self) -> Result<(), sqlx::Error> {
        let connection = self
            .connection
            .take()
            .expect("owned SQLite connection remains live");
        let cleanup_owner = self
            .cleanup_owner
            .take()
            .expect("owned cleanup owner remains live");
        let mut backup_lease = self.backup_lease.take();
        let shared_terminal_retention = self.shared_terminal_retention.take();
        let terminal_retention = shared_terminal_retention.is_none().then(|| {
            Arc::new(std::sync::Mutex::new(backup_lease.as_mut().and_then(
                |lease| {
                    claw_sqlite_file_control::SnapshotCleanupLease::take_terminal_retention(lease)
                },
            )))
        });
        #[cfg(test)]
        let fallback_timeout = owned_close_fallback_timeout();
        #[cfg(not(test))]
        let fallback_timeout = std::time::Duration::from_secs(1);
        let result_cutoff = std::time::Instant::now() + fallback_timeout;
        let retirement_deadline = self
            .cancellation
            .as_ref()
            .map_or(result_cutoff, |state| state.deadline);
        let retirement = StateOwnerRetirementReceipt::new();
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
        handoff_state_payload_with_completion(
            cleanup_owner,
            std::sync::Mutex::new(OwnedConnectionClosePayload {
                connection: Some(connection),
                backup_lease,
                backup_output: self.backup_output.take(),
                shared_terminal_retention,
                terminal_retention,
                result: Some(done_tx),
            }),
            retirement.signal(),
            |_runtime, terminal_closes, payload| {
                let mut payload = payload
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let result = close_owned_connection_payload(&mut payload, terminal_closes);
                #[cfg(test)]
                wait_at_owned_close_result_test_gate();
                let done_tx = payload
                    .result
                    .take()
                    .expect("owned close result remains owned");
                if let Err(error) = done_tx.send((result, payload.backup_lease.take())) {
                    let mut backup_lease = error.0.1;
                    if let Some(lease) = backup_lease.as_mut() {
                        claw_sqlite_file_control::SnapshotCleanupLease::detach_cleanup(lease);
                    }
                    payload.backup_lease = backup_lease;
                }
                #[cfg(test)]
                wait_at_owned_close_retirement_test_gate();
            },
        )
        .map_err(sqlx::Error::Protocol)?;
        self.cancellation = None;
        let (close, mut backup_lease) = loop {
            match done_rx.try_recv() {
                Ok(result) => break result,
                Err(std::sync::mpsc::TryRecvError::Empty)
                    if std::time::Instant::now() < result_cutoff =>
                {
                    tokio::task::yield_now().await;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    return Err(sqlx::Error::Protocol(
                        "owned connection cleanup exceeded its fixed cutoff".to_owned(),
                    ));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err(sqlx::Error::Protocol(
                        "owned connection cleanup stopped without result".to_owned(),
                    ));
                }
            }
        };
        retirement
            .wait(retirement_deadline, "owned SQLite connection cleanup")
            .await
            .map_err(sqlx::Error::Protocol)?;
        if let Some(lease) = backup_lease.as_mut() {
            lease
                .cleanup()
                .await
                .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        }
        match close {
            claw_sqlite_file_control::TerminalCloseOutcome::Closed => Ok(()),
            outcome => Err(sqlx::Error::Protocol(format!(
                "owned connection terminal close did not complete: {outcome:?}"
            ))),
        }
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
        if let Some(connection) = self.connection.take()
            && let Some(cleanup_owner) = self.cleanup_owner.take()
        {
            let mut backup_lease = self.backup_lease.take();
            let shared_terminal_retention = self.shared_terminal_retention.take();
            let terminal_retention = shared_terminal_retention.is_none().then(|| {
                Arc::new(std::sync::Mutex::new(backup_lease.as_mut().and_then(
                    |lease| {
                        claw_sqlite_file_control::SnapshotCleanupLease::take_terminal_retention(
                            lease,
                        )
                    },
                )))
            });
            let _ = handoff_state_payload(
                cleanup_owner,
                std::sync::Mutex::new(OwnedConnectionClosePayload {
                    connection: Some(connection),
                    backup_lease,
                    backup_output: self.backup_output.take(),
                    shared_terminal_retention,
                    terminal_retention,
                    result: None,
                }),
                |_runtime, terminal_closes, payload| {
                    let mut payload = payload
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let _ = close_owned_connection_payload(&mut payload, terminal_closes);
                },
            );
        }
    }
}

async fn close_owned_connection_or_error(
    operation: &'static str,
    connection: OwnedSqliteConnectionGuard,
    primary: StateError,
) -> StateError {
    match connection.close().await {
        Ok(()) => primary,
        Err(error) => append_operation_cleanup(
            operation,
            primary,
            format!("terminal SQLite close failed: {error}"),
        ),
    }
}

async fn discard_backup_connections_or_error(
    source: BackupConnectionGuard,
    destination: OwnedSqliteConnectionGuard,
    primary: StateError,
) -> StateError {
    let source_close = source.discard().await;
    let destination_close = destination.close().await;
    let mut diagnostics = Vec::new();
    if source_close != claw_sqlite_file_control::TerminalCloseOutcome::Closed {
        diagnostics.push(format!("source terminal close: {source_close:?}"));
    }
    if let Err(error) = destination_close {
        diagnostics.push(format!("destination terminal cleanup: {error}"));
    }
    if diagnostics.is_empty() {
        primary
    } else {
        append_operation_cleanup("SQLite backup", primary, diagnostics.join("; "))
    }
}

impl PinnedSnapshot {
    fn open(path: &Path) -> Result<Self, StateError> {
        let file = open_existing_file_no_follow(path)?;
        verify_path_identity(path, &file)?;
        reject_hard_link(path, &file)?;
        Self::from_file(path, file)
    }

    fn open_cleanup(path: &Path) -> Result<Self, StateError> {
        let file = open_cleanup_snapshot_file_no_follow(path)?;
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
        let mut failure = None;
        for (path, file, operation) in [
            (wal_path, _wal_file, "release destination WAL reservation"),
            (shm_path, _shm_file, "release destination SHM reservation"),
            (
                journal_path,
                _journal_file,
                "release destination journal reservation",
            ),
        ] {
            let release = match verify_path_identity(&path, &file) {
                Ok(()) => {
                    drop(file);
                    std::fs::remove_file(&path).map_err(|error| file_error(operation, &path, error))
                }
                Err(error) => {
                    drop(file);
                    Err(error)
                }
            };
            if let Err(error) = release {
                failure = Some(match failure {
                    None => error,
                    Some(primary) => append_operation_cleanup(
                        "release destination sidecar reservations",
                        primary,
                        error.to_string(),
                    ),
                });
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

fn reserve_destination_sidecars(database: &Path) -> Result<SidecarReservations, StateError> {
    for sidecar in database_artifacts(database).into_iter().skip(1) {
        if path_entry_exists(&sidecar)? {
            return Err(StateError::BackupDestinationExists { path: sidecar });
        }
    }
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

fn publish_bound_snapshot(
    snapshot: &PinnedSnapshot,
    cleanup: &mut SnapshotCleanupGuard,
    destination: &Path,
    operation: &'static str,
    publication_deadline: Option<(tokio::time::Instant, u64)>,
    publication_state: Option<&OpenDeadlineState>,
    destination_directory: &PinnedPrivateDirectory,
) -> Result<(), StateError> {
    snapshot.verify()?;
    verify_directory_path_identity(&destination_directory.path, &destination_directory.file)?;
    if let Some((deadline, timeout_ms)) = publication_deadline
        && (tokio::time::Instant::now() >= deadline
            || take_publication_deadline_expiration(destination, 0))
    {
        return Err(StateError::OperationTimedOut {
            operation,
            timeout_ms,
        });
    }
    let reservations = reserve_destination_sidecars(destination)?;
    if let Err(error) = verify_path_identity(destination, &snapshot.file) {
        let cleanup = reservations.release();
        return Err(append_operation_cleanup(
            operation,
            error,
            format!(
                "sidecar reservation cleanup: {}",
                result_diagnostic(cleanup)
            ),
        ));
    }
    if let Err(error) = reservations.release() {
        cleanup.mark_publication_uncertain();
        return Err(StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: format!("bound snapshot sidecar reservation release failed: {error}"),
        });
    }
    if let Some((deadline, timeout_ms)) = publication_deadline
        && (tokio::time::Instant::now() >= deadline
            || take_publication_deadline_expiration(destination, 1))
    {
        return Err(StateError::OperationTimedOut {
            operation,
            timeout_ms,
        });
    }
    if let Some(publication_state) = publication_state {
        publication_state.begin_final_commit()?;
    }
    cleanup.begin_publication();
    if let Err(error) = cleanup.clear_staging_marker() {
        if let Some(publication_state) = publication_state {
            let _ = publication_state.finish_final_commit();
        }
        cleanup.mark_publication_uncertain();
        return Err(StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: format!("bound snapshot staging marker removal failed: {error}"),
        });
    }
    if publication_state.is_some_and(|state| !state.finish_final_commit()) {
        cleanup.mark_publication_uncertain();
        return Err(StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: format!("{operation} cancellation raced with publication"),
        });
    }
    if publication_deadline.is_some_and(|(deadline, _)| {
        tokio::time::Instant::now() >= deadline
            || take_publication_deadline_expiration(destination, 2)
    }) {
        cleanup.mark_publication_uncertain();
        return Err(StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: format!("{operation} deadline expired immediately after publication"),
        });
    }
    #[cfg(all(test, windows))]
    if take_publication_failpoint(&FAIL_WINDOWS_SOURCE_REMOVAL, destination) {
        return Err(StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: "injected post-publication Windows failure".to_owned(),
        });
    }
    #[cfg(test)]
    if take_publication_failpoint(&FAIL_AFTER_PUBLICATION, destination) {
        return Err(StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: "injected post-publication failure".to_owned(),
        });
    }
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))]
    let publication_sync = sync_published_snapshot(snapshot, destination, destination_directory);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    )))]
    let publication_sync = sync_parent_directory(destination);
    publication_sync.map_err(|error| StateError::PublicationUncertain {
        path: destination.to_owned(),
        reason: format!("bound snapshot was published but sync failed: {error}"),
    })?;
    if publication_deadline.is_some_and(|(deadline, _)| {
        tokio::time::Instant::now() >= deadline
            || take_publication_deadline_expiration(destination, 3)
    }) {
        cleanup.mark_publication_uncertain();
        return Err(StateError::PublicationUncertain {
            path: destination.to_owned(),
            reason: format!("{operation} deadline expired after durable publication sync"),
        });
    }
    Ok(())
}

#[cfg(test)]
fn take_publication_deadline_expiration(destination: &Path, stage: u8) -> bool {
    let mut expirations = EXPIRE_PUBLICATION_DEADLINE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if expirations.get(destination) == Some(&stage) {
        expirations.remove(destination);
        true
    } else {
        false
    }
}

#[cfg(not(test))]
fn take_publication_deadline_expiration(_destination: &Path, _stage: u8) -> bool {
    false
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
            reason: "state directory does not have the exact protected service DACL",
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

fn result_diagnostic(result: Result<(), StateError>) -> String {
    match result {
        Ok(()) => "ok".to_owned(),
        Err(error) => error.to_string(),
    }
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

#[cfg(windows)]
fn acquire_creation_lock(path: &Path) -> Result<Option<File>, StateError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.len() == 0 => {}
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(file_error("inspect Windows creation path", path, error)),
    }
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".creation.lock");
    let lock_path = PathBuf::from(lock_path);
    let lock_file = open_database_file(&lock_path)?;
    match lock_file.try_lock() {
        Ok(()) => Ok(Some(lock_file)),
        Err(std::fs::TryLockError::WouldBlock) => Err(StateError::StoreLocked { path: lock_path }),
        Err(std::fs::TryLockError::Error(error)) => Err(file_error(
            "acquire Windows database creation lock",
            &lock_path,
            error,
        )),
    }
}

#[cfg(all(not(unix), not(windows)))]
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
    if length > MAX_WRITER_LOCK_CONTENT_BYTES {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "writer-lock identity contents are too large",
        });
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| file_error("seek writer-lock contents", path, error))?;
    let mut contents = String::new();
    (&mut *file)
        .take(MAX_WRITER_LOCK_CONTENT_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| file_error("read writer-lock contents", path, error))?;
    if contents.len() as u64 > MAX_WRITER_LOCK_CONTENT_BYTES {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "writer-lock identity contents are too large",
        });
    }
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
    (&mut *file)
        .take(MAX_WRITER_LOCK_CONTENT_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| file_error("read writer-lock contents", path, error))?;
    if contents.len() as u64 > MAX_WRITER_LOCK_CONTENT_BYTES {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "writer-lock contents are too large",
        });
    }
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
fn open_writer_lock(path: &Path) -> Result<File, StateError> {
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
    Ok(file)
}

#[cfg(windows)]
fn lock_writer_file(path: &Path, file: File) -> Result<File, StateError> {
    if !claw_sqlite_file_control::windows_try_lock_writer_marker(&file)
        .map_err(|error| file_error("acquire writer lock", path, error))?
    {
        Err(StateError::StoreLocked {
            path: path.to_owned(),
        })
    } else {
        Ok(file)
    }
}

#[cfg(windows)]
fn acquire_writer_lock(path: &Path) -> Result<File, StateError> {
    lock_writer_file(path, open_writer_lock(path)?)
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

#[cfg(target_os = "linux")]
fn acquire_linux_protected_store_lock(
    namespace: &Arc<ProtectedNamespace>,
) -> Result<(PathBuf, File, ProcessIdentityGuard), StateError> {
    use std::os::unix::fs::MetadataExt as _;

    namespace.verify()?;
    let database_file = namespace.clone_database()?;
    let metadata = database_file.metadata().map_err(|error| {
        file_error(
            "inspect LinuxProtected process identity",
            namespace.database_path(),
            error,
        )
    })?;
    let identity = (metadata.dev(), metadata.ino());
    if !PROCESS_IDENTITIES
        .lock()
        .expect("process identity registry lock poisoned")
        .insert(identity)
    {
        return Err(StateError::StoreLocked {
            path: namespace.writer_lock_path().to_owned(),
        });
    }
    let guard = ProcessIdentityGuard {
        identity: Some(identity),
    };
    let lock_path = namespace.writer_lock_path().to_owned();
    let lock_file = namespace.clone_writer_lock()?;
    acquire_private_lock(&lock_path, &lock_file)?;
    namespace.verify()?;
    Ok((lock_path, lock_file, guard))
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
    let mut lock_guard = open_writer_lock(&lock_path)?;
    validate_private_database_file(&lock_path, &lock_guard)?;
    let database_identity = claw_sqlite_file_control::windows_file_identity(database_file)
        .map_err(|_| StateError::InvalidPath {
            path: path.to_owned(),
            reason: "stable Windows database identity is unavailable",
        })?;
    let lock_identity =
        claw_sqlite_file_control::windows_file_identity(&lock_guard).map_err(|_| {
            StateError::InvalidPath {
                path: lock_path.clone(),
                reason: "stable Windows lock identity is unavailable",
            }
        })?;
    if lock_guard
        .metadata()
        .map_err(|error| file_error("inspect Windows writer-lock header", &lock_path, error))?
        .len()
        > MAX_WRITER_LOCK_CONTENT_BYTES
    {
        return Err(StateError::InvalidPath {
            path: lock_path,
            reason: "Windows writer-lock header is too large",
        });
    }
    let mut contents = String::new();
    lock_guard
        .seek(SeekFrom::Start(0))
        .and_then(|_| {
            (&mut lock_guard)
                .take(MAX_WRITER_LOCK_CONTENT_BYTES + 1)
                .read_to_string(&mut contents)
        })
        .map_err(|error| file_error("read Windows writer-lock header", &lock_path, error))?;
    if contents.len() as u64 > MAX_WRITER_LOCK_CONTENT_BYTES {
        return Err(StateError::InvalidPath {
            path: lock_path,
            reason: "Windows writer-lock header is too large",
        });
    }
    let header_prefix = format!(
        "v2\n{}\n{}\n",
        hex_encode(&database_identity),
        hex_encode(&lock_identity)
    );
    if contents.is_empty() {
        contents = format!("{header_prefix}{}", writer_owner()?);
        lock_guard
            .seek(SeekFrom::Start(0))
            .and_then(|_| lock_guard.write_all(contents.as_bytes()))
            .and_then(|_| lock_guard.sync_all())
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
    let lock_file = open_windows_file_no_follow(&lock_path, false, false)?;
    validate_private_database_file(&lock_path, &lock_file)?;
    if claw_sqlite_file_control::windows_file_identity(&lock_file).map_err(|_| {
        StateError::InvalidPath {
            path: lock_path.clone(),
            reason: "stable Windows lock identity is unavailable",
        }
    })? != lock_identity
    {
        return Err(StateError::InvalidPath {
            path: lock_path,
            reason: "Windows writer-lock identity changed while acquiring ownership",
        });
    }
    let lock_guard = lock_writer_file(&lock_path, lock_guard)?;
    Ok((
        lock_path,
        lock_file,
        ProcessIdentityGuard {
            lock_file: Some(lock_guard),
        },
    ))
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
    if file
        .metadata()
        .map_err(|error| file_error("inspect Windows writer-lock header", lock_path, error))?
        .len()
        > MAX_WRITER_LOCK_CONTENT_BYTES
    {
        return Err(StateError::InvalidPath {
            path: lock_path.to_owned(),
            reason: "Windows writer-lock header is too large",
        });
    }
    let mut contents = Vec::new();
    file.seek(SeekFrom::Start(0))
        .and_then(|_| {
            (&mut file)
                .take(MAX_WRITER_LOCK_CONTENT_BYTES + 1)
                .read_to_end(&mut contents)
        })
        .map_err(|error| file_error("read Windows writer-lock header", lock_path, error))?;
    if contents.len() as u64 > MAX_WRITER_LOCK_CONTENT_BYTES {
        return Err(StateError::InvalidPath {
            path: lock_path.to_owned(),
            reason: "Windows writer-lock header is too large",
        });
    }
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

    let database_file = open_windows_file_no_follow(database, false, false)?;
    let link_count = claw_sqlite_file_control::windows_file_link_count(&database_file)
        .map_err(|error| file_control_database("inspect Windows database links", error))?;
    if link_count != 1 {
        return Err(StateError::InvalidPath {
            path: database.to_owned(),
            reason: "hard-linked SQLite databases are not supported",
        });
    }

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
    (&mut identity_file)
        .take(MAX_IDENTITY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| file_error("read writer lock identity", database, error))?;
    if bytes.len() as u64 > MAX_IDENTITY_BYTES {
        return Err(StateError::InvalidPath {
            path: database.to_owned(),
            reason: "writer lock identity metadata is too large",
        });
    }
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
                if claw_sqlite_file_control::windows_file_final_path(&stored_file)
                    .map_err(|error| file_control_database("resolve stored Windows path", error))?
                    != claw_sqlite_file_control::windows_file_final_path(&database_file).map_err(
                        |error| file_control_database("resolve current Windows path", error),
                    )?
                    || claw_sqlite_file_control::windows_file_identity(&stored_file).map_err(
                        |error| file_control_database("identify stored Windows path", error),
                    )? != claw_sqlite_file_control::windows_file_identity(&database_file)
                        .map_err(|error| {
                            file_control_database("identify current Windows path", error)
                        })?
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
    drop(identity_file);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InspectedDatabase {
    Fresh,
    Existing { schema_version: i64 },
}

struct InitializedDatabase {
    recovered_writer: Option<RecoveredWriterLock>,
    undelivered_cleanup_owner: claw_sqlite_file_control::BlockingCleanupOwner,
    open_transaction_admission: tokio::sync::SemaphorePermit<'static>,
}

impl std::fmt::Debug for InitializedDatabase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitializedDatabase")
            .finish_non_exhaustive()
    }
}

async fn inspect_database(
    path: &Path,
    database_file: &File,
    require_latest: bool,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<InspectedDatabase, StateError> {
    let inspection_deadline = deadline_state.as_ref().map_or_else(
        || tokio::time::Instant::now() + MAX_CONFIGURED_TIMEOUT,
        |state| tokio::time::Instant::from_std(state.deadline),
    );
    let inspection_timeout = || {
        deadline_state.as_ref().map_or(
            StateError::OperationTimedOut {
                operation: "SQLite database inspection",
                timeout_ms: u64::try_from(MAX_CONFIGURED_TIMEOUT.as_millis())
                    .expect("timeout fits u64"),
            },
            |state| state.timeout_error(),
        )
    };
    if database_file
        .metadata()
        .map_err(|error| file_error("inspect state database", path, error))?
        .len()
        == 0
    {
        return Ok(InspectedDatabase::Fresh);
    }
    ensure_state_cleanup_executor(inspection_deadline)
        .await
        .map_err(|error| {
            database(
                "prepare database inspection cleanup executor",
                sqlx::Error::Protocol(error),
            )
        })?;
    verify_path_identity(path, database_file)?;
    let wal = sqlite_sidecar(path, "-wal");
    let shm = sqlite_sidecar(path, "-shm");
    let has_wal = path_entry_exists(&wal)?;
    if has_wal != path_entry_exists(&shm)? {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "snapshot source has an ambiguous WAL/SHM artifact set",
        });
    }
    if !has_wal {
        let mut inspection = tokio::time::timeout_at(
            inspection_deadline,
            SqliteConnection::connect_with(
                &SqliteConnectOptions::new()
                    .filename(path)
                    .read_only(true)
                    .create_if_missing(false)
                    .immutable(true)
                    .foreign_keys(true),
            ),
        )
        .await
        .map_err(|_| inspection_timeout())?
        .map_err(|error| database("open immutable database inspection", error))?;
        install_open_deadline_handler(&mut inspection, deadline_state.clone()).await?;
        let result = inspect_database_connection(&mut inspection, path, require_latest).await;
        let close = tokio::time::timeout_at(inspection_deadline, inspection.close())
            .await
            .map_err(|_| inspection_timeout())
            .and_then(|result| {
                result.map_err(|error| database("close immutable database inspection", error))
            });
        verify_path_identity(path, database_file)?;
        return match (result, close) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(inspected), Ok(())) => Ok(inspected),
        };
    }
    let wal_bytes = std::fs::metadata(&wal)
        .map_err(|error| file_error("inspect WAL size", &wal, error))?
        .len();
    let main_bytes = database_file
        .metadata()
        .map_err(|error| file_error("inspect database size", path, error))?
        .len();
    if main_bytes.saturating_add(wal_bytes) > MAX_AUTHENTICATED_SNAPSHOT_BYTES {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: "WAL-backed inspection exceeds the bounded memory limit".to_owned(),
        });
    }
    let deadline = deadline_state.as_ref().map_or_else(
        || std::time::Instant::now() + MAX_CONFIGURED_TIMEOUT,
        |state| state.work_cutoff,
    );
    let timeout_ms = deadline_state.as_ref().map_or_else(
        || u64::try_from(MAX_CONFIGURED_TIMEOUT.as_millis()).expect("timeout fits u64"),
        |state| state.timeout_ms,
    );
    let snapshot_memory =
        reserve_snapshot_memory(deadline.into(), "SQLite database inspection", timeout_ms).await?;
    let mut cleanup_owners = claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
        "claw-state-inspection-owner-set",
        3,
        deadline,
    )
    .await
    .map_err(|error| {
        file_control_database(
            "reserve database inspection worker and cleanup owners",
            claw_sqlite_file_control::FileControlError::Handle(error),
        )
    })?;
    let worker_owner = cleanup_owners.pop().expect("inspection worker owner");
    let inspection_cleanup_owner = cleanup_owners
        .pop()
        .expect("inspection destination cleanup owner");
    let source_cleanup_owner = cleanup_owners
        .pop()
        .expect("inspection source cleanup owner");
    let inspection = tokio::time::timeout_at(
        inspection_deadline,
        SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .in_memory(true)
                .foreign_keys(true),
        ),
    )
    .await
    .map_err(|_| inspection_timeout())?
    .map_err(|error| database("open in-memory database inspection", error))?;
    let mut source = tokio::time::timeout_at(
        inspection_deadline,
        SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .filename(path)
                .read_only(true)
                .create_if_missing(false)
                .immutable(!has_wal)
                .busy_timeout(Duration::ZERO),
        ),
    )
    .await
    .map_err(|_| inspection_timeout())?
    .map_err(|error| database("open database inspection source", error))?;
    let max_pages = bounded_backup_max_pages(&mut source).await?;
    let cancelled = deadline_state.as_ref().map_or_else(
        || Arc::new(std::sync::atomic::AtomicBool::new(false)),
        |state| Arc::clone(&state.cancelled),
    );
    let (source, inspection, _snapshot_memory) =
        claw_sqlite_file_control::backup_owned_main_database_with_cleanup_deadline(
            worker_owner,
            source,
            inspection,
            snapshot_memory,
            claw_sqlite_file_control::BackupExecutionContext {
                deadline,
                cancelled,
                max_pages,
                source_busy_timeout: Duration::ZERO,
                destination_busy_timeout: Duration::ZERO,
            },
            inspection_deadline.into_std(),
        )
        .await
        .map_err(|error| file_control_database("copy database for inspection", error))?;
    let source = OwnedSqliteConnectionGuard::new_cancellable_with_owner(
        source,
        deadline_state.clone(),
        source_cleanup_owner,
    );
    source
        .close()
        .await
        .map_err(|error| database("close inspection source", error))?;
    let mut inspection = OwnedSqliteConnectionGuard::new_cancellable_with_owner(
        inspection,
        deadline_state.clone(),
        inspection_cleanup_owner,
    );
    install_open_deadline_handler(&mut inspection, deadline_state.clone()).await?;
    let result = inspect_database_connection(&mut inspection, path, require_latest).await;
    let close = inspection
        .close()
        .await
        .map_err(|error| database("close in-memory database inspection", error));
    verify_path_identity(path, database_file)?;
    match (result, close) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(inspected), Ok(())) => Ok(inspected),
    }
}

async fn inspect_database_connection(
    connection: &mut SqliteConnection,
    source_path: &Path,
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
    let writer_table_exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sqlite_schema
         WHERE type = 'table' AND name = 'claw_writer_lock'",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(|error| database("inspect writer-lock schema", error))?
        == 1;
    let provenance = if writer_table_exists {
        sqlx::query_scalar::<_, String>("SELECT owner FROM claw_writer_lock WHERE singleton = 1")
            .fetch_optional(&mut *connection)
            .await
            .map_err(|error| database("inspect standalone snapshot provenance", error))?
    } else {
        None
    };
    if provenance.as_deref() == Some(SNAPSHOT_PROVENANCE_OWNER) {
        return Err(StateError::InvalidBackup {
            path: source_path.to_owned(),
            reason: "standalone snapshots must be consumed with StateStore::restore_backup"
                .to_owned(),
        });
    }
    Ok(InspectedDatabase::Existing { schema_version })
}

#[cfg(test)]
async fn wait_at_application_id_read_test_barrier(path: &Path, deadline_state: &OpenDeadlineState) {
    let barrier = APPLICATION_ID_READ_TEST_BARRIER
        .lock()
        .expect("application-id read barrier lock poisoned")
        .get(path)
        .map(|barrier| (Arc::clone(&barrier.entered), Arc::clone(&barrier.release)));
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
        APPLICATION_ID_READ_TEST_BARRIER
            .lock()
            .expect("application-id read barrier lock poisoned")
            .remove(path);
    }
}

async fn initialize_database(
    pool: &SqlitePool,
    path: &Path,
    inspected: InspectedDatabase,
    owner: &str,
    deadline_state: Arc<OpenDeadlineState>,
    transaction_admission: tokio::sync::SemaphorePermit<'static>,
) -> Result<InitializedDatabase, StateError> {
    if inspected == InspectedDatabase::Fresh {
        return initialize_fresh_database(pool, path, owner, deadline_state, transaction_admission)
            .await;
    }
    let mut application_connection = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline_state.work_cutoff),
        pool.acquire(),
    )
    .await
    .map_err(|_| deadline_state.timeout_error())?
    .map_err(|error| database("acquire application-id revalidation connection", error))?;
    #[cfg(test)]
    wait_at_application_id_read_test_barrier(path, &deadline_state).await;
    let application_id = claw_sqlite_file_control::read_application_id_with_deadline(
        &mut application_connection,
        deadline_state.work_cutoff,
        Arc::clone(&deadline_state.cancelled),
    )
    .await
    .map_err(|error| {
        if error.code() == Some(9) || std::time::Instant::now() >= deadline_state.work_cutoff {
            deadline_state.timeout_error()
        } else {
            file_control_database("read SQLite application id", error)
        }
    })?;
    install_open_deadline_handler(
        &mut application_connection,
        Some(Arc::clone(&deadline_state)),
    )
    .await?;
    drop(application_connection);
    if application_id != APPLICATION_ID {
        return Err(StateError::InvalidValue {
            field: "SQLite application id",
            reason: "database belongs to another application",
        });
    }
    apply_migrations(pool, path, owner, deadline_state, transaction_admission).await
}

struct OpenTransactionOwners {
    admission: tokio::sync::SemaphorePermit<'static>,
    primary_begin: Vec<claw_sqlite_file_control::BlockingCleanupOwner>,
    late_begin: Vec<claw_sqlite_file_control::BlockingCleanupOwner>,
    undelivered: claw_sqlite_file_control::BlockingCleanupOwner,
}

#[cfg(test)]
fn mark_reserved_owner_path_for_test(path: &Path) {
    if OPEN_RESERVED_OWNER_GATE_REMAINING
        .fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |remaining| remaining.checked_sub(1),
        )
        .is_ok()
    {
        OPEN_RESERVED_OWNER_PATHS
            .lock()
            .expect("reserved owner path set lock poisoned")
            .insert(path.to_owned());
    }
}

async fn reserve_open_transaction_owners(
    deadline_state: &OpenDeadlineState,
    admission: tokio::sync::SemaphorePermit<'static>,
) -> Result<OpenTransactionOwners, StateError> {
    let mut owners = claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
        "state-open-transaction",
        7,
        deadline_state.work_cutoff,
    )
    .await
    .map_err(|error| {
        if std::time::Instant::now() >= deadline_state.work_cutoff || error.contains("timed out") {
            deadline_state.timeout_error()
        } else {
            database(
                "reserve late writer-claim cleanup capacity",
                sqlx::Error::Protocol(error),
            )
        }
    })?;
    let undelivered = owners
        .pop()
        .expect("undelivered cleanup owner was reserved");
    let late_begin = owners.split_off(3);
    Ok(OpenTransactionOwners {
        admission,
        primary_begin: owners,
        late_begin,
        undelivered,
    })
}

fn shutdown_cleanup_owners(
    owners: Vec<claw_sqlite_file_control::BlockingCleanupOwner>,
) -> Result<(), StateError> {
    for owner in owners {
        owner.shutdown().map_err(|error| {
            database(
                "release late writer-claim cleanup capacity",
                sqlx::Error::Protocol(error),
            )
        })?;
    }
    Ok(())
}

fn shutdown_late_claim_cleanup_owners(
    mut begin_owners: Vec<claw_sqlite_file_control::BlockingCleanupOwner>,
    undelivered_owner: claw_sqlite_file_control::BlockingCleanupOwner,
) -> Result<(), StateError> {
    begin_owners.push(undelivered_owner);
    shutdown_cleanup_owners(begin_owners)
}

async fn reject_late_open_claim(
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    cleanup_owner: claw_sqlite_file_control::BlockingCleanupOwner,
    terminal_permit: claw_sqlite_file_control::TerminalClosePermit,
    late_begin_owners: Vec<claw_sqlite_file_control::BlockingCleanupOwner>,
    owner: &str,
    deadline_state: &OpenDeadlineState,
    cleanup_operation: &'static str,
) -> StateError {
    struct LateClaimCleanupPayload {
        connection: Option<sqlx::pool::PoolConnection<sqlx::Sqlite>>,
        terminal_permit: Option<claw_sqlite_file_control::TerminalClosePermit>,
        owner: String,
        deadline: std::time::Instant,
        busy_timeout: Duration,
        late_begin_owners: Option<Vec<claw_sqlite_file_control::BlockingCleanupOwner>>,
        result: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    }

    let _ = deadline_state.retain_open_cleanup();
    let primary = deadline_state.timeout_error();
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let handoff = handoff_state_payload_decide(
        cleanup_owner,
        std::sync::Mutex::new(LateClaimCleanupPayload {
            connection: Some(connection),
            terminal_permit: Some(terminal_permit),
            owner: owner.to_owned(),
            deadline: deadline_state.deadline,
            busy_timeout: deadline_state.busy_timeout,
            late_begin_owners: Some(late_begin_owners),
            result: Some(result_tx),
        }),
        |runtime, _, payload| {
            let mut payload = payload
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let cleanup_deadline = payload.deadline;
            let work_deadline = cleanup_deadline
                .checked_sub(Duration::from_millis(10))
                .unwrap_or(cleanup_deadline);
            let owner = payload.owner.clone();
            let busy_timeout = payload.busy_timeout;
            let late_begin_owners = payload
                .late_begin_owners
                .take()
                .expect("late-claim BEGIN owners remain reserved");
            let connection = payload
                .connection
                .take()
                .expect("late-claim connection remains owned");
            let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (connection, post_commit_owner, cleanup) = runtime.block_on(async {
                let mut transaction =
                    match claw_sqlite_file_control::begin_manual_pool_transaction_with_restore_deadlines_and_owners(
                        connection,
                        work_deadline,
                        cleanup_deadline,
                        busy_timeout,
                        busy_timeout,
                        Some(Arc::clone(&cancelled)),
                        late_begin_owners,
                    )
                    .await
                    {
                        Ok(transaction) => transaction,
                        Err(error) => return (None, None, Err(error.to_string())),
                    };
                let deletion = transaction
                    .delete_writer_claim_with_deadline(
                        &owner,
                        work_deadline,
                        Arc::clone(&cancelled),
                    )
                    .await;
                let deletion = match deletion {
                    Ok(1) => 1,
                    Ok(_) => {
                        let error =
                            "late writer claim cleanup did not own the committed row".to_owned();
                        return match transaction.rollback().await {
                            Ok(connection) => (Some(connection), None, Err(error)),
                            Err(cleanup) => (
                                None,
                                None,
                                Err(format!("{error}; rollback failed: {cleanup}")),
                            ),
                        };
                    }
                    Err(error) => {
                        let error = error.to_string();
                        return match transaction.rollback().await {
                            Ok(connection) => (Some(connection), None, Err(error)),
                            Err(cleanup) => (
                                None,
                                None,
                                Err(format!("{error}; rollback failed: {cleanup}")),
                            ),
                        };
                    }
                };
                let _ = deletion;
                match transaction
                    .commit_with_deadline(
                        work_deadline,
                        cleanup_deadline,
                        cancelled,
                        busy_timeout,
                        None,
                    )
                    .await
                {
                    Ok((connection, post_commit_owner)) => {
                        (Some(connection), Some(post_commit_owner), Ok(()))
                    }
                    Err(error) => (None, None, Err(error.to_string())),
                }
            });
            let close = if let Some(connection) = connection {
                match payload
                    .terminal_permit
                    .take()
                    .expect("late-claim terminal permit remains owned")
                    .close(connection)
                {
                    claw_sqlite_file_control::TerminalCloseOutcome::Closed => Ok(()),
                    outcome => Err(format!("terminal close did not complete: {outcome:?}")),
                }
            } else {
                payload.terminal_permit.take();
                Ok(())
            };
            let owner_shutdown = post_commit_owner.map_or(Ok(()), |owner| owner.shutdown());
            let outcome = match (cleanup, close, owner_shutdown) {
                (Ok(()), Ok(()), Ok(())) => Ok(()),
                (Err(cleanup), Ok(()), Ok(())) => Err(cleanup),
                (Ok(()), Err(close), Ok(())) => Err(close),
                (Ok(()), Ok(()), Err(owner)) => Err(owner),
                (Err(cleanup), Err(close), Ok(())) => Err(format!("{cleanup}; {close}")),
                (Err(cleanup), Ok(()), Err(owner)) => Err(format!("{cleanup}; {owner}")),
                (Ok(()), Err(close), Err(owner)) => Err(format!("{close}; {owner}")),
                (Err(cleanup), Err(close), Err(owner)) => {
                    Err(format!("{cleanup}; {close}; {owner}"))
                }
            };
            if let Some(result) = payload.result.take() {
                let _ = result.send(outcome.clone());
            }
            true
        },
    );
    if let Err(error) = handoff {
        let _ = error;
        std::future::pending::<()>().await;
        unreachable!("failed late-claim handoff retains lifecycle ownership");
    }
    match result_rx.await {
        Ok(Ok(())) => primary,
        Ok(Err(error)) => StateError::OperationCleanupFailed {
            operation: cleanup_operation,
            primary: Box::new(primary),
            cleanup: error,
        },
        Err(_) => StateError::OperationCleanupFailed {
            operation: cleanup_operation,
            primary: Box::new(primary),
            cleanup: "late writer-claim terminal owner stopped without result".to_owned(),
        },
    }
}

async fn initialize_fresh_database(
    pool: &SqlitePool,
    path: &Path,
    owner: &str,
    deadline_state: Arc<OpenDeadlineState>,
    transaction_admission: tokio::sync::SemaphorePermit<'static>,
) -> Result<InitializedDatabase, StateError> {
    #[cfg(not(test))]
    let _ = path;
    let OpenTransactionOwners {
        admission: open_transaction_admission,
        primary_begin,
        late_begin: late_begin_owners,
        undelivered: undelivered_cleanup_owner,
    } = reserve_open_transaction_owners(&deadline_state, transaction_admission).await?;
    #[cfg(test)]
    mark_reserved_owner_path_for_test(path);
    let pooled = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline_state.work_cutoff),
        pool.acquire(),
    )
    .await
    .map_err(|_| deadline_state.timeout_error())?
    .map_err(|error| database("acquire state database bootstrap connection", error))?;
    let mut connection =
        claw_sqlite_file_control::begin_manual_pool_transaction_with_restore_deadlines_and_owners(
            pooled,
            deadline_state.work_cutoff,
            deadline_state.deadline,
            deadline_state.busy_timeout,
            deadline_state.busy_timeout,
            None,
            primary_begin,
        )
        .await
        .map_err(|error| {
            if error.code() == Some(9) || std::time::Instant::now() >= deadline_state.work_cutoff {
                deadline_state.timeout_error()
            } else {
                file_control_database("begin state database bootstrap", error)
            }
        })?;
    #[cfg(test)]
    wait_at_migration_test_barrier(path, &deadline_state).await;
    let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
        .fetch_one(&mut connection)
        .await
        .map_err(|error| database("revalidate bootstrap application id", error))?;
    let existing_objects = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
    )
    .fetch_one(&mut connection)
    .await
    .map_err(|error| database("revalidate bootstrap schema emptiness", error))?;
    if application_id != 0 || existing_objects != 0 {
        return Err(StateError::InvalidMigrationHistory {
            reason: "fresh database ownership or schema changed before bootstrap".to_owned(),
        });
    }
    sqlx::query("PRAGMA application_id = 1196704067")
        .execute(&mut connection)
        .await
        .map_err(|error| database("set SQLite application id", error))?;
    sqlx::query(MIGRATION_TABLE_SQL)
        .execute(&mut connection)
        .await
        .map_err(|error| database("create migration table", error))?;
    for migration in MIGRATIONS {
        connection
            .execute_script(migration.sql)
            .await
            .map_err(|error| database("apply bootstrap migration", error))?;
        sqlx::query(
            "INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
             VALUES (?, ?, ?, CAST(unixepoch('subsec') * 1000 AS INTEGER))",
        )
        .bind(migration.version)
        .bind(migration.name)
        .bind(migration_checksum(migration.sql))
        .execute(&mut connection)
        .await
        .map_err(|error| database("record bootstrap migration", error))?;
    }
    set_sqlite_user_version(&mut connection, LATEST_SCHEMA_VERSION).await?;
    let recovered_writer = claim_application_lock_connection(&mut connection, owner, path).await?;
    validate_operational_schema(&mut connection).await?;
    #[cfg(test)]
    wait_at_open_precommit_test_barrier(path, &deadline_state).await;
    if let Err(error) = deadline_state.begin_final_commit() {
        let owner_cleanup =
            shutdown_late_claim_cleanup_owners(late_begin_owners, undelivered_cleanup_owner).err();
        let error = match owner_cleanup {
            Some(cleanup) => {
                append_operation_cleanup("rollback cancelled bootstrap", error, cleanup.to_string())
            }
            None => error,
        };
        return match connection.rollback().await {
            Ok(_) => Err(error),
            Err(cleanup) => Err(append_operation_cleanup(
                "rollback cancelled bootstrap",
                error,
                cleanup.to_string(),
            )),
        };
    }
    let commit = connection
        .commit_with_deadline(
            deadline_state.work_cutoff,
            deadline_state.deadline,
            Arc::clone(&deadline_state.cancelled),
            deadline_state.busy_timeout,
            Some(owner.to_owned()),
        )
        .await;
    let commit_eligible = deadline_state.finish_final_commit();
    let (connection, mut cleanup_owner) = match commit {
        Ok(committed) => committed,
        Err(error) => {
            let primary = file_control_database("commit state database bootstrap", error);
            return Err(
                match shutdown_late_claim_cleanup_owners(
                    late_begin_owners,
                    undelivered_cleanup_owner,
                ) {
                    Ok(()) => primary,
                    Err(cleanup) => append_operation_cleanup(
                        "commit state database bootstrap",
                        primary,
                        cleanup.to_string(),
                    ),
                },
            );
        }
    };
    let terminal_permit = cleanup_owner.take_terminal_permit().map_err(|error| {
        database(
            "reserve late bootstrap cleanup",
            sqlx::Error::Protocol(error),
        )
    })?;
    if !commit_eligible || !deadline_state.permits_sqlite_work() {
        let late = reject_late_open_claim(
            connection,
            cleanup_owner,
            terminal_permit,
            late_begin_owners,
            owner,
            &deadline_state,
            "remove late bootstrap writer claim",
        )
        .await;
        return Err(match undelivered_cleanup_owner.shutdown() {
            Ok(()) => late,
            Err(cleanup) => {
                append_operation_cleanup("remove late bootstrap writer claim", late, cleanup)
            }
        });
    }
    drop(terminal_permit);
    drop(connection);
    shutdown_cleanup_owners(late_begin_owners)?;
    cleanup_owner.shutdown().map_err(|error| {
        database(
            "release bootstrap post-COMMIT cleanup owner",
            sqlx::Error::Protocol(error),
        )
    })?;
    Ok(InitializedDatabase {
        recovered_writer,
        undelivered_cleanup_owner,
        open_transaction_admission,
    })
}

async fn claim_application_lock_connection(
    connection: &mut PoolTransactionConnection,
    owner: &str,
    path: &Path,
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
    if previous
        .as_ref()
        .is_some_and(|writer| writer.previous_owner == SNAPSHOT_PROVENANCE_OWNER)
    {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: "standalone snapshots must be consumed with StateStore::restore_backup"
                .to_owned(),
        });
    }
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
    connection: &mut PoolTransactionConnection,
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

async fn validate_migration_history_connection<Connection>(
    connection: &mut Connection,
    require_latest: bool,
) -> Result<i64, StateError>
where
    for<'connection> &'connection mut Connection:
        sqlx::Executor<'connection, Database = sqlx::Sqlite>,
{
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
    connection: &mut PoolTransactionConnection,
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

async fn validate_schema_prefix<Connection>(
    connection: &mut Connection,
    version: i64,
) -> Result<(), StateError>
where
    for<'connection> &'connection mut Connection:
        sqlx::Executor<'connection, Database = sqlx::Sqlite>,
{
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

async fn schema_fingerprint<Connection>(
    connection: &mut Connection,
) -> Result<SchemaFingerprint, StateError>
where
    for<'connection> &'connection mut Connection:
        sqlx::Executor<'connection, Database = sqlx::Sqlite>,
{
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

async fn apply_migrations(
    pool: &SqlitePool,
    path: &Path,
    owner: &str,
    deadline_state: Arc<OpenDeadlineState>,
    transaction_admission: tokio::sync::SemaphorePermit<'static>,
) -> Result<InitializedDatabase, StateError> {
    let mut preliminary = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline_state.work_cutoff),
        pool.acquire(),
    )
    .await
    .map_err(|_| deadline_state.timeout_error())?
    .map_err(|error| database("acquire migration inspection connection", error))?;
    let preliminary_version =
        validate_migration_history_connection(&mut *preliminary, false).await?;
    drop(preliminary);
    for migration in MIGRATIONS {
        if migration.version > preliminary_version && migration.destructive {
            let destination = destructive_backup_path(path, preliminary_version, migration.version);
            ensure_destructive_backup(pool, &destination, preliminary_version).await?;
        }
    }

    let OpenTransactionOwners {
        admission: open_transaction_admission,
        primary_begin,
        late_begin: late_begin_owners,
        undelivered: undelivered_cleanup_owner,
    } = reserve_open_transaction_owners(&deadline_state, transaction_admission).await?;
    #[cfg(test)]
    mark_reserved_owner_path_for_test(path);
    let pooled = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline_state.work_cutoff),
        pool.acquire(),
    )
    .await
    .map_err(|_| deadline_state.timeout_error())?
    .map_err(|error| database("acquire transactional migration connection", error))?;
    let mut connection =
        claw_sqlite_file_control::begin_manual_pool_transaction_with_restore_deadlines_and_owners(
            pooled,
            deadline_state.work_cutoff,
            deadline_state.deadline,
            deadline_state.busy_timeout,
            deadline_state.busy_timeout,
            None,
            primary_begin,
        )
        .await
        .map_err(|error| {
            if error.code() == Some(9) || std::time::Instant::now() >= deadline_state.work_cutoff {
                deadline_state.timeout_error()
            } else {
                file_control_database("begin immediate schema migration", error)
            }
        })?;
    #[cfg(test)]
    wait_at_migration_test_barrier(path, &deadline_state).await;
    let migration_result = async {
        let application_id = sqlx::query_scalar::<_, i64>("PRAGMA application_id")
            .fetch_one(&mut connection)
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

            connection
                .execute_script(migration.sql)
                .await
                .map_err(|error| database("apply schema migration", error))?;
            sqlx::query(
                "INSERT INTO claw_schema_migrations(version, name, checksum, applied_at_ms)
                 VALUES (?, ?, ?, CAST(unixepoch('subsec') * 1000 AS INTEGER))",
            )
            .bind(migration.version)
            .bind(migration.name)
            .bind(migration_checksum(migration.sql))
            .execute(&mut connection)
            .await
            .map_err(|error| database("record schema migration", error))?;
            current_version = migration.version;
        }
        set_sqlite_user_version(&mut connection, current_version).await?;
        validate_operational_schema(&mut connection).await?;
        claim_application_lock_connection(&mut connection, owner, path).await
    }
    .await;
    let recovered_writer = migration_result?;
    #[cfg(test)]
    wait_at_open_precommit_test_barrier(path, &deadline_state).await;
    if let Err(error) = deadline_state.begin_final_commit() {
        let owner_cleanup =
            shutdown_late_claim_cleanup_owners(late_begin_owners, undelivered_cleanup_owner).err();
        let error = match owner_cleanup {
            Some(cleanup) => {
                append_operation_cleanup("rollback cancelled migration", error, cleanup.to_string())
            }
            None => error,
        };
        return match connection.rollback().await {
            Ok(_) => Err(error),
            Err(cleanup) => Err(append_operation_cleanup(
                "rollback cancelled migration",
                error,
                cleanup.to_string(),
            )),
        };
    }
    let commit = connection
        .commit_with_deadline(
            deadline_state.work_cutoff,
            deadline_state.deadline,
            Arc::clone(&deadline_state.cancelled),
            deadline_state.busy_timeout,
            Some(owner.to_owned()),
        )
        .await;
    let commit_eligible = deadline_state.finish_final_commit();
    let (connection, mut cleanup_owner) = match commit {
        Ok(committed) => committed,
        Err(error) => {
            let primary = file_control_database("commit schema migration and writer claim", error);
            return Err(
                match shutdown_late_claim_cleanup_owners(
                    late_begin_owners,
                    undelivered_cleanup_owner,
                ) {
                    Ok(()) => primary,
                    Err(cleanup) => append_operation_cleanup(
                        "commit schema migration and writer claim",
                        primary,
                        cleanup.to_string(),
                    ),
                },
            );
        }
    };
    let terminal_permit = cleanup_owner.take_terminal_permit().map_err(|error| {
        database(
            "reserve late migration cleanup",
            sqlx::Error::Protocol(error),
        )
    })?;
    if !commit_eligible || !deadline_state.permits_sqlite_work() {
        let late = reject_late_open_claim(
            connection,
            cleanup_owner,
            terminal_permit,
            late_begin_owners,
            owner,
            &deadline_state,
            "remove late migration writer claim",
        )
        .await;
        return Err(match undelivered_cleanup_owner.shutdown() {
            Ok(()) => late,
            Err(cleanup) => {
                append_operation_cleanup("remove late migration writer claim", late, cleanup)
            }
        });
    }
    drop(terminal_permit);
    drop(connection);
    shutdown_cleanup_owners(late_begin_owners)?;
    cleanup_owner.shutdown().map_err(|error| {
        database(
            "release migration post-COMMIT cleanup owner",
            sqlx::Error::Protocol(error),
        )
    })?;
    Ok(InitializedDatabase {
        recovered_writer,
        undelivered_cleanup_owner,
        open_transaction_admission,
    })
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
    let hold_after_cancel = OPEN_POSTCOMMIT_HOLD_AFTER_CANCEL
        .lock()
        .expect("open postcommit hold set lock poisoned")
        .contains(path);
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
                    if !hold_after_cancel
                        && deadline_state.cancelled.load(std::sync::atomic::Ordering::Acquire)
                    {
                        break;
                    }
                }
            }
        }
        OPEN_POSTCOMMIT_TEST_BARRIER
            .lock()
            .expect("open postcommit test barrier lock poisoned")
            .remove(path);
        OPEN_POSTCOMMIT_HOLD_AFTER_CANCEL
            .lock()
            .expect("open postcommit hold set lock poisoned")
            .remove(path);
    }
}

#[cfg(test)]
async fn wait_at_open_after_ack_test_barrier(path: &Path, deadline_state: &OpenDeadlineState) {
    let barrier = OPEN_AFTER_ACK_TEST_BARRIER
        .lock()
        .expect("open after-ack barrier lock poisoned")
        .get(path)
        .map(|barrier| (Arc::clone(&barrier.entered), Arc::clone(&barrier.release)));
    if let Some((entered, release)) = barrier {
        entered.notify_one();
        release.notified().await;
        OPEN_AFTER_ACK_TEST_BARRIER
            .lock()
            .expect("open after-ack barrier lock poisoned")
            .remove(path);
        if OPEN_AFTER_ACK_CANCEL_ON_RELEASE
            .lock()
            .expect("open after-ack cancel set lock poisoned")
            .remove(path)
        {
            deadline_state.cancel();
        }
        if OPEN_AFTER_ACK_EXPIRE_ON_RELEASE
            .lock()
            .expect("open after-ack expire set lock poisoned")
            .remove(path)
        {
            deadline_state
                .expired
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(test)]
async fn wait_at_open_cleanup_test_barrier(path: &Path) {
    let barrier = OPEN_CLEANUP_TEST_BARRIER
        .lock()
        .expect("open cleanup test barrier lock poisoned")
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
        OPEN_CLEANUP_TEST_BARRIER
            .lock()
            .expect("open cleanup test barrier lock poisoned")
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

#[cfg(all(test, unix))]
fn wait_at_snapshot_hardening_test_barrier(destination: &Path, temporary: &Path) {
    let barrier = SNAPSHOT_HARDENING_TEST_BARRIER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(destination)
        .cloned();
    if let Some(barrier) = barrier {
        *barrier
            .temporary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(temporary.to_owned());
        barrier.entered.notify_one();
        let mut released = barrier
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*released {
            released = barrier
                .changed
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

#[cfg(test)]
async fn wait_at_restore_read_test_barrier(destination: &Path) {
    let barrier = RESTORE_READ_TEST_BARRIER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        RESTORE_READ_TEST_BARRIER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(destination);
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
    output_guard: SnapshotCleanupGuard,
    reservation: RestoreMaterializationReservation,
) -> Result<
    (
        SnapshotCleanupGuard,
        claw_sqlite_file_control::SnapshotWriteReceipt,
    ),
    StateError,
> {
    materialize_authenticated_snapshot(
        source,
        source_file,
        destination,
        expected_digest,
        deadline_state,
        output_guard,
        reservation,
    )
    .await
}

async fn materialize_authenticated_snapshot(
    source: &Path,
    source_file: &File,
    destination: &Path,
    expected_digest: Option<&[u8]>,
    deadline_state: Option<Arc<OpenDeadlineState>>,
    mut output_guard: SnapshotCleanupGuard,
    reservation: RestoreMaterializationReservation,
) -> Result<
    (
        SnapshotCleanupGuard,
        claw_sqlite_file_control::SnapshotWriteReceipt,
    ),
    StateError,
> {
    let RestoreMaterializationReservation {
        mut cleanup_owners,
        memory: memory_reservation,
        admission: operation_admission,
    } = reservation;
    let expected_digest = expected_digest.ok_or_else(|| StateError::InvalidBackup {
        path: source.to_owned(),
        reason: "authenticated restore bytes require a trusted digest".to_owned(),
    })?;
    let operation_reservation = Arc::new(std::sync::Mutex::new(Some((
        memory_reservation,
        operation_admission,
    ))));
    output_guard.shared_retention = Some(Arc::clone(&operation_reservation));
    ensure_database_artifacts_absent(destination)?;
    let deadline = deadline_state.as_ref().map_or_else(
        || std::time::Instant::now() + MAX_CONFIGURED_TIMEOUT,
        |state| state.work_cutoff,
    );
    if cleanup_owners.len() != 6 {
        return Err(database(
            "validate restore cleanup reservation",
            sqlx::Error::Protocol("restore cleanup owner set is incomplete".to_owned()),
        ));
    }
    let worker_owner = cleanup_owners
        .pop()
        .expect("restore materialization worker owner");
    let finalization_worker_owner = cleanup_owners
        .pop()
        .expect("restore finalization worker owner");
    let source_cleanup_owner = cleanup_owners.pop().expect("restore source cleanup owner");
    let output_creation_owner = cleanup_owners.pop().expect("restore output creation owner");
    let source_read_owner = cleanup_owners.pop().expect("restore source read owner");
    let output_inspection_owner = cleanup_owners
        .pop()
        .expect("restore output inspection owner");
    let source_read_file = source_file
        .try_clone()
        .map_err(|error| file_error("clone restore source handle", source, error))?;
    let source_read_path = source.to_owned();
    let source_read_deadline = deadline_state.clone();
    let (bytes, digest) = run_bounded_filesystem(
        source_read_owner,
        tokio::time::Instant::from_std(deadline),
        "SQLite restore",
        deadline_state
            .as_ref()
            .map_or(u64::MAX, |state| state.timeout_ms),
        move || {
            verify_path_identity(&source_read_path, &source_read_file)?;
            reject_hard_link(&source_read_path, &source_read_file)?;
            let bytes =
                file_bytes_with_deadline(&source_read_file, source_read_deadline.as_deref())?;
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            Ok((bytes, digest))
        },
    )
    .await?;
    if digest.as_slice() != expected_digest {
        return Err(StateError::InvalidBackup {
            path: source.to_owned(),
            reason: "sealed snapshot bytes changed before deserialization".to_owned(),
        });
    }
    let output_destination = destination.to_owned();
    let mut output_guard = Some(output_guard);
    let output_creation_deadline = deadline;
    let output_creation_state = deadline_state.clone();
    let output = run_bounded_filesystem_with_acceptance(
        output_creation_owner,
        tokio::time::Instant::from_std(deadline) + Duration::from_secs(1),
        tokio::time::Instant::from_std(deadline),
        "SQLite restore",
        deadline_state
            .as_ref()
            .map_or(u64::MAX, |state| state.timeout_ms),
        move || {
            #[cfg(test)]
            let injected_expiration =
                take_publication_failpoint(&EXPIRE_OUTPUT_CREATION_DEADLINE, &output_destination);
            #[cfg(not(test))]
            let injected_expiration = false;
            if injected_expiration
                || std::time::Instant::now() >= output_creation_deadline
                || output_creation_state
                    .as_ref()
                    .is_some_and(|state| !state.permits_sqlite_work())
            {
                let error = output_creation_state.as_ref().map_or(
                    StateError::OperationTimedOut {
                        operation: "SQLite restore",
                        timeout_ms: u64::MAX,
                    },
                    |state| state.timeout_error(),
                );
                return Ok(Err((
                    error,
                    output_guard
                        .take()
                        .expect("expired restore output guard is delivered once"),
                )));
            }
            let result = create_bound_snapshot_output(
                &output_destination,
                Some(
                    output_guard
                        .as_mut()
                        .expect("restore output guard remains owned"),
                ),
                output_creation_deadline,
                output_creation_state.as_deref(),
                "SQLite restore",
                output_creation_state
                    .as_ref()
                    .map_or(u64::MAX, |state| state.timeout_ms),
            );
            Ok(match result {
                Ok(output) => Ok((
                    output,
                    output_guard
                        .take()
                        .expect("restore output guard is delivered once"),
                )),
                Err(error) => Err((
                    error,
                    output_guard
                        .take()
                        .expect("failed restore output guard is delivered once"),
                )),
            })
        },
    )
    .await;
    let (output, mut output_guard) = match output {
        Ok(Ok(output)) => output,
        Ok(Err((error, mut guard))) => {
            return Err(cleanup_snapshot_guard_or_error(&mut guard, error).await);
        }
        Err(error) => return Err(error),
    };
    let source_connection =
        SqliteConnection::connect_with(&SqliteConnectOptions::new().in_memory(true)).await;
    let source_connection = match source_connection {
        Ok(connection) => connection,
        Err(error) => {
            drop(output);
            return Err(cleanup_snapshot_guard_or_error(
                &mut output_guard,
                invalid_backup(source, "open readonly restore image", error),
            )
            .await);
        }
    };
    let mut source_connection = OwnedSqliteConnectionGuard::new_cancellable_with_owner(
        source_connection,
        deadline_state.clone(),
        source_cleanup_owner,
    );
    source_connection.attach_shared_terminal_retention(Arc::clone(&operation_reservation));
    if let Err(error) =
        claw_sqlite_file_control::deserialize_readonly(&mut source_connection, &bytes).await
    {
        drop(output);
        let error = close_owned_connection_or_error(
            "SQLite restore",
            source_connection,
            file_control_with_deadline(
                "deserialize authenticated restore bytes",
                error,
                deadline_state.as_deref(),
            ),
        )
        .await;
        return Err(cleanup_snapshot_guard_or_error(&mut output_guard, error).await);
    }
    drop(bytes);
    if let Err(error) =
        install_open_deadline_handler(&mut source_connection, deadline_state.clone()).await
    {
        drop(output);
        let error =
            close_owned_connection_or_error("SQLite restore", source_connection, error).await;
        return Err(cleanup_snapshot_guard_or_error(&mut output_guard, error).await);
    }
    if let Err(error) = sqlx::query("BEGIN").execute(&mut *source_connection).await {
        drop(output);
        let error = close_owned_connection_or_error(
            "SQLite restore",
            source_connection,
            invalid_backup(source, "begin restore validation snapshot", error),
        )
        .await;
        return Err(cleanup_snapshot_guard_or_error(&mut output_guard, error).await);
    }
    let validation = async {
        let provenance = sqlx::query_scalar::<_, String>(
            "SELECT owner FROM claw_writer_lock
             WHERE singleton = 1 AND acquired_at_ms = 0",
        )
        .fetch_optional(&mut *source_connection)
        .await
        .map_err(|error| invalid_backup(source, "read standalone snapshot provenance", error))?;
        if provenance.as_deref() != Some(SNAPSHOT_PROVENANCE_OWNER) {
            return Err(StateError::InvalidBackup {
                path: source.to_owned(),
                reason: "restore source is not a verified standalone snapshot".to_owned(),
            });
        }
        validate_backup_connection(
            source,
            &mut source_connection,
            BackupValidationMode::SupportedRestorePrefix,
        )
        .await
    }
    .await;
    let rollback = sqlx::query("ROLLBACK")
        .execute(&mut *source_connection)
        .await
        .map(|_| ())
        .map_err(|error| invalid_backup(source, "finish restore validation snapshot", error));
    match (validation, rollback) {
        (Err(error), _) | (Ok(_), Err(error)) => {
            drop(output);
            let error =
                close_owned_connection_or_error("SQLite restore", source_connection, error).await;
            return Err(cleanup_snapshot_guard_or_error(&mut output_guard, error).await);
        }
        (Ok(_), Ok(())) => {}
    }
    let destination_connection = SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .in_memory(true)
            .journal_mode(SqliteJournalMode::Off),
    )
    .await;
    let destination_connection = match destination_connection {
        Ok(connection) => connection,
        Err(error) => {
            drop(output);
            let error = close_owned_connection_or_error(
                "SQLite restore",
                source_connection,
                invalid_backup(source, "open writable restore image", error),
            )
            .await;
            return Err(cleanup_snapshot_guard_or_error(&mut output_guard, error).await);
        }
    };
    let max_pages = match bounded_backup_max_pages(&mut source_connection).await {
        Ok(max_pages) => max_pages,
        Err(error) => {
            drop(output);
            let error =
                close_owned_connection_or_error("SQLite restore", source_connection, error).await;
            return Err(cleanup_snapshot_guard_or_error(&mut output_guard, error).await);
        }
    };
    let cancelled = deadline_state.as_ref().map_or_else(
        || Arc::new(std::sync::atomic::AtomicBool::new(false)),
        |state| Arc::clone(&state.cancelled),
    );
    let (source_connection, source_cleanup_owner) = source_connection.release_connection();
    let copied = claw_sqlite_file_control::backup_owned_main_database_with_cleanup_deadline(
        worker_owner,
        source_connection,
        destination_connection,
        Arc::clone(&operation_reservation),
        claw_sqlite_file_control::BackupExecutionContext {
            deadline,
            cancelled: Arc::clone(&cancelled),
            max_pages,
            source_busy_timeout: Duration::ZERO,
            destination_busy_timeout: Duration::ZERO,
        },
        deadline_state
            .as_ref()
            .map_or(deadline, |state| state.deadline),
    )
    .await;
    let (source_connection, destination_connection, operation_reservation) = match copied {
        Ok(copied) => copied,
        Err(error) => {
            drop(output);
            return Err(cleanup_snapshot_guard_or_error(
                &mut output_guard,
                file_control_with_deadline(
                    "copy authenticated restore image",
                    error,
                    deadline_state.as_deref(),
                ),
            )
            .await);
        }
    };
    output_guard.shared_retention = Some(Arc::clone(&operation_reservation));
    let mut source_connection = OwnedSqliteConnectionGuard::new_cancellable_with_owner(
        source_connection,
        deadline_state.clone(),
        source_cleanup_owner,
    );
    source_connection.attach_shared_terminal_retention(Arc::clone(&operation_reservation));
    if let Err(error) = source_connection.close().await {
        drop(output);
        return Err(cleanup_snapshot_guard_or_error(
            &mut output_guard,
            invalid_backup(source, "close readonly restore image", error),
        )
        .await);
    }
    let mut destination_connection = destination_connection;
    if let Err(error) = sqlx::query("DELETE FROM claw_writer_lock")
        .execute(&mut destination_connection)
        .await
    {
        let primary = invalid_backup(source, "clear restored writer ownership", error);
        let (close_tx, close_rx) = tokio::sync::oneshot::channel();
        let close_retention = Arc::clone(&operation_reservation);
        handoff_state_payload(
            finalization_worker_owner,
            std::sync::Mutex::new((
                Some(destination_connection),
                Some(close_retention),
                Some(close_tx),
            )),
            |_, terminal_closes, payload| {
                let mut payload = payload
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let permit = terminal_closes
                    .take_permit()
                    .expect("restore destination close capacity was pre-reserved");
                let destination_connection = payload
                    .0
                    .take()
                    .expect("restore destination connection remains owned");
                let close_retention = payload
                    .1
                    .take()
                    .expect("restore close retention remains owned");
                let close_tx = payload
                    .2
                    .take()
                    .expect("restore close result remains owned");
                let _ = close_tx.send(
                    permit.close_with_shared_retention(destination_connection, close_retention),
                );
            },
        )
        .map_err(|handoff| {
            append_operation_cleanup(
                "SQLite restore",
                primary.clone(),
                format!("destination terminal close handoff: {handoff}"),
            )
        })?;
        let close = tokio::time::timeout(std::time::Duration::from_secs(1), close_rx)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(claw_sqlite_file_control::TerminalCloseOutcome::Quarantined);
        drop(output);
        let primary = if close == claw_sqlite_file_control::TerminalCloseOutcome::Closed {
            primary
        } else {
            append_operation_cleanup(
                "SQLite restore",
                primary,
                format!("destination terminal close: {close:?}"),
            )
        };
        return Err(cleanup_snapshot_guard_or_error(&mut output_guard, primary).await);
    }
    let (receipt, output_guard) = claw_sqlite_file_control::finalize_owned_snapshot(
        finalization_worker_owner,
        destination_connection,
        output,
        output_guard,
        claw_sqlite_file_control::SnapshotFinalizeContext {
            output_path: destination.to_string_lossy().into_owned(),
            deadline,
            cancelled,
            maximum_bytes: usize::try_from(MAX_AUTHENTICATED_SNAPSHOT_BYTES)
                .expect("snapshot cap fits usize"),
        },
    )
    .await
    .map_err(|error| {
        file_control_with_deadline(
            "finalize held restored snapshot",
            error,
            deadline_state.as_deref(),
        )
    })?;
    let inspection_destination = destination.to_owned();
    let inspection_deadline = deadline_state.clone();
    let inspection_receipt = receipt.clone();
    let mut output_guard = Some(output_guard);
    let inspected = run_bounded_filesystem(
        output_inspection_owner,
        tokio::time::Instant::from_std(deadline),
        "SQLite restore",
        deadline_state
            .as_ref()
            .map_or(u64::MAX, |state| state.timeout_ms),
        move || {
            let result = (|| {
                let expected_file = output_guard
                    .as_ref()
                    .expect("snapshot inspection guard remains owned")
                    .expected_file
                    .as_ref()
                    .expect("restore output identity was bound before finalization");
                verify_path_identity(&inspection_destination, expected_file)?;
                if expected_file
                    .metadata()
                    .map_err(|error| {
                        file_error(
                            "inspect restored snapshot size",
                            &inspection_destination,
                            error,
                        )
                    })?
                    .len()
                    != inspection_receipt.byte_count
                    || file_digest_with_deadline(expected_file, inspection_deadline.as_deref())?
                        != inspection_receipt.digest
                {
                    return Err(StateError::InvalidBackup {
                        path: inspection_destination.clone(),
                        reason: "restored snapshot failed final held size/digest verification"
                            .to_owned(),
                    });
                }
                secure_private_snapshot_file(&inspection_destination, expected_file)
            })();
            Ok(match result {
                Ok(()) => Ok(output_guard
                    .take()
                    .expect("snapshot inspection guard is delivered once")),
                Err(error) => Err((
                    error,
                    output_guard
                        .take()
                        .expect("failed snapshot inspection guard is delivered once"),
                )),
            })
        },
    )
    .await?;
    match inspected {
        Ok(output_guard) => Ok((output_guard, receipt)),
        Err((error, mut output_guard)) => {
            Err(cleanup_snapshot_guard_or_error(&mut output_guard, error).await)
        }
    }
}

async fn bounded_backup_max_pages(
    connection: &mut SqliteConnection,
) -> Result<std::ffi::c_int, StateError> {
    let page_size = sqlx::query_scalar::<_, i64>("PRAGMA page_size")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| database("read SQLite backup page size", error))?;
    let page_size = u64::try_from(page_size).map_err(|_| StateError::InvalidBackup {
        path: PathBuf::from("<SQLite connection>"),
        reason: "SQLite page size is invalid".to_owned(),
    })?;
    let pages = MAX_AUTHENTICATED_SNAPSHOT_BYTES
        .checked_div(page_size)
        .ok_or_else(|| StateError::InvalidBackup {
            path: PathBuf::from("<SQLite connection>"),
            reason: "SQLite page size must be positive".to_owned(),
        })?;
    Ok(std::ffi::c_int::try_from(pages).unwrap_or(std::ffi::c_int::MAX))
}

#[cfg(unix)]
fn mark_snapshot_staging(path: &Path, file: &File) -> Result<(), StateError> {
    rustix::fs::fsetxattr(
        file,
        UNIX_SNAPSHOT_STAGING_XATTR,
        SNAPSHOT_STAGING_MARKER,
        rustix::fs::XattrFlags::CREATE,
    )
    .map_err(|error| file_error("mark held snapshot as staging-bound", path, error.into()))?;
    file.sync_all()
        .map_err(|error| file_error("sync held snapshot staging marker", path, error))
}

#[cfg(unix)]
fn clear_snapshot_staging(path: &Path, file: &File) -> Result<(), StateError> {
    use xattr::FileExt as _;

    file.remove_xattr(UNIX_SNAPSHOT_STAGING_XATTR)
        .map_err(|error| file_error("clear held snapshot staging marker", path, error))?;
    file.sync_all()
        .map_err(|error| file_error("sync cleared snapshot staging marker", path, error))
}

#[cfg(unix)]
fn snapshot_is_staging(path: &Path, file: &File) -> Result<bool, StateError> {
    use xattr::FileExt as _;

    match file
        .get_xattr(UNIX_SNAPSHOT_STAGING_XATTR)
        .map_err(|error| file_error("read held snapshot staging marker", path, error))?
    {
        None => Ok(false),
        Some(marker) if marker == SNAPSHOT_STAGING_MARKER => Ok(true),
        Some(_) => Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "snapshot staging marker is malformed",
        }),
    }
}

#[cfg(windows)]
fn windows_snapshot_staging_path(path: &Path) -> PathBuf {
    let mut marker = path.as_os_str().to_owned();
    marker.push(":gta-claw-snapshot-staging");
    PathBuf::from(marker)
}

#[cfg(windows)]
fn mark_snapshot_staging(path: &Path, _file: &File) -> Result<(), StateError> {
    use std::io::Write as _;

    let marker_path = windows_snapshot_staging_path(path);
    let mut marker = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&marker_path)
        .map_err(|error| file_error("create held snapshot staging stream", &marker_path, error))?;
    marker
        .write_all(SNAPSHOT_STAGING_MARKER)
        .and_then(|()| marker.sync_all())
        .map_err(|error| file_error("write held snapshot staging stream", &marker_path, error))
}

#[cfg(windows)]
fn clear_snapshot_staging(path: &Path, file: &File) -> Result<(), StateError> {
    let marker_path = windows_snapshot_staging_path(path);
    let writable = open_windows_file_no_follow(path, false, true)?;
    if !files_share_identity_from_handles_portable(file, &writable)? {
        return Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "writable publication handle does not match the staging object",
        });
    }
    std::fs::remove_file(&marker_path)
        .map_err(|error| file_error("remove held snapshot staging stream", &marker_path, error))?;
    writable
        .sync_all()
        .map_err(|error| file_error("flush published Windows snapshot", path, error))?;
    if snapshot_is_staging(path, file)? {
        return Err(StateError::PublicationUncertain {
            path: path.to_owned(),
            reason: "Windows staging marker remained after flushed removal".to_owned(),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn snapshot_is_staging(path: &Path, _file: &File) -> Result<bool, StateError> {
    use std::io::Read as _;

    let marker_path = windows_snapshot_staging_path(path);
    let marker = match File::open(&marker_path) {
        Ok(marker) => marker,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(file_error(
                "open held snapshot staging stream",
                &marker_path,
                error,
            ));
        }
    };
    let mut contents = Vec::new();
    contents
        .try_reserve_exact(SNAPSHOT_STAGING_MARKER.len())
        .map_err(|_| StateError::InvalidPath {
            path: marker_path.clone(),
            reason: "snapshot staging marker allocation failed",
        })?;
    marker
        .take(u64::try_from(SNAPSHOT_STAGING_MARKER.len() + 1).expect("marker length fits u64"))
        .read_to_end(&mut contents)
        .map_err(|error| file_error("read held snapshot staging stream", &marker_path, error))?;
    if contents == SNAPSHOT_STAGING_MARKER {
        Ok(true)
    } else {
        Err(StateError::InvalidPath {
            path: marker_path,
            reason: "snapshot staging marker is malformed",
        })
    }
}

#[cfg(all(not(unix), not(windows)))]
fn mark_snapshot_staging(path: &Path, _file: &File) -> Result<(), StateError> {
    Err(StateError::InvalidPath {
        path: path.to_owned(),
        reason: "snapshot staging markers are unsupported",
    })
}

#[cfg(all(not(unix), not(windows)))]
fn clear_snapshot_staging(path: &Path, _file: &File) -> Result<(), StateError> {
    Err(StateError::InvalidPath {
        path: path.to_owned(),
        reason: "snapshot staging markers are unsupported",
    })
}

#[cfg(all(not(unix), not(windows)))]
fn snapshot_is_staging(path: &Path, _file: &File) -> Result<bool, StateError> {
    Err(StateError::InvalidPath {
        path: path.to_owned(),
        reason: "snapshot staging markers are unsupported",
    })
}

fn reject_snapshot_staging_marker(path: &Path, file: &File) -> Result<(), StateError> {
    if snapshot_is_staging(path, file)? {
        Err(StateError::InvalidPath {
            path: path.to_owned(),
            reason: "snapshot publication is still staging-bound",
        })
    } else {
        Ok(())
    }
}

fn create_bound_snapshot_output(
    destination: &Path,
    output_guard: Option<&mut SnapshotCleanupGuard>,
    deadline: std::time::Instant,
    deadline_state: Option<&OpenDeadlineState>,
    operation: &'static str,
    timeout_ms: u64,
) -> Result<File, StateError> {
    let ensure_creation_allowed = || {
        if std::time::Instant::now() >= deadline
            || deadline_state.is_some_and(|state| !state.permits_sqlite_work())
        {
            Err(StateError::OperationTimedOut {
                operation,
                timeout_ms,
            })
        } else {
            Ok(())
        }
    };
    ensure_creation_allowed()?;
    let creation_lock = acquire_creation_lock(destination)?;
    ensure_creation_allowed()?;
    let file = create_private_snapshot_file(destination)?;
    if let Some(guard) = output_guard {
        guard.bind_file(&file)?;
    }
    ensure_creation_allowed()?;
    secure_private_snapshot_file(destination, &file)?;
    ensure_creation_allowed()?;
    mark_snapshot_staging(destination, &file)?;
    ensure_creation_allowed()?;
    drop(creation_lock);
    Ok(file)
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

fn file_bytes_with_deadline(
    file: &File,
    deadline_state: Option<&OpenDeadlineState>,
) -> Result<Vec<u8>, StateError> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let path = Path::new("<open database handle>");
    let length = file
        .metadata()
        .map_err(|error| file_error("inspect authenticated database handle", path, error))?
        .len();
    if length > MAX_AUTHENTICATED_SNAPSHOT_BYTES {
        return Err(StateError::InvalidBackup {
            path: path.to_owned(),
            reason: format!(
                "authenticated snapshot exceeds {} bytes",
                MAX_AUTHENTICATED_SNAPSHOT_BYTES
            ),
        });
    }
    let mut file = file
        .try_clone()
        .map_err(|error| file_error("clone database handle for authenticated read", path, error))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| file_error("seek authenticated database handle", path, error))?;
    let capacity = usize::try_from(length).map_err(|_| StateError::InvalidBackup {
        path: path.to_owned(),
        reason: "authenticated snapshot size does not fit memory".to_owned(),
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|error| StateError::InvalidBackup {
            path: path.to_owned(),
            reason: format!("authenticated snapshot allocation failed: {error}"),
        })?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if let Some(deadline_state) = deadline_state
            && !deadline_state.permits_sqlite_work()
        {
            return Err(deadline_state.timeout_error());
        }
        let read = file
            .read(&mut buffer)
            .map_err(|error| file_error("read authenticated database handle", path, error))?;
        if read == 0 {
            break;
        }
        let next_length =
            bytes
                .len()
                .checked_add(read)
                .ok_or_else(|| StateError::InvalidBackup {
                    path: path.to_owned(),
                    reason: "authenticated snapshot size overflowed memory".to_owned(),
                })?;
        if u64::try_from(next_length).unwrap_or(u64::MAX) > MAX_AUTHENTICATED_SNAPSHOT_BYTES {
            return Err(StateError::InvalidBackup {
                path: path.to_owned(),
                reason: format!(
                    "authenticated snapshot grew beyond {} bytes",
                    MAX_AUTHENTICATED_SNAPSHOT_BYTES
                ),
            });
        }
        bytes
            .try_reserve(read)
            .map_err(|error| StateError::InvalidBackup {
                path: path.to_owned(),
                reason: format!("authenticated snapshot allocation failed: {error}"),
            })?;
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes)
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
    #[cfg(any(unix, windows))]
    path: PathBuf,
    #[cfg(unix)]
    file: Option<File>,
    #[cfg(unix)]
    deleted: bool,
    armed: bool,
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
    fn cleanup(&mut self) -> Result<(), StateError> {
        #[cfg(unix)]
        {
            let Some(file) = self.file.as_ref() else {
                self.armed = false;
                return Ok(());
            };
            if !self.deleted {
                verify_path_identity(&self.path, file)?;
                std::fs::remove_file(&self.path).map_err(|error| {
                    file_error("remove unused trusted backup seal", &self.path, error)
                })?;
                self.deleted = true;
            }
            #[cfg(test)]
            if take_counted_failure(&FAIL_TRUSTED_SEAL_AFTER_UNLINK, &self.path) {
                return Err(StateError::InvalidPath {
                    path: self.path.clone(),
                    reason: "injected failure after trusted backup seal unlink",
                });
            }
            sync_parent_directory(&self.path)?;
            self.file.take();
        }
        #[cfg(windows)]
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(file_error(
                    "remove unused Windows backup seal",
                    &self.path,
                    error,
                ));
            }
        }
        self.armed = false;
        Ok(())
    }

    fn disarm(&mut self) {
        self.armed = false;
        #[cfg(unix)]
        self.file.take();
    }
}

impl Drop for TrustedBackupSeal {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cleanup();
        }
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
        file: Some(record),
        deleted: false,
        armed: true,
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
    Ok(TrustedBackupSeal {
        path: seal_path,
        armed: true,
    })
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
    let source_busy_timeout =
        operational_identity.map_or(MAX_CONFIGURED_TIMEOUT, |identity| identity.busy_timeout);
    let snapshot_memory = reserve_snapshot_memory(deadline, "SQLite backup", timeout_ms).await?;
    let deadline_state = Arc::new(OpenDeadlineState {
        work_cutoff: deadline.into_std(),
        deadline: deadline.into_std(),
        timeout_ms,
        operation: "SQLite backup",
        busy_timeout: MAX_CONFIGURED_TIMEOUT,
        expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        finished: std::sync::atomic::AtomicBool::new(false),
        final_commit_state: std::sync::atomic::AtomicU8::new(0),
        open_cleanup_state: std::sync::atomic::AtomicU8::new(0),
    });
    let backup_cleanup_permit =
        tokio::time::timeout_at(deadline, BACKUP_CLEANUP_ADMISSION.acquire())
            .await
            .map_err(|_| timed_out())?
            .map_err(|_| {
                database(
                    "acquire backup cleanup admission",
                    sqlx::Error::Protocol("backup cleanup admission closed".to_owned()),
                )
            })?;
    let mut cleanup_owners = claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
        "claw-state-backup-owner-set",
        11,
        deadline.into_std(),
    )
    .await
    .map_err(|error| {
        if tokio::time::Instant::now() >= deadline {
            timed_out()
        } else {
            database(
                "reserve logical backup worker and cleanup owners",
                sqlx::Error::Protocol(error),
            )
        }
    })?;
    let final_handoff_owner = cleanup_owners
        .pop()
        .expect("logical backup final handoff owner");
    let inspection_owner = cleanup_owners
        .pop()
        .expect("logical backup held inspection owner");
    let output_creation_owner = cleanup_owners
        .pop()
        .expect("logical backup output creation owner");
    let publication_owner = cleanup_owners
        .pop()
        .expect("logical backup publication owner");
    let durability_owner = cleanup_owners
        .pop()
        .expect("logical backup durability owner");
    let destination_preflight_owner = cleanup_owners
        .pop()
        .expect("logical backup destination preflight owner");
    let snapshot_cleanup_owner = cleanup_owners
        .pop()
        .expect("logical backup snapshot cleanup owner");
    let backup_worker_owner = cleanup_owners.pop().expect("logical backup worker owner");
    let finalization_worker_owner = cleanup_owners
        .pop()
        .expect("logical backup finalization worker owner");
    let validation_cleanup_owner = cleanup_owners
        .pop()
        .expect("logical backup validation cleanup owner");
    let source_cleanup_owner = cleanup_owners
        .pop()
        .expect("logical backup source cleanup owner");
    let preflight_destination = destination.to_owned();
    let mut snapshot_cleanup_owner = Some(snapshot_cleanup_owner);
    let preflight_deadline_state = Arc::clone(&deadline_state);
    let (destination_directory, temporary, snapshot_guard) = run_bounded_filesystem(
        destination_preflight_owner,
        deadline,
        "SQLite backup",
        timeout_ms,
        move || {
            ensure_database_artifacts_absent(&preflight_destination)?;
            let destination_directory = pin_private_directory(&preflight_destination)?;
            #[cfg(test)]
            if take_publication_failpoint(
                &CREATE_DESTINATION_BEFORE_PUBLICATION,
                &preflight_destination,
            ) {
                std::fs::write(&preflight_destination, b"other publisher").map_err(|error| {
                    file_error(
                        "inject competing publication",
                        &preflight_destination,
                        error,
                    )
                })?;
            }
            ensure_database_artifacts_absent(&preflight_destination)?;
            let guard = SnapshotCleanupGuard::new_pinned(
                &preflight_destination,
                &destination_directory,
                snapshot_cleanup_owner
                    .take()
                    .expect("backup snapshot cleanup owner is consumed once"),
                Some(&preflight_deadline_state),
            )?;
            Ok((destination_directory, preflight_destination.clone(), guard))
        },
    )
    .await?;
    let mut temporary_guard = BackupStagingLease {
        snapshot: snapshot_guard,
        admission_permit: Some(backup_cleanup_permit),
        memory_reservation: None,
    };
    let mut connection = match tokio::time::timeout_at(deadline, pool.acquire()).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            let primary = database("acquire bounded backup connection", error);
            return Err(cleanup_backup_staging_or_error(&mut temporary_guard, primary).await);
        }
        Err(_) => {
            return Err(cleanup_backup_staging_or_error(&mut temporary_guard, timed_out()).await);
        }
    };
    let mut cancellation_guard = OperationCancellationGuard::new(Arc::clone(&deadline_state));
    let output_temporary = temporary.clone();
    let mut temporary_guard = Some(temporary_guard);
    let output_creation_state = Arc::clone(&deadline_state);
    let output = run_bounded_filesystem(
        output_creation_owner,
        deadline + Duration::from_secs(1),
        "SQLite backup",
        timeout_ms,
        move || {
            #[cfg(test)]
            let injected_expiration =
                take_publication_failpoint(&EXPIRE_OUTPUT_CREATION_DEADLINE, &output_temporary);
            #[cfg(not(test))]
            let injected_expiration = false;
            if injected_expiration || !output_creation_state.permits_sqlite_work() {
                return Ok(Err((
                    output_creation_state.timeout_error(),
                    temporary_guard
                        .take()
                        .expect("expired backup staging guard is delivered once"),
                )));
            }
            let result = create_bound_snapshot_output(
                &output_temporary,
                Some(
                    &mut temporary_guard
                        .as_mut()
                        .expect("backup staging guard remains owned")
                        .snapshot,
                ),
                output_creation_state.work_cutoff,
                Some(&output_creation_state),
                "SQLite backup",
                timeout_ms,
            );
            Ok(match result {
                Ok(output) => Ok((
                    output,
                    temporary_guard
                        .take()
                        .expect("backup staging guard is delivered once"),
                )),
                Err(error) => Err((
                    error,
                    temporary_guard
                        .take()
                        .expect("failed backup staging guard is delivered once"),
                )),
            })
        },
    )
    .await?;
    let (backup_output, mut temporary_guard) = match output {
        Ok(output) => output,
        Err((error, mut guard)) => {
            return Err(cleanup_backup_staging_or_error(&mut guard, error).await);
        }
    };
    let destination_connection = SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .in_memory(true)
            .journal_mode(SqliteJournalMode::Off),
    )
    .await;
    let destination_connection = match destination_connection {
        Ok(connection) => connection,
        Err(error) => {
            drop(backup_output);
            return Err(cleanup_backup_staging_or_error(
                &mut temporary_guard,
                database("open prebound backup output", error),
            )
            .await);
        }
    };
    #[cfg(test)]
    let execution_gate = {
        BACKUP_CAPTURE_TEST_BARRIER
            .lock()
            .expect("backup capture test barrier lock poisoned")
            .remove(destination)
    };
    #[cfg(test)]
    if let Some(gate) = execution_gate {
        gate.wait(&deadline_state).await;
    }
    let max_pages = match bounded_backup_max_pages(&mut connection).await {
        Ok(max_pages) => max_pages,
        Err(error) => {
            let owner = validation_cleanup_owner;
            let (close_tx, close_rx) = tokio::sync::oneshot::channel();
            if let Err(handoff) = handoff_state_payload(
                owner,
                std::sync::Mutex::new((Some(destination_connection), Some(close_tx))),
                |_, terminal_closes, payload| {
                    let mut payload = payload
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let permit = terminal_closes
                        .take_permit()
                        .expect("backup destination close capacity was pre-reserved");
                    let connection = payload
                        .0
                        .take()
                        .expect("backup destination connection remains owned");
                    let close_tx = payload.1.take().expect("backup close result remains owned");
                    let _ = close_tx.send(permit.close(connection));
                },
            ) {
                drop(backup_output);
                return Err(append_operation_cleanup(
                    "SQLite backup",
                    error,
                    format!("destination terminal close handoff: {handoff}"),
                ));
            }
            let close = tokio::time::timeout(std::time::Duration::from_secs(1), close_rx)
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(claw_sqlite_file_control::TerminalCloseOutcome::Quarantined);
            drop(backup_output);
            let error = if close == claw_sqlite_file_control::TerminalCloseOutcome::Closed {
                error
            } else {
                append_operation_cleanup(
                    "SQLite backup",
                    error,
                    format!("destination terminal close: {close:?}"),
                )
            };
            return Err(cleanup_backup_staging_or_error(&mut temporary_guard, error).await);
        }
    };
    let operation_reservation = (
        snapshot_memory,
        temporary_guard
            .admission_permit
            .take()
            .expect("backup admission permit remains reserved"),
    );
    let backup_connections =
        claw_sqlite_file_control::backup_owned_main_database_with_cleanup_deadline(
            backup_worker_owner,
            connection,
            destination_connection,
            operation_reservation,
            claw_sqlite_file_control::BackupExecutionContext {
                deadline: deadline.into_std(),
                cancelled: Arc::clone(&deadline_state.cancelled),
                max_pages,
                source_busy_timeout,
                destination_busy_timeout: Duration::ZERO,
            },
            deadline_state.deadline,
        )
        .await
        .map_err(|error| {
            if error.code() == Some(9)
                && (tokio::time::Instant::now() >= deadline
                    || deadline_state
                        .cancelled
                        .load(std::sync::atomic::Ordering::Acquire))
            {
                timed_out()
            } else {
                file_control_database("create consistent SQLite backup", error)
            }
        });
    let (connection, destination_connection, operation_reservation) = match backup_connections {
        Ok(connections) => connections,
        Err(primary) => {
            drop(backup_output);
            return Err(cleanup_backup_staging_or_error(&mut temporary_guard, primary).await);
        }
    };
    temporary_guard.memory_reservation = Some(operation_reservation.0);
    temporary_guard.admission_permit = Some(operation_reservation.1);
    let mut connection = BackupConnectionGuard::new_cancellable(
        connection,
        Arc::clone(&deadline_state),
        source_cleanup_owner,
    );
    let mut destination_connection = OwnedSqliteConnectionGuard::new_cancellable_with_owner(
        destination_connection,
        Some(Arc::clone(&deadline_state)),
        validation_cleanup_owner,
    );
    destination_connection.attach_backup_resources(temporary_guard, backup_output);
    if let Err(error) = install_open_deadline_handler(
        &mut destination_connection,
        Some(Arc::clone(&deadline_state)),
    )
    .await
    {
        return Err(
            discard_backup_connections_or_error(connection, destination_connection, error).await,
        );
    }
    let preparation = async {
        mark_backup_provenance_connection(&temporary, &mut destination_connection).await?;
        validate_backup_connection(&temporary, &mut destination_connection, validation_mode)
            .await?;
        Ok::<(), StateError>(())
    }
    .await;
    if let Err(primary) = preparation {
        return Err(discard_backup_connections_or_error(
            connection,
            destination_connection,
            primary,
        )
        .await);
    }
    let (destination_connection, backup_output, temporary_guard) =
        destination_connection.release_to_worker()?;
    let finalized = claw_sqlite_file_control::finalize_owned_snapshot(
        finalization_worker_owner,
        destination_connection,
        backup_output,
        temporary_guard,
        claw_sqlite_file_control::SnapshotFinalizeContext {
            output_path: temporary.to_string_lossy().into_owned(),
            deadline: deadline.into_std(),
            cancelled: Arc::clone(&deadline_state.cancelled),
            maximum_bytes: usize::try_from(MAX_AUTHENTICATED_SNAPSHOT_BYTES)
                .expect("snapshot cap fits usize"),
        },
    )
    .await
    .map_err(|error| {
        if error.code() == Some(9)
            && (tokio::time::Instant::now() >= deadline
                || deadline_state
                    .cancelled
                    .load(std::sync::atomic::Ordering::Acquire))
        {
            timed_out()
        } else {
            file_control_database("finalize held SQLite backup", error)
        }
    });
    let (write_receipt, mut temporary_guard) = match finalized {
        Ok(finalized) => finalized,
        Err(primary) => {
            let close = connection.discard().await;
            return Err(
                if close == claw_sqlite_file_control::TerminalCloseOutcome::Closed {
                    primary
                } else {
                    append_operation_cleanup(
                        "SQLite backup",
                        primary,
                        format!("source terminal close: {close:?}"),
                    )
                },
            );
        }
    };
    let sqlite_identity = match operational_identity {
        Some(identity) => identity.profile.verify_connection(&mut connection).await,
        None => verify_sqlite_connection_identity(&mut connection).await,
    }
    .map_err(|error| database("reverify backup source SQLite identity", error));
    let source_identity = sqlite_identity.and_then(|()| {
        operational_identity
            .map(OperationalIdentity::verify)
            .unwrap_or(Ok(()))
    });
    if let Err(error) = source_identity {
        let close = connection.discard().await;
        let error = if close == claw_sqlite_file_control::TerminalCloseOutcome::Closed {
            error
        } else {
            append_operation_cleanup(
                "SQLite backup",
                error,
                format!("source terminal close: {close:?}"),
            )
        };
        return Err(cleanup_backup_staging_or_error(&mut temporary_guard, error).await);
    }
    connection.release_reusable()?;
    let inspection_temporary = temporary.clone();
    let inspection_destination = destination.to_owned();
    let inspection_deadline_state = Arc::clone(&deadline_state);
    let inspection_receipt = write_receipt.clone();
    let mut temporary_guard = Some(temporary_guard);
    let inspection = run_bounded_filesystem(
        inspection_owner,
        deadline,
        "SQLite backup",
        timeout_ms,
        move || {
            let expected_file = temporary_guard
                .as_ref()
                .expect("backup inspection guard remains owned")
                .snapshot
                .expected_file
                .as_ref()
                .expect("backup output identity was bound before inspection");
            #[cfg(all(test, unix))]
            wait_at_snapshot_hardening_test_barrier(&inspection_destination, &inspection_temporary);
            if let Err(error) = secure_private_snapshot_file(&inspection_temporary, expected_file) {
                return Ok(Err((
                    error,
                    None,
                    temporary_guard
                        .take()
                        .expect("failed backup inspection guard is delivered once"),
                )));
            }
            let pinned = match PinnedSnapshot::open_cleanup(&inspection_temporary) {
                Ok(pinned) => pinned,
                Err(error) => {
                    return Ok(Err((
                        error,
                        None,
                        temporary_guard
                            .take()
                            .expect("failed backup inspection guard is delivered once"),
                    )));
                }
            };
            if let Err(error) = temporary_guard
                .as_mut()
                .expect("backup inspection guard remains owned")
                .bind_file(&pinned.file)
            {
                return Ok(Err((
                    error,
                    Some(pinned),
                    temporary_guard
                        .take()
                        .expect("failed backup inspection guard is delivered once"),
                )));
            }
            let snapshot_length = match pinned.file.metadata() {
                Ok(metadata) => metadata.len(),
                Err(error) => {
                    return Ok(Err((
                        file_error(
                            "inspect completed backup size",
                            &inspection_temporary,
                            error,
                        ),
                        Some(pinned),
                        temporary_guard
                            .take()
                            .expect("failed backup inspection guard is delivered once"),
                    )));
                }
            };
            let digest = file_digest_with_deadline(&pinned.file, Some(&inspection_deadline_state));
            match digest {
                Ok(digest)
                    if snapshot_length <= MAX_AUTHENTICATED_SNAPSHOT_BYTES
                        && snapshot_length == inspection_receipt.byte_count
                        && digest == inspection_receipt.digest =>
                {
                    Ok(Ok((
                        pinned,
                        temporary_guard
                            .take()
                            .expect("backup inspection guard is delivered once"),
                    )))
                }
                Ok(_) => Ok(Err((
                    StateError::InvalidBackup {
                        path: inspection_destination.clone(),
                        reason: "completed backup failed final held size/digest verification"
                            .to_owned(),
                    },
                    Some(pinned),
                    temporary_guard
                        .take()
                        .expect("failed backup inspection guard is delivered once"),
                ))),
                Err(error) => Ok(Err((
                    error,
                    Some(pinned),
                    temporary_guard
                        .take()
                        .expect("failed backup inspection guard is delivered once"),
                ))),
            }
        },
    )
    .await?;
    let (pinned, temporary_guard) = match inspection {
        Ok(inspection) => inspection,
        Err((error, pinned, mut guard)) => {
            if let Some(pinned) = pinned {
                drop(pinned);
            }
            return Err(cleanup_backup_staging_or_error(&mut guard, error).await);
        }
    };
    #[cfg(test)]
    if tokio::time::timeout_at(
        deadline,
        wait_at_snapshot_test_barrier(destination, &temporary),
    )
    .await
    .is_err()
    {
        drop(pinned);
        let mut guard = temporary_guard;
        return Err(cleanup_backup_staging_or_error(&mut guard, timed_out()).await);
    }
    let durability_destination = destination.to_owned();
    let durability_temporary = temporary.clone();
    let durability_deadline_state = Arc::clone(&deadline_state);
    let mut pinned = Some(pinned);
    let mut temporary_guard = Some(temporary_guard);
    let durability = run_bounded_filesystem(
        durability_owner,
        deadline,
        "SQLite backup",
        timeout_ms,
        move || {
            let result = (|| {
                let mut identity_guard = initialize_restored_store_identity(
                    &durability_temporary,
                    &pinned
                        .as_ref()
                        .expect("backup durability snapshot remains owned")
                        .file,
                    &durability_destination,
                )?;
                if tokio::time::Instant::now() >= deadline {
                    return Err(StateError::OperationTimedOut {
                        operation: "SQLite backup",
                        timeout_ms,
                    });
                }
                let mut seal = create_trusted_backup_seal(
                    pinned
                        .as_ref()
                        .expect("backup durability snapshot remains owned"),
                    Some(durability_deadline_state.as_ref()),
                )?;
                if tokio::time::Instant::now() >= deadline {
                    let error = StateError::OperationTimedOut {
                        operation: "SQLite backup",
                        timeout_ms,
                    };
                    let error = match seal.cleanup() {
                        Ok(()) => error,
                        Err(cleanup) => append_operation_cleanup(
                            "SQLite backup",
                            error,
                            format!("seal cleanup failed: {cleanup}"),
                        ),
                    };
                    return Err(cleanup_identity_or_error(
                        "SQLite backup",
                        &mut identity_guard,
                        error,
                    ));
                }
                if let Err(error) = pinned
                    .as_ref()
                    .expect("backup durability snapshot remains owned")
                    .sync()
                {
                    let error = match seal.cleanup() {
                        Ok(()) => error,
                        Err(cleanup) => append_operation_cleanup(
                            "SQLite backup",
                            error,
                            format!("seal cleanup failed: {cleanup}"),
                        ),
                    };
                    return Err(cleanup_identity_or_error(
                        "SQLite backup",
                        &mut identity_guard,
                        error,
                    ));
                }
                if tokio::time::Instant::now() >= deadline {
                    let error = StateError::OperationTimedOut {
                        operation: "SQLite backup",
                        timeout_ms,
                    };
                    let error = match seal.cleanup() {
                        Ok(()) => error,
                        Err(cleanup) => append_operation_cleanup(
                            "SQLite backup",
                            error,
                            format!("seal cleanup failed: {cleanup}"),
                        ),
                    };
                    return Err(cleanup_identity_or_error(
                        "SQLite backup",
                        &mut identity_guard,
                        error,
                    ));
                }
                Ok((identity_guard, seal))
            })();
            Ok(match result {
                Ok((identity_guard, seal)) => Ok((
                    pinned
                        .take()
                        .expect("backup durability snapshot is delivered once"),
                    identity_guard,
                    seal,
                    temporary_guard
                        .take()
                        .expect("backup durability guard is delivered once"),
                )),
                Err(error) => Err((
                    error,
                    pinned
                        .take()
                        .expect("failed backup durability snapshot is delivered once"),
                    temporary_guard
                        .take()
                        .expect("failed backup durability guard is delivered once"),
                )),
            })
        },
    )
    .await?;
    let (pinned, identity_guard, seal, temporary_guard) = match durability {
        Ok(durable) => durable,
        Err((error, pinned, mut guard)) => {
            drop(pinned);
            return Err(cleanup_backup_staging_or_error(&mut guard, error).await);
        }
    };
    let publication_destination = destination.to_owned();
    let caller_receipt = write_receipt.clone();
    let publication_receipt = write_receipt;
    let publication_deadline_state = Arc::clone(&deadline_state);
    let mut pinned = Some(pinned);
    let mut temporary_guard = Some(temporary_guard);
    let mut identity_guard = Some(identity_guard);
    let mut seal = Some(seal);
    let publication = run_bounded_filesystem_with_acceptance(
        publication_owner,
        deadline + Duration::from_secs(1),
        deadline,
        "SQLite backup",
        timeout_ms,
        move || {
            let result = publish_bound_snapshot(
                pinned
                    .as_ref()
                    .expect("backup publication snapshot remains owned"),
                &mut temporary_guard
                    .as_mut()
                    .expect("backup publication guard remains owned")
                    .snapshot,
                &publication_destination,
                "SQLite backup",
                Some((deadline, timeout_ms)),
                Some(&publication_deadline_state),
                &destination_directory,
            );
            Ok(match result {
                Ok(()) => {
                    let handoff =
                        validate_published_snapshot_handoff(
                            &publication_destination,
                            &pinned
                                .as_ref()
                                .expect("backup publication snapshot remains owned")
                                .file,
                        )
                        .and_then(
                            |()| {
                                pinned
                                    .as_ref()
                                    .expect("backup publication snapshot remains owned")
                                    .verify()?;
                                let sealed_digest = validate_trusted_backup_seal(
                                    pinned
                                        .as_ref()
                                        .expect("backup publication snapshot remains owned"),
                                    Some(&publication_deadline_state),
                                )?;
                                if pinned
                                    .as_ref()
                                    .expect("backup publication snapshot remains owned")
                                    .file
                                    .metadata()
                                    .map_err(|error| {
                                        file_error(
                                            "inspect final published backup size",
                                            &publication_destination,
                                            error,
                                        )
                                    })?
                                    .len()
                                    != publication_receipt.byte_count
                                    || file_digest_with_deadline(
                                        &pinned
                                            .as_ref()
                                            .expect("backup publication snapshot remains owned")
                                            .file,
                                        Some(&publication_deadline_state),
                                    )? != publication_receipt.digest
                                    || sealed_digest.as_slice() != publication_receipt.digest
                                    || snapshot_is_staging(
                                        &publication_destination,
                                        &pinned
                                            .as_ref()
                                            .expect("backup publication snapshot remains owned")
                                            .file,
                                    )?
                                {
                                    return Err(StateError::InvalidBackup {
                                        path: publication_destination.clone(),
                                        reason: "published backup failed final digest/seal/marker verification"
                                            .to_owned(),
                                    });
                                }
                                if tokio::time::Instant::now() >= deadline
                                    || take_publication_deadline_expiration(
                                        &publication_destination,
                                        4,
                                    )
                                {
                                    Err(StateError::OperationTimedOut {
                                        operation: "SQLite backup",
                                        timeout_ms,
                                    })
                                } else {
                                    Ok(())
                                }
                            },
                        );
                    match handoff {
                        Ok(()) => {
                            identity_guard
                                .as_mut()
                                .expect("backup identity guard remains owned")
                                .mark_published();
                            seal.as_mut()
                                .expect("backup seal remains owned")
                                .disarm();
                            Ok((
                                pinned
                                    .take()
                                    .expect("published backup snapshot is delivered once"),
                                temporary_guard
                                    .take()
                                    .expect("published backup guard is delivered once"),
                                identity_guard
                                    .take()
                                    .expect("published backup identity is delivered once"),
                            ))
                        }
                        Err(error) => {
                            identity_guard
                                .as_mut()
                                .expect("backup identity guard remains owned")
                                .mark_published();
                            seal.as_mut()
                                .expect("backup seal remains owned")
                                .disarm();
                            temporary_guard
                                .as_mut()
                                .expect("backup publication guard remains owned")
                                .mark_publication_uncertain();
                            Err((
                                StateError::PublicationUncertain {
                                    path: publication_destination.clone(),
                                    reason: format!(
                                        "published backup failed final identity/deadline validation: {error}"
                                    ),
                                },
                                pinned
                                    .take()
                                    .expect("uncertain backup snapshot is delivered once"),
                                temporary_guard
                                    .take()
                                    .expect("uncertain backup guard is delivered once"),
                            ))
                        }
                    }
                }
                Err(error @ StateError::PublicationUncertain { .. }) => {
                    identity_guard
                        .as_mut()
                        .expect("backup identity guard remains owned")
                        .mark_published();
                    seal.as_mut()
                        .expect("backup seal remains owned")
                        .disarm();
                    Err((
                        error,
                        pinned
                            .take()
                            .expect("uncertain backup snapshot is delivered once"),
                        temporary_guard
                            .take()
                            .expect("uncertain backup guard is delivered once"),
                    ))
                }
                Err(error) => {
                    let error = match seal
                        .as_mut()
                        .expect("backup seal remains owned")
                        .cleanup()
                    {
                        Ok(()) => error,
                        Err(cleanup) => append_operation_cleanup(
                            "SQLite backup publication",
                            error,
                            format!("seal cleanup failed: {cleanup}"),
                        ),
                    };
                    let error = cleanup_identity_or_error(
                        "SQLite backup publication",
                        identity_guard
                            .as_mut()
                            .expect("backup identity guard remains owned"),
                        error,
                    );
                    Err((
                        error,
                        pinned
                            .take()
                            .expect("failed backup publication snapshot is delivered once"),
                        temporary_guard
                            .take()
                            .expect("failed backup publication guard is delivered once"),
                    ))
                }
            })
        },
    )
    .await;
    let publication = match publication {
        Ok(publication) => publication,
        Err(error) => {
            return Err(StateError::PublicationUncertain {
                path: destination.to_owned(),
                reason: format!(
                    "backup publication executor stopped after publication became possible: {error}"
                ),
            });
        }
    };
    let (pinned, temporary_guard, identity_guard) = match publication {
        Ok(published) => published,
        Err((error, pinned, mut temporary_guard)) => {
            if matches!(error, StateError::PublicationUncertain { .. }) {
                cancellation_guard.disarm();
                temporary_guard.mark_publication_uncertain();
                drop(pinned);
                return Err(error);
            }
            drop(pinned);
            return Err(cleanup_backup_staging_or_error(&mut temporary_guard, error).await);
        }
    };
    #[cfg(test)]
    wait_at_published_handoff_test_barrier(destination).await;
    let final_destination = destination.to_owned();
    let final_deadline_state = Arc::clone(&deadline_state);
    let mut pinned = Some(pinned);
    let mut temporary_guard = Some(temporary_guard);
    let mut identity_guard = Some(identity_guard);
    let final_handoff = run_bounded_filesystem_with_acceptance(
        final_handoff_owner,
        deadline + Duration::from_secs(1),
        deadline,
        "SQLite backup",
        timeout_ms,
        move || {
            let result = validate_published_snapshot_handoff(
                &final_destination,
                &pinned
                    .as_ref()
                    .expect("final backup snapshot remains owned")
                    .file,
            )
            .and_then(|()| {
                pinned
                    .as_ref()
                    .expect("final backup snapshot remains owned")
                    .verify()?;
                let sealed_digest = validate_trusted_backup_seal(
                    pinned
                        .as_ref()
                        .expect("final backup snapshot remains owned"),
                    Some(&final_deadline_state),
                )?;
                if pinned
                    .as_ref()
                    .expect("final backup snapshot remains owned")
                    .file
                    .metadata()
                    .map_err(|error| {
                        file_error(
                            "inspect caller published backup size",
                            &final_destination,
                            error,
                        )
                    })?
                    .len()
                    != caller_receipt.byte_count
                    || file_digest_with_deadline(
                        &pinned
                            .as_ref()
                            .expect("final backup snapshot remains owned")
                            .file,
                        Some(&final_deadline_state),
                    )? != caller_receipt.digest
                    || sealed_digest.as_slice() != caller_receipt.digest
                    || snapshot_is_staging(
                        &final_destination,
                        &pinned
                            .as_ref()
                            .expect("final backup snapshot remains owned")
                            .file,
                    )?
                    || tokio::time::Instant::now() >= deadline
                {
                    return Err(StateError::OperationTimedOut {
                        operation: "SQLite backup",
                        timeout_ms,
                    });
                }
                Ok(())
            });
            let result = result.and_then(|()| {
                temporary_guard
                    .as_mut()
                    .expect("final backup guard remains owned")
                    .disarm_published()
            });
            Ok(match result {
                Ok(()) => Ok((
                    pinned
                        .take()
                        .expect("final backup snapshot is delivered once"),
                    temporary_guard
                        .take()
                        .expect("final backup guard is delivered once"),
                    identity_guard
                        .take()
                        .expect("final backup identity is delivered once"),
                )),
                Err(error) => Err((
                    error,
                    pinned
                        .take()
                        .expect("failed final backup snapshot is delivered once"),
                    temporary_guard
                        .take()
                        .expect("failed final backup guard is delivered once"),
                    identity_guard
                        .take()
                        .expect("failed final backup identity is delivered once"),
                )),
            })
        },
    )
    .await;
    let (pinned, _temporary_guard, mut identity_guard) = match final_handoff {
        Ok(Ok(result)) => result,
        Ok(Err((error, pinned, mut guard, identity_guard))) => {
            guard.mark_publication_uncertain();
            drop((pinned, identity_guard));
            cancellation_guard.disarm();
            return Err(StateError::PublicationUncertain {
                path: destination.to_owned(),
                reason: format!("published backup failed caller handoff: {error}"),
            });
        }
        Err(error) => {
            cancellation_guard.disarm();
            return Err(StateError::PublicationUncertain {
                path: destination.to_owned(),
                reason: format!("published backup caller handoff stopped: {error}"),
            });
        }
    };
    drop(pinned);
    cancellation_guard.disarm();
    identity_guard.disarm();
    Ok(())
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

async fn mark_backup_provenance_connection(
    path: &Path,
    connection: &mut SqliteConnection,
) -> Result<(), StateError> {
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

async fn validate_standalone_snapshot_source(path: &Path) -> Result<Vec<u8>, StateError> {
    let snapshot = PinnedSnapshot::open(path)?;
    validate_standalone_snapshot_source_pinned(&snapshot, None)
}

fn validate_standalone_snapshot_source_pinned(
    snapshot: &PinnedSnapshot,
    deadline_state: Option<Arc<OpenDeadlineState>>,
) -> Result<Vec<u8>, StateError> {
    validate_standalone_sidecar_absence(snapshot)?;
    validate_trusted_backup_seal(snapshot, deadline_state.as_deref())
}

fn validate_standalone_sidecar_absence(snapshot: &PinnedSnapshot) -> Result<(), StateError> {
    let path = &snapshot.path;
    snapshot.verify()?;
    reject_snapshot_staging_marker(path, &snapshot.file)?;
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
    let owner_deadline = deadline_state.as_ref().map_or_else(
        || std::time::Instant::now() + MAX_CONFIGURED_TIMEOUT,
        |state| state.work_cutoff,
    );
    let mut cleanup_owners = claw_sqlite_file_control::BlockingCleanupOwner::acquire_set(
        "claw-state-backup-validation-owner",
        1,
        owner_deadline,
    )
    .await
    .map_err(|error| {
        OpenDeadlineState::deadline_or_error(
            deadline_state.as_deref(),
            database(
                "reserve backup validation cleanup owner",
                sqlx::Error::Protocol(error),
            ),
        )
    })?;
    let cleanup_owner = cleanup_owners
        .pop()
        .expect("backup validation cleanup owner");
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
    let mut connection = OwnedSqliteConnectionGuard::new_cancellable_with_owner(
        connection,
        deadline_state.clone(),
        cleanup_owner,
    );
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
    #[cfg(target_os = "linux")]
    use std::sync::Arc;

    #[cfg(unix)]
    use sqlx::SqliteConnection;
    use sqlx::SqlitePool;

    #[cfg(unix)]
    use super::verify_sqlite_connection_identity;
    use super::{
        EXPIRE_OUTPUT_CREATION_DEADLINE, EXPIRE_PUBLICATION_DEADLINE, FAIL_AFTER_PUBLICATION,
        PinnedSnapshot, STALL_HEALTH_PROGRESS, StateStore, create_trusted_backup_seal,
        migration_checksum,
    };
    use crate::StateError;

    pub(crate) fn pool(store: &StateStore) -> &SqlitePool {
        store.pool()
    }

    #[cfg(not(windows))]
    pub(crate) fn lock_path(store: &StateStore) -> std::path::PathBuf {
        store.lock_path.clone()
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

    #[cfg(target_os = "linux")]
    pub(crate) fn fail_protected_snapshot_at(path: &Path, stage: u8) {
        assert!((1..=3).contains(&stage));
        super::PROTECTED_SNAPSHOT_TEST_FAILURES
            .lock()
            .expect("protected snapshot failure map lock poisoned")
            .insert(path.to_owned(), stage);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn install_protected_snapshot_gate(
        path: &Path,
    ) -> (
        Arc<tokio::sync::Notify>,
        Arc<tokio::sync::Notify>,
        Arc<std::sync::atomic::AtomicU8>,
    ) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let slot = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let previous = super::PROTECTED_SNAPSHOT_TEST_GATES
            .lock()
            .expect("protected snapshot gate map lock poisoned")
            .insert(
                path.to_owned(),
                super::ProtectedSnapshotTestGate {
                    stage: 4,
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                    slot: Arc::clone(&slot),
                },
            );
        assert!(
            previous.is_none(),
            "protected snapshot gate is installed once"
        );
        (entered, release, slot)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn clear_protected_snapshot_gate(path: &Path) {
        if let Some(gate) = super::PROTECTED_SNAPSHOT_TEST_GATES
            .lock()
            .expect("protected snapshot gate map lock poisoned")
            .remove(path)
        {
            gate.release.notify_waiters();
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn reject_protected_connection_and_close(
        namespace: Arc<super::ProtectedNamespace>,
        connection: SqliteConnection,
        fail_persistent_wal: bool,
    ) -> String {
        super::FAIL_PROTECTED_PERSIST_WAL
            .store(fail_persistent_wal, std::sync::atomic::Ordering::Release);
        let owner = claw_sqlite_file_control::BlockingCleanupOwner::acquire(
            "claw-state-protected-connection-rejection-test",
        )
        .await
        .expect("reserve rejected protected connection cleanup owner");
        let mut connection =
            super::OwnedSqliteConnectionGuard::new_cancellable_with_owner(connection, None, owner);
        let error = super::ActiveStoreProfile::LinuxProtected(namespace)
            .verify_connection(&mut connection)
            .await
            .expect_err("invalid protected connection must be rejected");
        connection
            .close()
            .await
            .expect("rejected protected connection is terminally closed");
        error.to_string()
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
        #[cfg(windows)]
        drop(process_identity);
        #[cfg(not(windows))]
        {
            std::fs::File::unlock(&lock_file).expect("unlock store identity fixture");
            drop(process_identity);
        }
        drop((lock_file, database_file));
    }

    pub(crate) fn fail_after_publication_once(destination: &Path) {
        let destination =
            super::resolve_database_path(destination).expect("resolve publication failpoint path");
        FAIL_AFTER_PUBLICATION
            .lock()
            .expect("publication failpoint lock poisoned")
            .insert(destination);
    }

    pub(crate) fn expire_publication_deadline_once(destination: &Path, stage: u8) {
        assert!(
            matches!(stage, 0..=4),
            "publication deadline stage is valid"
        );
        let destination =
            super::resolve_database_path(destination).expect("resolve publication deadline path");
        let previous = EXPIRE_PUBLICATION_DEADLINE
            .lock()
            .expect("publication deadline failpoint lock poisoned")
            .insert(destination, stage);
        assert!(
            previous.is_none(),
            "publication deadline failpoint must be unique"
        );
    }

    pub(crate) fn expire_output_creation_deadline_once(destination: &Path) {
        let destination =
            super::resolve_database_path(destination).expect("resolve output creation path");
        let inserted = EXPIRE_OUTPUT_CREATION_DEADLINE
            .lock()
            .expect("output creation deadline failpoint lock poisoned")
            .insert(destination);
        assert!(inserted, "output creation expiration is registered once");
    }

    pub(crate) fn stall_health_progress_once(path: &Path) {
        let path = super::resolve_database_path(path).expect("resolve health progress path");
        let inserted = STALL_HEALTH_PROGRESS
            .lock()
            .expect("health progress failpoint lock poisoned")
            .insert(path);
        assert!(inserted, "health progress failpoint must be unique");
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

    pub(crate) fn panic_close_after_ownership_guard_once(path: &Path) {
        let path = super::resolve_database_path(path).expect("resolve close panic failpoint path");
        let inserted = super::PANIC_CLOSE_AFTER_OWNERSHIP_GUARD
            .lock()
            .expect("close panic failpoint lock poisoned")
            .insert(path);
        assert!(inserted, "close panic failpoint is registered once");
    }

    pub(crate) fn close_retention_capacity() -> usize {
        super::MAX_STATE_CLOSE_RETENTIONS
    }

    pub(crate) fn available_close_retention_slots() -> usize {
        super::STATE_CLOSE_RETENTION_SLOTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|slot| !slot.reserved)
            .count()
    }

    pub(crate) fn retained_state_cleanup_jobs() -> usize {
        super::STATE_CLEANUP_QUARANTINE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .slots
            .iter()
            .filter(|entry| entry.is_some())
            .count()
    }

    pub(crate) fn open_transaction_waiters() -> usize {
        super::OPEN_TRANSACTION_WAITERS.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) async fn handoff_expired_undelivered_store(store: super::StateStore) -> usize {
        super::EXPIRED_UNDELIVERED_BEGIN_DISPATCHES.store(0, std::sync::atomic::Ordering::Release);
        let owner =
            claw_sqlite_file_control::BlockingCleanupOwner::acquire("expired-undelivered-test")
                .await
                .expect("reserve expired undelivered cleanup owner");
        let open_admission = super::STATE_OPEN_ADMISSION
            .acquire()
            .await
            .expect("reserve expired undelivered open admission");
        let now = std::time::Instant::now();
        let deadline_state = std::sync::Arc::new(super::OpenDeadlineState {
            work_cutoff: now - std::time::Duration::from_millis(2),
            deadline: now - std::time::Duration::from_millis(1),
            timeout_ms: 1,
            operation: "state store open",
            busy_timeout: std::time::Duration::from_secs(1),
            expired: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            finished: std::sync::atomic::AtomicBool::new(false),
            final_commit_state: std::sync::atomic::AtomicU8::new(1),
            open_cleanup_state: std::sync::atomic::AtomicU8::new(1),
        });
        super::handoff_undelivered_store(
            owner,
            store,
            open_admission,
            tokio::time::Instant::from_std(deadline_state.deadline),
            std::sync::Arc::clone(&deadline_state),
        )
        .expect("handoff expired undelivered store");
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !deadline_state
                .finished
                .load(std::sync::atomic::Ordering::Acquire)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("expired undelivered ownership reaches terminal release");
        super::EXPIRED_UNDELIVERED_BEGIN_DISPATCHES.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) struct UndeliveredCompletion(std::sync::Arc<super::OpenDeadlineState>);

    pub(crate) async fn handoff_gated_undelivered_store(
        store: super::StateStore,
        after_delete: bool,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
        UndeliveredCompletion,
    ) {
        let path = store.path().to_owned();
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let barriers = if after_delete {
            &super::UNDELIVERED_AFTER_DELETE_TEST_BARRIER
        } else {
            &super::UNDELIVERED_AFTER_BEGIN_TEST_BARRIER
        };
        barriers
            .lock()
            .expect("gated undelivered barrier lock poisoned")
            .insert(
                path,
                super::MigrationTestBarrier {
                    entered: std::sync::Arc::clone(&entered),
                    release: std::sync::Arc::clone(&release),
                },
            );
        let owner =
            claw_sqlite_file_control::BlockingCleanupOwner::acquire("gated-undelivered-test")
                .await
                .expect("reserve gated undelivered cleanup owner");
        let open_admission = super::STATE_OPEN_ADMISSION
            .acquire()
            .await
            .expect("reserve gated undelivered open admission");
        let now = std::time::Instant::now();
        let deadline_state = std::sync::Arc::new(super::OpenDeadlineState {
            work_cutoff: now + std::time::Duration::from_millis(190),
            deadline: now + std::time::Duration::from_millis(200),
            timeout_ms: 200,
            operation: "state store open",
            busy_timeout: std::time::Duration::from_secs(1),
            expired: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            finished: std::sync::atomic::AtomicBool::new(false),
            final_commit_state: std::sync::atomic::AtomicU8::new(0),
            open_cleanup_state: std::sync::atomic::AtomicU8::new(1),
        });
        super::handoff_undelivered_store(
            owner,
            store,
            open_admission,
            tokio::time::Instant::from_std(deadline_state.deadline),
            std::sync::Arc::clone(&deadline_state),
        )
        .expect("handoff gated undelivered store");
        (entered, release, UndeliveredCompletion(deadline_state))
    }

    pub(crate) async fn wait_for_undelivered_completion(completion: &UndeliveredCompletion) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !completion
                .0
                .finished
                .load(std::sync::atomic::Ordering::Acquire)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("gated undelivered ownership reaches terminal release");
    }

    pub(crate) fn set_open_admission_barrier() -> (
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut barrier = super::OPEN_ADMISSION_TEST_BARRIER
            .lock()
            .expect("open admission test barrier lock poisoned");
        assert!(barrier.is_none(), "open admission test barrier is unique");
        *barrier = Some(super::OpenAdmissionTestBarrier {
            entered: std::sync::Arc::clone(&entered),
            release: std::sync::Arc::clone(&release),
        });
        (entered, release)
    }

    pub(crate) fn clear_open_admission_barrier() {
        super::OPEN_ADMISSION_TEST_BARRIER
            .lock()
            .expect("open admission test barrier lock poisoned")
            .take();
    }

    pub(crate) fn set_before_acquire_owner_barrier() -> (
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let releases = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        super::OPEN_RESERVED_OWNER_GATE_REMAINING.store(
            super::OPEN_TRANSACTION_ADMISSION_LIMIT,
            std::sync::atomic::Ordering::Release,
        );
        let mut barrier = super::BEFORE_ACQUIRE_OWNER_TEST_BARRIER
            .lock()
            .expect("before-acquire owner barrier lock poisoned");
        assert!(barrier.is_none(), "before-acquire owner barrier is unique");
        *barrier = Some(super::BeforeAcquireOwnerTestBarrier {
            entered: std::sync::Arc::clone(&entered),
            releases: std::sync::Arc::clone(&releases),
        });
        (entered, releases)
    }

    pub(crate) fn clear_before_acquire_owner_barrier() {
        super::OPEN_RESERVED_OWNER_GATE_REMAINING.store(0, std::sync::atomic::Ordering::Release);
        super::BEFORE_ACQUIRE_OWNER_TEST_BARRIER
            .lock()
            .expect("before-acquire owner barrier lock poisoned")
            .take();
        super::OPEN_RESERVED_OWNER_PATHS
            .lock()
            .expect("reserved owner path set lock poisoned")
            .clear();
    }

    pub(crate) fn set_early_verifier_retire_barrier(
        path: &Path,
    ) -> (
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        let path = super::resolve_database_path(path).expect("resolve early verifier retire path");
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        assert!(
            super::EARLY_VERIFIER_RETIRE_PATHS
                .lock()
                .expect("early verifier retire path set lock poisoned")
                .insert(path.clone()),
            "early verifier retire path is configured once"
        );
        assert!(
            super::EARLY_VERIFIER_RETIRE_TEST_BARRIER
                .lock()
                .expect("early verifier retire barrier lock poisoned")
                .insert(
                    path,
                    super::OpenAdmissionTestBarrier {
                        entered: std::sync::Arc::clone(&entered),
                        release: std::sync::Arc::clone(&release),
                    },
                )
                .is_none(),
            "early verifier retire barrier is configured once"
        );
        (entered, release)
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
        let mut seal = create_trusted_backup_seal(&snapshot, None)
            .expect("create trusted backup fixture seal");
        seal.disarm();
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

    pub(crate) async fn assert_snapshot_memory_saturation() {
        let admission = std::sync::Arc::new(tokio::sync::Semaphore::new(
            super::PROCESS_SNAPSHOT_PEAK_UNITS,
        ));
        let first = std::sync::Arc::clone(&admission)
            .acquire_many_owned(super::SNAPSHOT_OPERATION_PEAK_UNITS)
            .await
            .expect("reserve first snapshot peak");
        let second = std::sync::Arc::clone(&admission)
            .acquire_many_owned(super::SNAPSHOT_OPERATION_PEAK_UNITS)
            .await
            .expect("reserve second snapshot peak");
        let blocked = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            std::sync::Arc::clone(&admission)
                .acquire_many_owned(super::SNAPSHOT_OPERATION_PEAK_UNITS),
        )
        .await;
        assert!(blocked.is_err());
        drop(first);
        let replacement = std::sync::Arc::clone(&admission)
            .acquire_many_owned(super::SNAPSHOT_OPERATION_PEAK_UNITS)
            .await
            .expect("released peak reservation is reusable");
        drop((second, replacement));
    }

    pub(crate) async fn drop_disarmed_snapshot_guard(path: &Path) {
        let path = super::resolve_database_path(path).expect("resolve published snapshot path");
        let parent = super::pin_private_directory(&path).expect("pin published snapshot parent");
        let cleanup_owner =
            claw_sqlite_file_control::BlockingCleanupOwner::acquire("test snapshot cleanup owner")
                .await
                .expect("reserve test snapshot cleanup owner");
        let mut guard =
            super::SnapshotCleanupGuard::new_pinned(&path, &parent, cleanup_owner, None)
                .expect("create snapshot guard");
        let file =
            super::open_existing_file_no_follow(&path).expect("open published snapshot identity");
        guard
            .bind_file(&file)
            .expect("bind published snapshot identity");
        guard.disarm().expect("disarm published snapshot guard");
        drop(guard);
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

    pub(crate) fn set_open_postcommit_hold_barrier(
        path: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let barrier = set_open_postcommit_barrier(path);
        let path =
            super::resolve_database_path(path).expect("resolve held postcommit barrier path");
        assert!(
            super::OPEN_POSTCOMMIT_HOLD_AFTER_CANCEL
                .lock()
                .expect("open postcommit hold set lock poisoned")
                .insert(path),
            "held postcommit barrier is configured once"
        );
        barrier
    }

    pub(crate) fn set_open_after_ack_barrier(
        path: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let path = super::resolve_database_path(path).expect("resolve after-ack barrier path");
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        assert!(
            super::OPEN_AFTER_ACK_TEST_BARRIER
                .lock()
                .expect("open after-ack barrier lock poisoned")
                .insert(
                    path,
                    super::MigrationTestBarrier {
                        entered: std::sync::Arc::clone(&entered),
                        release: std::sync::Arc::clone(&release),
                    },
                )
                .is_none(),
            "open after-ack barrier is configured once"
        );
        (entered, release)
    }

    pub(crate) fn set_open_after_ack_cancel_barrier(
        path: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let barrier = set_open_after_ack_barrier(path);
        let path =
            super::resolve_database_path(path).expect("resolve after-ack cancel barrier path");
        assert!(
            super::OPEN_AFTER_ACK_CANCEL_ON_RELEASE
                .lock()
                .expect("open after-ack cancel set lock poisoned")
                .insert(path),
            "open after-ack cancellation is configured once"
        );
        barrier
    }

    pub(crate) fn set_open_after_ack_expire_barrier(
        path: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let barrier = set_open_after_ack_barrier(path);
        let path =
            super::resolve_database_path(path).expect("resolve after-ack expire barrier path");
        assert!(
            super::OPEN_AFTER_ACK_EXPIRE_ON_RELEASE
                .lock()
                .expect("open after-ack expire set lock poisoned")
                .insert(path),
            "open after-ack expiry is configured once"
        );
        barrier
    }

    pub(crate) fn set_open_cleanup_budget(path: &Path, budget: std::time::Duration) {
        let path = super::resolve_database_path(path).expect("resolve open cleanup budget path");
        assert!(
            super::OPEN_TEST_CLEANUP_BUDGET
                .lock()
                .expect("open test cleanup budget lock poisoned")
                .insert(path, budget)
                .is_none(),
            "open cleanup budget is configured once"
        );
    }

    pub(crate) struct OpenDeadlineObservation(super::OpenTestDeadlineObserver);

    pub(crate) fn observe_open_deadlines(path: &Path) -> OpenDeadlineObservation {
        let path = super::resolve_database_path(path).expect("resolve open deadline observer path");
        let observer = std::sync::Arc::new(std::sync::Mutex::new(None));
        assert!(
            super::OPEN_TEST_DEADLINE_OBSERVERS
                .lock()
                .expect("open deadline observer map lock poisoned")
                .insert(path, std::sync::Arc::clone(&observer))
                .is_none(),
            "open deadline observer is configured once"
        );
        OpenDeadlineObservation(observer)
    }

    pub(crate) async fn wait_for_open_deadlines(
        observer: &OpenDeadlineObservation,
    ) -> (tokio::time::Instant, tokio::time::Instant) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if let Some(deadlines) = *observer
                    .0
                    .lock()
                    .expect("open deadline observation lock poisoned")
                {
                    break deadlines;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("open publishes its exact deadlines")
    }

    pub(crate) fn set_open_cleanup_barrier(
        path: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let path = super::resolve_database_path(path).expect("resolve open cleanup barrier path");
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        super::OPEN_CLEANUP_TEST_BARRIER
            .lock()
            .expect("open cleanup test barrier lock poisoned")
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

    pub(crate) fn set_checkpoint_identity_barrier() -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let previous = super::CHECKPOINT_IDENTITY_TEST_CONTROL
            .lock()
            .expect("checkpoint identity test control lock poisoned")
            .replace(super::CheckpointIdentityTestControl {
                entered: std::sync::Arc::clone(&entered),
                release: std::sync::Arc::clone(&release),
            });
        assert!(
            previous.is_none(),
            "checkpoint identity barrier is configured once"
        );
        (entered, release)
    }

    pub(crate) fn clear_checkpoint_identity_barrier() {
        super::CHECKPOINT_IDENTITY_TEST_CONTROL
            .lock()
            .expect("checkpoint identity test control lock poisoned")
            .take();
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

    #[cfg(windows)]
    pub(crate) async fn cleanup_renamed_windows_snapshot(
        staging: &Path,
        alternate: &Path,
        victim: &Path,
        block_first_delete: bool,
        normal_queue_pressure: bool,
    ) {
        use std::io::Write as _;
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        let staging =
            super::resolve_database_path(staging).expect("resolve Windows staging fixture");
        let alternate =
            super::resolve_database_path(alternate).expect("resolve Windows alternate fixture");
        let victim = super::resolve_database_path(victim).expect("resolve Windows victim fixture");
        let retained_signal = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
        let parent =
            super::pin_private_directory(&staging).expect("pin Windows staging fixture parent");
        let cleanup_owner =
            claw_sqlite_file_control::BlockingCleanupOwner::acquire("windows-bound-delete-test")
                .await
                .expect("reserve Windows bound deletion cleanup owner");
        let mut guard =
            super::SnapshotCleanupGuard::new_pinned(&staging, &parent, cleanup_owner, None)
                .expect("create Windows bound deletion guard");
        guard.retained_signal = Some(std::sync::Arc::clone(&retained_signal));
        let mut file = super::create_bound_snapshot_output(
            &staging,
            Some(&mut guard),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            None,
            "Windows bound deletion test",
            1_000,
        )
        .expect("create Windows bound deletion staging");
        file.write_all(b"sensitive staging bytes")
            .and_then(|()| file.sync_all())
            .expect("persist Windows bound deletion staging");
        drop(file);
        std::fs::rename(&staging, &alternate).expect("rename bound Windows staging");
        std::fs::hard_link(&victim, &staging).expect("substitute Windows victim");
        let blocker = block_first_delete.then(|| {
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .open(&alternate)
                .expect("block the first Windows bound deletion")
        });
        let result = guard.cleanup().await;
        if let Some(blocker) = blocker {
            assert!(
                result.is_err(),
                "a failed handle deletion must not report successful cleanup"
            );
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while retained_signal.load(std::sync::atomic::Ordering::Acquire) < 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("this exact blocked Windows cleanup exhausts into retained retry");
            assert_eq!(
                std::fs::metadata(&alternate)
                    .expect("stat scrubbed retained Windows staging")
                    .len(),
                0,
                "bound staging contents are scrubbed before deletion can be blocked"
            );
            let pressure = if normal_queue_pressure {
                let unrelated_release =
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let unrelated_signal = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
                let unrelated_owner = claw_sqlite_file_control::BlockingCleanupOwner::acquire(
                    "windows-unrelated-retained-test",
                )
                .await
                .expect("reserve unrelated retained cleanup owner");
                super::handoff_state_payload_decide_with_signal(
                    unrelated_owner,
                    std::sync::Arc::clone(&unrelated_release),
                    Some(std::sync::Arc::clone(&unrelated_signal)),
                    None,
                    |_, _, release| release.load(std::sync::atomic::Ordering::Acquire),
                )
                .expect("submit unrelated retained cleanup");
                tokio::time::timeout(std::time::Duration::from_secs(1), async {
                    while unrelated_signal.load(std::sync::atomic::Ordering::Acquire) != 1 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("unrelated cleanup reaches its exact retained slot");
                let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let completed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let producer_stop = std::sync::Arc::clone(&stop);
                let producer_accepted = std::sync::Arc::clone(&accepted);
                let producer_completed = std::sync::Arc::clone(&completed);
                let producer = tokio::spawn(async move {
                    while !producer_stop.load(std::sync::atomic::Ordering::Acquire) {
                        let owner = claw_sqlite_file_control::BlockingCleanupOwner::acquire(
                            "windows-retained-fairness-test",
                        )
                        .await
                        .expect("reserve normal cleanup pressure owner");
                        let completed = std::sync::Arc::clone(&producer_completed);
                        super::handoff_state_payload(owner, completed, |_, _, completed| {
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            completed.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                        })
                        .expect("submit normal cleanup pressure job");
                        producer_accepted.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    }
                });
                tokio::time::timeout(std::time::Duration::from_secs(1), async {
                    while accepted.load(std::sync::atomic::Ordering::Acquire) < 64 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("normal cleanup pressure fills executor capacity");
                Some((
                    producer,
                    stop,
                    accepted,
                    completed,
                    unrelated_release,
                    unrelated_signal,
                ))
            } else {
                None
            };
            drop(blocker);
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while retained_signal.load(std::sync::atomic::Ordering::Acquire) != 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("exact retained Windows cleanup releases its slot and capacity");
            assert!(
                !alternate.exists(),
                "exact retained Windows staging is deleted before completion"
            );
            if let Some((
                producer,
                stop,
                accepted,
                completed,
                unrelated_release,
                unrelated_signal,
            )) = pressure
            {
                assert!(
                    !producer.is_finished(),
                    "normal cleanup producer remains actively submitting at retained completion"
                );
                assert_eq!(
                    unrelated_signal.load(std::sync::atomic::Ordering::Acquire),
                    1,
                    "unrelated cleanup remains retained through exact target completion"
                );
                stop.store(true, std::sync::atomic::Ordering::Release);
                tokio::time::timeout(std::time::Duration::from_secs(5), producer)
                    .await
                    .expect("normal cleanup pressure producer remains bounded")
                    .expect("normal cleanup pressure producer joins");
                let accepted = accepted.load(std::sync::atomic::Ordering::Acquire);
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    while completed.load(std::sync::atomic::Ordering::Acquire) < accepted {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("every accepted normal cleanup pressure job completes");
                assert_eq!(
                    completed.load(std::sync::atomic::Ordering::Acquire),
                    accepted
                );
                unrelated_release.store(true, std::sync::atomic::Ordering::Release);
                tokio::time::timeout(std::time::Duration::from_secs(1), async {
                    while unrelated_signal.load(std::sync::atomic::Ordering::Acquire) != 2 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("unrelated retained cleanup releases its slot and capacity");
            }
        } else {
            result.expect("cleanup exact renamed Windows staging");
        }
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

    #[cfg(unix)]
    pub(crate) struct SnapshotHardeningBarrier {
        destination: std::path::PathBuf,
        state: std::sync::Arc<super::SnapshotHardeningTestBarrier>,
    }

    #[cfg(unix)]
    impl Drop for SnapshotHardeningBarrier {
        fn drop(&mut self) {
            self.state.release();
            let mut barriers = super::SNAPSHOT_HARDENING_TEST_BARRIER
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if barriers
                .get(&self.destination)
                .is_some_and(|barrier| std::sync::Arc::ptr_eq(barrier, &self.state))
            {
                barriers.remove(&self.destination);
            }
        }
    }

    #[cfg(unix)]
    pub(crate) fn set_snapshot_hardening_barrier(
        destination: &Path,
    ) -> (
        SnapshotHardeningBarrier,
        std::sync::Arc<std::sync::Mutex<Option<std::path::PathBuf>>>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let destination = super::resolve_database_path(destination)
            .expect("resolve snapshot hardening barrier path");
        let temporary = std::sync::Arc::new(std::sync::Mutex::new(None));
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let state = std::sync::Arc::new(super::SnapshotHardeningTestBarrier {
            temporary: std::sync::Arc::clone(&temporary),
            entered: std::sync::Arc::clone(&entered),
            released: std::sync::Mutex::new(false),
            changed: std::sync::Condvar::new(),
        });
        let previous = super::SNAPSHOT_HARDENING_TEST_BARRIER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(destination.clone(), std::sync::Arc::clone(&state));
        assert!(
            previous.is_none(),
            "snapshot hardening barrier must be unique"
        );
        (
            SnapshotHardeningBarrier { destination, state },
            temporary,
            entered,
        )
    }

    pub(crate) fn set_restore_read_barrier(
        destination: &Path,
    ) -> (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let destination =
            super::resolve_database_path(destination).expect("resolve restore read barrier path");
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        super::RESTORE_READ_TEST_BARRIER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                destination,
                super::MigrationTestBarrier {
                    entered: std::sync::Arc::clone(&entered),
                    release: std::sync::Arc::clone(&release),
                },
            );
        (entered, release)
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
                std::sync::Arc::new(super::BackupCaptureTestBarrier {
                    entered: std::sync::Arc::clone(&entered),
                    release: std::sync::Arc::clone(&release),
                    observed: std::sync::atomic::AtomicBool::new(false),
                }),
            );
        (entered, release)
    }

    pub(crate) fn clear_snapshot_barrier(destination: &Path) {
        let file_name = destination.file_name().map(ToOwned::to_owned);
        super::SNAPSHOT_TEST_BARRIER
            .lock()
            .expect("snapshot test barrier lock poisoned")
            .retain(|path, _| path.file_name().map(ToOwned::to_owned) != file_name);
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
        let bytes = std::fs::read(path)
            .map_err(|error| super::file_error("read journal inspection bytes", path, error))?;
        if bytes.len() < 20 || &bytes[..16] != b"SQLite format 3\0" {
            return Err(StateError::InvalidBackup {
                path: path.to_owned(),
                reason: "journal inspection source is not a SQLite database".to_owned(),
            });
        }
        Ok(if bytes[18] == 2 && bytes[19] == 2 {
            "wal".to_owned()
        } else {
            "delete".to_owned()
        })
    }

    #[cfg(unix)]
    pub(crate) async fn sqlite_identity_is_valid(connection: &mut SqliteConnection) -> bool {
        verify_sqlite_connection_identity(connection).await.is_ok()
    }
}

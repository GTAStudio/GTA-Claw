//! Minimal audited access to SQLite file-control operations.

use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::ptr::NonNull;
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
/// Failure returned by SQLite while inspecting its open main database file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileControlError {
    /// SQLx could not lock its live SQLite handle.
    Handle(String),
    /// SQLite rejected the file-control request.
    SQLite(i32),
    /// COMMIT became durable after its delivery deadline and was quarantined.
    CommittedAfterDeadline(Option<String>),
    /// COMMIT became durable but terminal connection cleanup degraded.
    CommittedWithCleanupFailure(String),
    /// COMMIT returned an error after autocommit made durability uncertain.
    CommitOutcomeUncertain(i32, String),
}

/// Builds the fixed-format record stored in Windows sidecar generation ADS.
#[cfg(windows)]
pub fn windows_sidecar_generation_record(identity: &[u8]) -> [u8; 52] {
    let digest = Sha256::digest(identity);
    let mut record = [0_u8; 52];
    record[..20].copy_from_slice(b"GTA-CLAW-SIDECAR-V1\0");
    record[20..].copy_from_slice(&digest);
    record
}

/// Builds the authenticated fixed-format Unix sidecar generation record.
#[cfg(unix)]
pub fn unix_sidecar_generation_record(
    database_path: &std::path::Path,
    sidecar_path: &std::path::Path,
    identity: &[u8],
) -> [u8; 52] {
    let mut digest = Sha256::new();
    for value in [
        identity,
        database_path.as_os_str().as_encoded_bytes(),
        sidecar_path.as_os_str().as_encoded_bytes(),
    ] {
        digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
        digest.update(value);
    }
    let mut record = [0_u8; 52];
    record[..20].copy_from_slice(b"GTA-CLAW-SIDECAR-U1\0");
    record[20..].copy_from_slice(&digest.finalize());
    record
}

impl FileControlError {
    /// Returns SQLite's result code.
    #[must_use]
    pub const fn code(&self) -> Option<i32> {
        match self {
            Self::Handle(_) => None,
            Self::SQLite(code) => Some(*code),
            Self::CommittedAfterDeadline(_) => None,
            Self::CommittedWithCleanupFailure(_) => None,
            Self::CommitOutcomeUncertain(code, _) => Some(*code),
        }
    }
}

impl Display for FileControlError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handle(message) => write!(formatter, "failed to lock SQLite handle: {message}"),
            Self::SQLite(code) => {
                write!(
                    formatter,
                    "SQLite file-control operation failed with code {code}"
                )
            }
            Self::CommittedAfterDeadline(cleanup) => {
                write!(formatter, "SQLite COMMIT became durable after its deadline")?;
                if let Some(cleanup) = cleanup {
                    write!(formatter, "; late writer-claim cleanup failed: {cleanup}")?;
                }
                Ok(())
            }
            Self::CommittedWithCleanupFailure(cleanup) => {
                write!(
                    formatter,
                    "SQLite COMMIT became durable but cleanup failed: {cleanup}"
                )
            }
            Self::CommitOutcomeUncertain(code, cleanup) => write!(
                formatter,
                "SQLite COMMIT returned code {code} after autocommit; outcome is uncertain: {cleanup}"
            ),
        }
    }
}

impl Error for FileControlError {}

fn append_committed_cleanup(
    error: FileControlError,
    additional: impl std::fmt::Display,
) -> FileControlError {
    match error {
        FileControlError::CommittedWithCleanupFailure(cleanup) => {
            FileControlError::CommittedWithCleanupFailure(format!("{cleanup}; {additional}"))
        }
        FileControlError::CommitOutcomeUncertain(code, cleanup) => {
            FileControlError::CommitOutcomeUncertain(code, format!("{cleanup}; {additional}"))
        }
        error => FileControlError::Handle(format!("{error}; {additional}")),
    }
}

#[derive(Clone, Copy)]
struct LiveInterruptPointer(NonNull<libsqlite3_sys::sqlite3>);

struct LiveBackupPointer(Option<NonNull<libsqlite3_sys::sqlite3_backup>>);

struct BackupBusyState {
    deadline: std::time::Instant,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}

unsafe extern "C" fn backup_busy_handler(
    context: *mut std::ffi::c_void,
    _prior_calls: std::ffi::c_int,
) -> std::ffi::c_int {
    // SAFETY: the backup function retains this context until both handlers are restored.
    let state = unsafe { &*context.cast::<BackupBusyState>() };
    if state.cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= state.deadline {
        0
    } else {
        std::thread::yield_now();
        1
    }
}

struct BackupBusyRegistration {
    database: LiveInterruptPointer,
    restore_milliseconds: i32,
}

impl Drop for BackupBusyRegistration {
    fn drop(&mut self) {
        // SAFETY: both connections remain exclusively borrowed until registration drop.
        unsafe {
            libsqlite3_sys::sqlite3_busy_timeout(self.database.as_ptr(), self.restore_milliseconds);
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
struct BackupTestControl {
    interrupt_at_step: Option<usize>,
    observed_steps: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
static BACKUP_TEST_CONTROLS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<usize, BackupTestControl>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

// SAFETY: the backup handle is exclusively owned and both SQLite connections
// remain mutably borrowed until it is finished.
unsafe impl Send for LiveBackupPointer {}

impl LiveBackupPointer {
    fn as_ptr(&self) -> *mut libsqlite3_sys::sqlite3_backup {
        self.0.expect("live SQLite backup pointer").as_ptr()
    }

    fn finish(mut self) -> std::ffi::c_int {
        let pointer = self.0.take().expect("live SQLite backup pointer");
        // SAFETY: this consumes the unique live backup handle.
        unsafe { libsqlite3_sys::sqlite3_backup_finish(pointer.as_ptr()) }
    }
}

impl Drop for LiveBackupPointer {
    fn drop(&mut self) {
        if let Some(pointer) = self.0.take() {
            // SAFETY: cancellation still owns the unique backup handle.
            unsafe {
                libsqlite3_sys::sqlite3_backup_finish(pointer.as_ptr());
            }
        }
    }
}

// SAFETY: SQLite permits sqlite3_interrupt() from another thread, and every
// registration is cleared before the owning connection can be closed.
unsafe impl Send for LiveInterruptPointer {}
// SAFETY: sqlite3_interrupt() is concurrency-safe.
unsafe impl Sync for LiveInterruptPointer {}

impl LiveInterruptPointer {
    fn as_ptr(&self) -> *mut libsqlite3_sys::sqlite3 {
        self.0.as_ptr()
    }
}

struct LiveInterruptRegistration {
    slot: Arc<std::sync::Mutex<Option<LiveInterruptPointer>>>,
}

struct SqliteAllocation(*mut u8);

impl SqliteAllocation {
    fn into_raw(mut self) -> *mut u8 {
        let pointer = self.0;
        self.0 = std::ptr::null_mut();
        pointer
    }
}

impl Drop for SqliteAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this pointer is owned by Rust until `into_raw`.
            unsafe {
                libsqlite3_sys::sqlite3_free(self.0.cast());
            }
        }
    }
}

impl LiveInterruptRegistration {
    fn publish(
        slot: Arc<std::sync::Mutex<Option<LiveInterruptPointer>>>,
        pointer: LiveInterruptPointer,
    ) -> Self {
        *slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(pointer);
        Self { slot }
    }
}

impl Drop for LiveInterruptRegistration {
    fn drop(&mut self) {
        *self
            .slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

type BlockingCleanupJob = Box<dyn FnOnce(&tokio::runtime::Runtime) + Send + 'static>;

const MAX_CLEANUP_JOBS: usize = 64;
const CLEANUP_THREADS: usize = 16;
const TERMINAL_CLOSE_SLOTS_PER_OWNER: usize = 2;
const MAX_TERMINAL_CLOSE_JOBS: usize = MAX_CLEANUP_JOBS * TERMINAL_CLOSE_SLOTS_PER_OWNER;
const TERMINAL_CLOSE_THREADS: usize = 4;
const TERMINAL_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(25);
static ACTIVE_CLEANUP_JOBS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_TERMINAL_CLOSE_JOBS: AtomicUsize = AtomicUsize::new(0);

struct CleanupReservation;

impl Drop for CleanupReservation {
    fn drop(&mut self) {
        ACTIVE_CLEANUP_JOBS.fetch_sub(1, Ordering::AcqRel);
    }
}

struct CleanupEnvelope {
    job: BlockingCleanupJob,
    _reservation: CleanupReservation,
}

struct CleanupExecutor {
    sender: std::sync::mpsc::SyncSender<CleanupEnvelope>,
}

type TerminalCloseJob = Box<dyn FnOnce(&tokio::runtime::Runtime) -> bool + Send + 'static>;

struct TerminalCloseReservation;

impl Drop for TerminalCloseReservation {
    fn drop(&mut self) {
        ACTIVE_TERMINAL_CLOSE_JOBS.fetch_sub(1, Ordering::AcqRel);
    }
}

struct TerminalCloseEnvelope {
    job: TerminalCloseJob,
    _reservation: TerminalCloseReservation,
}

struct TerminalCloseExecutor {
    sender: std::sync::mpsc::SyncSender<TerminalCloseEnvelope>,
}

static CLEANUP_EXECUTOR: std::sync::LazyLock<Result<CleanupExecutor, String>> =
    std::sync::LazyLock::new(|| {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<CleanupEnvelope>(MAX_CLEANUP_JOBS);
        let receiver = Arc::new(std::sync::Mutex::new(receiver));
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(CLEANUP_THREADS);
        for index in 0..CLEANUP_THREADS {
            let receiver = Arc::clone(&receiver);
            let ready_tx = ready_tx.clone();
            std::thread::Builder::new()
                .name(format!("claw-sqlite-cleanup-{index}"))
                .spawn(move || {
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => {
                            let _ = ready_tx.send(Ok(()));
                            runtime
                        }
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.to_string()));
                            return;
                        }
                    };
                    loop {
                        let envelope = receiver
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv();
                        let Ok(envelope) = envelope else {
                            return;
                        };
                        let CleanupEnvelope { job, _reservation } = envelope;
                        job(&runtime);
                        drop(_reservation);
                    }
                })
                .map_err(|error| error.to_string())?;
        }
        drop(ready_tx);
        for _ in 0..CLEANUP_THREADS {
            ready_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|error| {
                    format!("cleanup executor readiness acknowledgement: {error}")
                })??;
        }
        Ok(CleanupExecutor { sender })
    });

static TERMINAL_CLOSE_EXECUTOR: std::sync::LazyLock<Result<TerminalCloseExecutor, String>> =
    std::sync::LazyLock::new(|| {
        let (sender, receiver) =
            std::sync::mpsc::sync_channel::<TerminalCloseEnvelope>(MAX_TERMINAL_CLOSE_JOBS);
        let receiver = Arc::new(std::sync::Mutex::new(receiver));
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(TERMINAL_CLOSE_THREADS);
        for index in 0..TERMINAL_CLOSE_THREADS {
            let receiver = Arc::clone(&receiver);
            let ready_tx = ready_tx.clone();
            std::thread::Builder::new()
                .name(format!("claw-sqlite-terminal-close-{index}"))
                .spawn(move || {
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => {
                            let _ = ready_tx.send(Ok(()));
                            runtime
                        }
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.to_string()));
                            return;
                        }
                    };
                    loop {
                        let envelope = receiver
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv();
                        let Ok(envelope) = envelope else {
                            return;
                        };
                        let TerminalCloseEnvelope { job, _reservation } = envelope;
                        if job(&runtime) {
                            std::mem::forget(_reservation);
                        } else {
                            drop(_reservation);
                        }
                    }
                })
                .map_err(|error| error.to_string())?;
        }
        drop(ready_tx);
        for _ in 0..TERMINAL_CLOSE_THREADS {
            ready_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|error| {
                    format!("terminal close executor readiness acknowledgement: {error}")
                })??;
        }
        Ok(TerminalCloseExecutor { sender })
    });

/// Result of transferring a physical SQLite close to the bounded close executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalCloseOutcome {
    /// SQLx and the SQLite VFS completed the close.
    Closed,
    /// The close completed with an observable error.
    Failed(String),
    /// The fixed cutoff elapsed; the bounded quarantine still owns the close.
    Quarantined,
}

struct TerminalCloseReceipt {
    result: std::sync::mpsc::Receiver<Result<(), String>>,
}

impl TerminalCloseReceipt {
    fn wait(self, cutoff: std::time::Instant) -> TerminalCloseOutcome {
        let remaining = cutoff.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return TerminalCloseOutcome::Quarantined;
        }
        match self.result.recv_timeout(remaining) {
            Ok(Ok(())) => TerminalCloseOutcome::Closed,
            Ok(Err(error)) => TerminalCloseOutcome::Failed(error),
            Err(
                std::sync::mpsc::RecvTimeoutError::Timeout
                | std::sync::mpsc::RecvTimeoutError::Disconnected,
            ) => TerminalCloseOutcome::Quarantined,
        }
    }
}

/// Pre-reserved capacity for physical closes that cannot occupy cleanup workers.
pub struct TerminalCloseBatch {
    reservations: Vec<TerminalCloseReservation>,
}

impl TerminalCloseBatch {
    fn submit_full<Connection: BeginOwnedConnection>(
        &mut self,
        connection: Connection,
        authorizer_address: usize,
        retention: Option<Arc<dyn Send + Sync>>,
    ) -> TerminalCloseReceipt {
        let reservation = self
            .reservations
            .pop()
            .expect("terminal close capacity was reserved before resource acquisition");
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let executor = TERMINAL_CLOSE_EXECUTOR
            .as_ref()
            .unwrap_or_else(|error| panic!("terminal close executor unavailable: {error}"));
        if executor
            .sender
            .try_send(TerminalCloseEnvelope {
                job: Box::new(move |runtime| {
                    let result = connection.close_on_runtime(runtime);
                    if result.is_ok() && authorizer_address != 0 {
                        // SAFETY: terminal connection ownership keeps SQLite's
                        // pApp live until the close future has completed.
                        unsafe {
                            drop(Box::from_raw(
                                authorizer_address as *mut TransactionAuthorizerContext,
                            ));
                        }
                    }
                    let retain = result.is_err();
                    if retain {
                        std::mem::forget(retention);
                    } else {
                        drop(retention);
                    }
                    let _ = result_tx.send(result);
                    retain
                }),
                _reservation: reservation,
            })
            .is_err()
        {
            std::process::abort();
        }
        TerminalCloseReceipt { result: result_rx }
    }

    fn submit_with_authorizer<Connection: BeginOwnedConnection>(
        &mut self,
        connection: Connection,
        authorizer_address: usize,
    ) -> TerminalCloseReceipt {
        self.submit_full(connection, authorizer_address, None)
    }

    fn submit<Connection: BeginOwnedConnection>(
        &mut self,
        connection: Connection,
    ) -> TerminalCloseReceipt {
        self.submit_with_authorizer(connection, 0)
    }

    fn submit_retaining<Connection, Retention>(
        &mut self,
        connection: Connection,
        retention: Arc<std::sync::Mutex<Option<Retention>>>,
    ) -> TerminalCloseReceipt
    where
        Connection: BeginOwnedConnection,
        Retention: Send + 'static,
    {
        let retention: Arc<dyn Send + Sync> = retention;
        self.submit_full(connection, 0, Some(retention))
    }

    /// Keeps a shared reservation alive until the physical close completes.
    pub fn close_with_shared_retention<Connection, Retention>(
        &mut self,
        connection: Connection,
        retention: Arc<std::sync::Mutex<Option<Retention>>>,
    ) -> TerminalCloseOutcome
    where
        Connection: BeginOwnedConnection,
        Retention: Send + 'static,
    {
        let receipt = self.submit_retaining(connection, retention);
        receipt.wait(std::time::Instant::now() + TERMINAL_CLOSE_TIMEOUT)
    }

    /// Submits one physical close and waits only until the fixed close cutoff.
    pub fn close<Connection: BeginOwnedConnection>(
        &mut self,
        connection: Connection,
    ) -> TerminalCloseOutcome {
        self.submit(connection)
            .wait(std::time::Instant::now() + TERMINAL_CLOSE_TIMEOUT)
    }

    /// Retains caller-supplied capacity only when physical close is quarantined.
    pub fn close_with_quarantine_retention<Connection, Retention>(
        &mut self,
        connection: Connection,
        retention: Retention,
    ) -> TerminalCloseOutcome
    where
        Connection: BeginOwnedConnection,
        Retention: FnOnce() -> Option<Box<dyn Send>>,
    {
        let shared = Arc::new(std::sync::Mutex::new(None));
        let receipt = self.submit_retaining(connection, Arc::clone(&shared));
        let outcome = receipt.wait(std::time::Instant::now() + TERMINAL_CLOSE_TIMEOUT);
        if outcome != TerminalCloseOutcome::Closed {
            *shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = retention();
        }
        drop(shared);
        outcome
    }

    fn close_with_authorizer<Connection: BeginOwnedConnection>(
        &mut self,
        connection: Connection,
        authorizer_address: usize,
    ) -> TerminalCloseOutcome {
        self.submit_with_authorizer(connection, authorizer_address)
            .wait(std::time::Instant::now() + TERMINAL_CLOSE_TIMEOUT)
    }
}

/// Pre-acquired dedicated owner for cancellation-safe blocking cleanup.
pub struct BlockingCleanupOwner {
    reservation: Option<CleanupReservation>,
    terminal_closes: Option<TerminalCloseBatch>,
}

impl BlockingCleanupOwner {
    fn validate_executor(thread_name: &str) -> Result<&'static CleanupExecutor, String> {
        if thread_name.contains('\0') {
            return Err("blocking cleanup owner name contains a NUL byte".to_owned());
        }
        let executor = CLEANUP_EXECUTOR.as_ref().map_err(Clone::clone)?;
        let _ = TERMINAL_CLOSE_EXECUTOR.as_ref().map_err(Clone::clone)?;
        Ok(executor)
    }

    /// Acquires and readies a dedicated cleanup runtime without blocking Tokio.
    pub async fn acquire(thread_name: &str) -> Result<Self, String> {
        let mut owners = Self::acquire_many_until(thread_name, 1, None).await?;
        Ok(owners.pop().expect("one cleanup owner was reserved"))
    }

    /// Atomically reserves a complete owner set before an operation acquires resources.
    pub async fn acquire_set(
        thread_name: &str,
        count: usize,
        deadline: std::time::Instant,
    ) -> Result<Vec<Self>, String> {
        Self::acquire_many_until(thread_name, count, Some(deadline)).await
    }

    async fn acquire_many_until(
        thread_name: &str,
        count: usize,
        deadline: Option<std::time::Instant>,
    ) -> Result<Vec<Self>, String> {
        let _ = Self::validate_executor(thread_name)?;
        if count == 0 || count > MAX_CLEANUP_JOBS {
            return Err("blocking cleanup owner count is out of range".to_owned());
        }
        loop {
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return Err("blocking cleanup owner admission timed out".to_owned());
            }
            let terminal_count = count
                .checked_mul(TERMINAL_CLOSE_SLOTS_PER_OWNER)
                .ok_or_else(|| "terminal close owner count overflowed".to_owned())?;
            let active = ACTIVE_CLEANUP_JOBS.load(Ordering::Acquire);
            let active_terminal = ACTIVE_TERMINAL_CLOSE_JOBS.load(Ordering::Acquire);
            if active <= MAX_CLEANUP_JOBS - count
                && active_terminal <= MAX_TERMINAL_CLOSE_JOBS - terminal_count
                && ACTIVE_CLEANUP_JOBS
                    .compare_exchange_weak(
                        active,
                        active + count,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            {
                if ACTIVE_TERMINAL_CLOSE_JOBS
                    .compare_exchange(
                        active_terminal,
                        active_terminal + terminal_count,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    ACTIVE_CLEANUP_JOBS.fetch_sub(count, Ordering::AcqRel);
                    tokio::task::yield_now().await;
                    continue;
                }
                let mut owners = Vec::new();
                if let Err(error) = owners.try_reserve_exact(count) {
                    ACTIVE_CLEANUP_JOBS.fetch_sub(count, Ordering::AcqRel);
                    ACTIVE_TERMINAL_CLOSE_JOBS.fetch_sub(terminal_count, Ordering::AcqRel);
                    return Err(format!("reserve cleanup owner set: {error}"));
                }
                for _ in 0..count {
                    owners.push(Self {
                        reservation: Some(CleanupReservation),
                        terminal_closes: Some(TerminalCloseBatch {
                            reservations: (0..TERMINAL_CLOSE_SLOTS_PER_OWNER)
                                .map(|_| TerminalCloseReservation)
                                .collect(),
                        }),
                    });
                }
                return Ok(owners);
            }
            tokio::task::yield_now().await;
        }
    }

    #[cfg(test)]
    fn acquire_without_runtime(thread_name: &str) -> Result<Self, String> {
        let _ = Self::validate_executor(thread_name)?;
        let active = ACTIVE_CLEANUP_JOBS.fetch_add(1, Ordering::AcqRel);
        if active >= MAX_CLEANUP_JOBS {
            ACTIVE_CLEANUP_JOBS.fetch_sub(1, Ordering::AcqRel);
            return Err("blocking cleanup owner capacity is exhausted".to_owned());
        }
        let terminal_active =
            ACTIVE_TERMINAL_CLOSE_JOBS.fetch_add(TERMINAL_CLOSE_SLOTS_PER_OWNER, Ordering::AcqRel);
        if terminal_active > MAX_TERMINAL_CLOSE_JOBS - TERMINAL_CLOSE_SLOTS_PER_OWNER {
            ACTIVE_TERMINAL_CLOSE_JOBS.fetch_sub(TERMINAL_CLOSE_SLOTS_PER_OWNER, Ordering::AcqRel);
            ACTIVE_CLEANUP_JOBS.fetch_sub(1, Ordering::AcqRel);
            return Err("terminal close owner capacity is exhausted".to_owned());
        }
        Ok(Self {
            reservation: Some(CleanupReservation),
            terminal_closes: Some(TerminalCloseBatch {
                reservations: (0..TERMINAL_CLOSE_SLOTS_PER_OWNER)
                    .map(|_| TerminalCloseReservation)
                    .collect(),
            }),
        })
    }

    /// Transfers terminal cleanup to the dedicated runtime.
    pub fn handoff<Cleanup>(&mut self, cleanup: Cleanup)
    where
        Cleanup: FnOnce(&tokio::runtime::Runtime, TerminalCloseBatch) + Send + 'static,
    {
        let reservation = self
            .reservation
            .take()
            .expect("blocking cleanup handoff is single-use");
        let terminal_closes = self
            .terminal_closes
            .take()
            .expect("terminal close handoff is single-use");
        let executor = CLEANUP_EXECUTOR
            .as_ref()
            .unwrap_or_else(|error| panic!("cleanup executor unavailable: {error}"));
        if executor
            .sender
            .try_send(CleanupEnvelope {
                job: Box::new(move |runtime| cleanup(runtime, terminal_closes)),
                _reservation: reservation,
            })
            .is_err()
        {
            // The owner acknowledges readiness before any SQLite worker starts,
            // so losing it would leave live native state without an owner.
            std::process::abort();
        }
    }

    /// Shuts down an unused cleanup owner without waiting on a runtime thread.
    pub fn shutdown(mut self) -> Result<(), String> {
        self.reservation
            .take()
            .ok_or_else(|| "blocking cleanup owner is missing".to_owned())?;
        self.terminal_closes
            .take()
            .ok_or_else(|| "terminal close owner is missing".to_owned())?;
        Ok(())
    }
}

impl Drop for BlockingCleanupOwner {
    fn drop(&mut self) {
        self.reservation.take();
        self.terminal_closes.take();
    }
}

/// Returns whether a Unix file has the expected owner/mode and no effective
/// platform ACL beyond those mode bits.
#[cfg(unix)]
pub fn unix_file_is_service_private(
    file: &std::fs::File,
    expected_uid: u32,
    expected_mode: u32,
) -> Result<bool, FileControlError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    if metadata.uid() != expected_uid || metadata.mode() & 0o7777 != expected_mode {
        return Ok(false);
    }
    unix_file_has_trivial_acl(file)
}

/// Returns whether platform ACLs grant no authority beyond Unix mode bits.
#[cfg(unix)]
pub fn unix_file_has_trivial_acl(file: &std::fs::File) -> Result<bool, FileControlError> {
    #[cfg(target_vendor = "apple")]
    {
        apple_file_acl_is_trivial(file)
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use xattr::FileExt as _;

        let acl_names = [
            "system.posix_acl_access",
            "system.posix_acl_default",
            "system.nfs4_acl",
        ];
        let names = file
            .list_xattr()
            .map_err(|error| FileControlError::Handle(error.to_string()))?;
        for name in names {
            if acl_names.iter().any(|acl| name == *acl) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    #[cfg(all(
        not(target_vendor = "apple"),
        not(any(target_os = "linux", target_os = "android"))
    ))]
    {
        let _ = file;
        Ok(false)
    }
}

#[cfg(target_vendor = "apple")]
fn apple_file_acl_is_trivial(file: &std::fs::File) -> Result<bool, FileControlError> {
    use std::ffi::{c_int, c_void};
    use std::os::fd::AsRawFd as _;

    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: c_int = 0;
    unsafe extern "C" {
        fn __error() -> *mut c_int;
        fn acl_get_fd_np(file_descriptor: c_int, acl_type: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    // SAFETY: Darwin exposes the calling thread's errno slot through __error.
    unsafe {
        *__error() = 0;
    }
    // SAFETY: The file descriptor is live and ACL_TYPE_EXTENDED is the Darwin
    // extended-ACL selector. errno was cleared so NULL cannot inherit stale state.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        if std::io::Error::last_os_error().raw_os_error() == Some(2) {
            return Ok(true);
        }
        return Err(FileControlError::Handle(format!(
            "read Apple file ACL: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: `acl` is live and `entry` points to writable storage.
    let entry_status = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) };
    let entry_error = std::io::Error::last_os_error();
    // SAFETY: acl_get_fd_np returned this owned ACL allocation.
    let freed = unsafe { acl_free(acl) };
    if freed != 0 {
        return Err(FileControlError::Handle(format!(
            "free Apple file ACL: {}",
            std::io::Error::last_os_error()
        )));
    }
    match entry_status {
        0 => Ok(false),
        -1 if entry_error.raw_os_error() == Some(22) => Ok(true),
        _ => Err(FileControlError::Handle(format!(
            "inspect Apple file ACL entries: {}",
            entry_error
        ))),
    }
}

/// Returns whether SQLite reports that its open main database was moved or replaced.
#[cfg(unix)]
pub async fn main_database_has_moved(
    connection: &mut sqlx::SqliteConnection,
) -> Result<bool, FileControlError> {
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let mut moved = 0_i32;
    // SAFETY: SQLx's locked handle guarantees a live SQLite connection for this
    // call. The schema name is NUL-terminated and `moved` remains valid.
    let result = unsafe {
        libsqlite3_sys::sqlite3_file_control(
            database.as_raw_handle().as_ptr(),
            c"main".as_ptr(),
            libsqlite3_sys::SQLITE_FCNTL_HAS_MOVED,
            (&raw mut moved).cast(),
        )
    };
    if result == libsqlite3_sys::SQLITE_OK {
        Ok(moved != 0)
    } else {
        Err(FileControlError::SQLite(result))
    }
}

/// Replaces a connection's main schema with an immutable SQLite-owned copy of
/// authenticated database bytes.
pub async fn deserialize_readonly(
    connection: &mut sqlx::SqliteConnection,
    bytes: &[u8],
) -> Result<(), FileControlError> {
    if bytes.is_empty() {
        return Err(FileControlError::Handle(
            "serialized database must not be empty".to_owned(),
        ));
    }
    let size = i64::try_from(bytes.len())
        .map_err(|_| FileControlError::Handle("serialized database is too large".to_owned()))?;
    let mut handle = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    // SAFETY: sqlite3_malloc64 returns SQLite-owned suitably aligned storage.
    let allocation = SqliteAllocation(
        unsafe {
            libsqlite3_sys::sqlite3_malloc64(
                u64::try_from(bytes.len())
                    .map_err(|_| FileControlError::Handle("database size overflow".to_owned()))?,
            )
        }
        .cast::<u8>(),
    );
    if allocation.0.is_null() {
        return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_NOMEM));
    }
    // SAFETY: allocation has exactly bytes.len() writable bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), allocation.0, bytes.len());
    }
    let allocation = allocation.into_raw();
    // SAFETY: the locked SQLite handle is live; on success SQLite owns allocation.
    let result = unsafe {
        libsqlite3_sys::sqlite3_deserialize(
            handle.as_raw_handle().as_ptr(),
            c"main".as_ptr(),
            allocation,
            size,
            size,
            libsqlite3_sys::SQLITE_DESERIALIZE_FREEONCLOSE
                | libsqlite3_sys::SQLITE_DESERIALIZE_READONLY,
        )
    };
    if result != libsqlite3_sys::SQLITE_OK {
        return Err(FileControlError::SQLite(result));
    }
    Ok(())
}

/// Absolute deadline, cancellation, size, and handler restoration for logical backup.
pub struct BackupExecutionContext {
    /// Absolute operation deadline.
    pub deadline: std::time::Instant,
    /// Shared operation cancellation state.
    pub cancelled: Arc<std::sync::atomic::AtomicBool>,
    /// Maximum permitted SQLite page count.
    pub max_pages: std::ffi::c_int,
    /// Busy timeout restored on the source connection.
    pub source_busy_timeout: std::time::Duration,
    /// Busy timeout restored on the destination connection.
    pub destination_busy_timeout: std::time::Duration,
}

async fn backup_main_database(
    source: &mut sqlx::SqliteConnection,
    destination: &mut sqlx::SqliteConnection,
    context: &BackupExecutionContext,
) -> Result<(), FileControlError> {
    let mut source_handle = source
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let mut destination_handle = destination
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let busy_state = BackupBusyState {
        deadline: context.deadline,
        cancelled: Arc::clone(&context.cancelled),
    };
    let source_database = LiveInterruptPointer(source_handle.as_raw_handle());
    let destination_database = LiveInterruptPointer(destination_handle.as_raw_handle());
    let source_restore_milliseconds =
        i32::try_from(context.source_busy_timeout.as_millis()).unwrap_or(i32::MAX);
    let destination_restore_milliseconds =
        i32::try_from(context.destination_busy_timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: `busy_state` and both exclusive connection borrows outlive the registrations.
    let source_busy = unsafe {
        libsqlite3_sys::sqlite3_busy_handler(
            source_database.as_ptr(),
            Some(backup_busy_handler),
            std::ptr::from_ref(&busy_state).cast_mut().cast(),
        )
    };
    if source_busy != libsqlite3_sys::SQLITE_OK {
        return Err(FileControlError::SQLite(source_busy));
    }
    let _source_busy_registration = BackupBusyRegistration {
        database: source_database,
        restore_milliseconds: source_restore_milliseconds,
    };
    // SAFETY: same lifetime argument as the source registration.
    let destination_busy = unsafe {
        libsqlite3_sys::sqlite3_busy_handler(
            destination_database.as_ptr(),
            Some(backup_busy_handler),
            std::ptr::from_ref(&busy_state).cast_mut().cast(),
        )
    };
    if destination_busy != libsqlite3_sys::SQLITE_OK {
        return Err(FileControlError::SQLite(destination_busy));
    }
    let _destination_busy_registration = BackupBusyRegistration {
        database: destination_database,
        restore_milliseconds: destination_restore_milliseconds,
    };
    // SAFETY: both SQLx handles are exclusively locked for the backup lifetime.
    let backup = LiveBackupPointer(NonNull::new(unsafe {
        libsqlite3_sys::sqlite3_backup_init(
            destination_handle.as_raw_handle().as_ptr(),
            c"main".as_ptr(),
            source_handle.as_raw_handle().as_ptr(),
            c"main".as_ptr(),
        )
    }));
    if backup.0.is_none() {
        // SAFETY: destination handle is live.
        let destination_code =
            unsafe { libsqlite3_sys::sqlite3_errcode(destination_handle.as_raw_handle().as_ptr()) };
        let source_code =
            unsafe { libsqlite3_sys::sqlite3_errcode(source_handle.as_raw_handle().as_ptr()) };
        return Err(FileControlError::Handle(format!(
            "initialize SQLite backup: destination code {destination_code}, source code {source_code}"
        )));
    }
    #[cfg(test)]
    let test_control = BACKUP_TEST_CONTROLS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(source_handle.as_raw_handle().as_ptr() as usize))
        .cloned();

    drop((source_handle, destination_handle));
    let step = loop {
        #[cfg(test)]
        if let Some(control) = &test_control {
            let step = control.observed_steps.fetch_add(1, Ordering::AcqRel);
            if control.interrupt_at_step == Some(step) {
                break libsqlite3_sys::SQLITE_INTERRUPT;
            }
        }
        if context.cancelled.load(std::sync::atomic::Ordering::Acquire)
            || std::time::Instant::now() >= context.deadline
        {
            break libsqlite3_sys::SQLITE_INTERRUPT;
        }
        // SAFETY: backup is live until sqlite3_backup_finish below.
        let step = unsafe { libsqlite3_sys::sqlite3_backup_step(backup.as_ptr(), 128) };
        // SAFETY: backup remains live during the bounded step loop.
        if unsafe { libsqlite3_sys::sqlite3_backup_pagecount(backup.as_ptr()) } > context.max_pages
        {
            break libsqlite3_sys::SQLITE_TOOBIG;
        }
        if context.cancelled.load(Ordering::Acquire)
            || std::time::Instant::now() >= context.deadline
        {
            break libsqlite3_sys::SQLITE_INTERRUPT;
        }
        match step {
            libsqlite3_sys::SQLITE_OK
            | libsqlite3_sys::SQLITE_BUSY
            | libsqlite3_sys::SQLITE_LOCKED => tokio::task::yield_now().await,
            _ => break step,
        }
    };
    // SAFETY: finish consumes the live backup handle exactly once.
    let finish = backup.finish();
    if step != libsqlite3_sys::SQLITE_DONE {
        Err(FileControlError::SQLite(step))
    } else if finish != libsqlite3_sys::SQLITE_OK {
        Err(FileControlError::SQLite(finish))
    } else {
        Ok(())
    }
}

/// Runs a logical SQLite backup on the bounded native executor while retaining
/// exclusive ownership of both connections through terminal result delivery.
pub async fn backup_owned_main_database<Source, Destination, Reservation>(
    mut worker_owner: BlockingCleanupOwner,
    mut source: Source,
    mut destination: Destination,
    reservation: Reservation,
    context: BackupExecutionContext,
) -> Result<(Source, Destination, Reservation), FileControlError>
where
    Source: BeginOwnedConnection,
    Destination: BeginOwnedConnection,
    Reservation: Send + 'static,
{
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let deadline = context.deadline;
    worker_owner.handoff(move |runtime, mut terminal_closes| {
        let result = runtime.block_on(backup_main_database(
            source.sqlite(),
            destination.sqlite(),
            &context,
        ));
        match result {
            Ok(()) => {
                if let Err(error) = result_tx.send(Ok((source, destination, reservation)))
                    && let Ok((source, destination, reservation)) = error.0
                {
                    let retention = Arc::new(std::sync::Mutex::new(Some(reservation)));
                    let source_close =
                        terminal_closes.submit_retaining(source, Arc::clone(&retention));
                    let destination_close =
                        terminal_closes.submit_retaining(destination, Arc::clone(&retention));
                    drop(retention);
                    let cutoff = std::time::Instant::now() + TERMINAL_CLOSE_TIMEOUT;
                    let _ = source_close.wait(cutoff);
                    let _ = destination_close.wait(cutoff);
                }
            }
            Err(error) => {
                let retention = Arc::new(std::sync::Mutex::new(Some(reservation)));
                let source_close = terminal_closes.submit_retaining(source, Arc::clone(&retention));
                let destination_close =
                    terminal_closes.submit_retaining(destination, Arc::clone(&retention));
                drop(retention);
                let cutoff = std::time::Instant::now() + TERMINAL_CLOSE_TIMEOUT;
                let source_outcome = source_close.wait(cutoff);
                let destination_outcome = destination_close.wait(cutoff);
                let error = if source_outcome == TerminalCloseOutcome::Closed
                    && destination_outcome == TerminalCloseOutcome::Closed
                {
                    error
                } else {
                    FileControlError::Handle(format!(
                        "{error}; terminal backup closes: source={source_outcome:?}, destination={destination_outcome:?}"
                    ))
                };
                let _ = result_tx.send(Err(error));
            }
        }
    });
    let cleanup_cutoff = deadline + std::time::Duration::from_secs(5);
    loop {
        match result_rx.try_recv() {
            Ok(result) => return result,
            Err(std::sync::mpsc::TryRecvError::Empty)
                if std::time::Instant::now() < cleanup_cutoff =>
            {
                tokio::task::yield_now().await;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                return Err(FileControlError::Handle(
                    "logical backup cleanup exceeded its fixed cutoff".to_owned(),
                ));
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err(FileControlError::Handle(
                    "logical backup owner stopped without a result".to_owned(),
                ));
            }
        }
    }
}

/// Copies SQLite's current main database image from its internal contiguous
/// backing into one fallibly allocated bounded byte vector.
pub async fn serialize_main_database(
    connection: &mut sqlx::SqliteConnection,
    maximum_bytes: usize,
) -> Result<Vec<u8>, FileControlError> {
    let mut handle = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let mut size = 0_i64;
    // SAFETY: the handle is exclusively locked and NOCOPY retains SQLite ownership.
    let mut pointer = unsafe {
        libsqlite3_sys::sqlite3_serialize(
            handle.as_raw_handle().as_ptr(),
            c"main".as_ptr(),
            &raw mut size,
            libsqlite3_sys::SQLITE_SERIALIZE_NOCOPY,
        )
    };
    let probe_size = usize::try_from(size)
        .map_err(|_| FileControlError::Handle("serialized database size is invalid".to_owned()))?;
    if probe_size > maximum_bytes {
        return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_TOOBIG));
    }
    let mut sqlite_owned = None;
    if pointer.is_null() {
        // SAFETY: fallback asks SQLite for one owned contiguous serialization.
        pointer = unsafe {
            libsqlite3_sys::sqlite3_serialize(
                handle.as_raw_handle().as_ptr(),
                c"main".as_ptr(),
                &raw mut size,
                0,
            )
        };
        sqlite_owned = Some(SqliteAllocation(pointer));
    }
    let size = usize::try_from(size)
        .map_err(|_| FileControlError::Handle("serialized database size is invalid".to_owned()))?;
    if pointer.is_null() || size == 0 {
        return Err(FileControlError::Handle(
            "SQLite main database is not contiguously serializable".to_owned(),
        ));
    }
    if size > maximum_bytes {
        return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_TOOBIG));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|error| {
        FileControlError::Handle(format!("serialize allocation failed: {error}"))
    })?;
    // SAFETY: SQLite retains at least `size` immutable bytes while the handle is locked.
    bytes.extend_from_slice(unsafe { std::slice::from_raw_parts(pointer, size) });
    drop(sqlite_owned);
    Ok(bytes)
}

/// Cleanup capability retained through snapshot finalization and result delivery.
pub trait SnapshotCleanupLease: Send + 'static {
    /// Reclaims an unpublished snapshot or leaves it quarantined on failure.
    fn cleanup(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>;

    /// Transfers memory/admission reservations to a terminal close quarantine.
    fn take_terminal_retention(&mut self) -> Option<Box<dyn Send>>;

    /// Transfers cleanup ownership without waiting for completion.
    fn detach_cleanup(&mut self);
}

/// Verified result of writing one serialized logical snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotWriteReceipt {
    /// Exact number of bytes written and verified through the held handle.
    pub byte_count: u64,
    /// SHA-256 digest of the exact serialized bytes.
    pub digest: [u8; 32],
}

/// Deadline, cancellation, path diagnostics, and size cap for snapshot finalization.
pub struct SnapshotFinalizeContext {
    /// Diagnostic path for held-handle I/O failures.
    pub output_path: String,
    /// Absolute operation deadline.
    pub deadline: std::time::Instant,
    /// Shared operation cancellation state.
    pub cancelled: Arc<std::sync::atomic::AtomicBool>,
    /// Maximum serialized byte count.
    pub maximum_bytes: usize,
}

/// Serializes an owned in-memory SQLite image, closes SQLite, and writes only
/// through the supplied precreated held file on the bounded native executor.
pub async fn finalize_owned_snapshot<Cleanup>(
    mut worker_owner: BlockingCleanupOwner,
    mut connection: sqlx::SqliteConnection,
    mut output: std::fs::File,
    mut cleanup: Cleanup,
    context: SnapshotFinalizeContext,
) -> Result<(SnapshotWriteReceipt, Cleanup), FileControlError>
where
    Cleanup: SnapshotCleanupLease,
{
    let SnapshotFinalizeContext {
        output_path,
        deadline,
        cancelled,
        maximum_bytes,
    } = context;
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(0);
    let delivery_cancelled = Arc::clone(&cancelled);
    worker_owner.handoff(move |runtime, mut terminal_closes| {
        let operation = (|| {
            if cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
                return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
            }
            let serialization = runtime.block_on(async {
                sqlx::query("PRAGMA journal_mode = DELETE")
                    .execute(&mut connection)
                    .await
                    .map_err(|error| FileControlError::Handle(error.to_string()))?;
                serialize_main_database(&mut connection, maximum_bytes).await
            });
            let mut bytes = match serialization {
                Ok(bytes) => bytes,
                Err(error) => {
                    let close = terminal_closes.close_with_quarantine_retention(connection, || {
                        cleanup.take_terminal_retention()
                    });
                    return Err(if close == TerminalCloseOutcome::Closed {
                        error
                    } else {
                        FileControlError::Handle(format!(
                            "{error}; terminal snapshot close: {close:?}"
                        ))
                    });
                }
            };
            if bytes.len() > 19 {
                bytes[18] = 1;
                bytes[19] = 1;
            }
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            match terminal_closes
                .close_with_quarantine_retention(connection, || cleanup.take_terminal_retention())
            {
                TerminalCloseOutcome::Closed => {}
                close => {
                    return Err(FileControlError::Handle(format!(
                        "terminal snapshot close did not complete: {close:?}"
                    )));
                }
            }
            if cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
                return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
            }
            use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
            output
                .seek(SeekFrom::Start(0))
                .and_then(|_| output.set_len(0))
                .map_err(|error| {
                    FileControlError::Handle(format!(
                        "prepare held snapshot output {output_path}: {error}"
                    ))
                })?;
            for chunk in bytes.chunks(64 * 1024) {
                if cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
                    return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
                }
                output.write_all(chunk).map_err(|error| {
                    FileControlError::Handle(format!(
                        "write held snapshot output {output_path}: {error}"
                    ))
                })?;
            }
            output.sync_all().map_err(|error| {
                FileControlError::Handle(format!(
                    "sync held snapshot output {output_path}: {error}"
                ))
            })?;
            if cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
                return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
            }
            output.seek(SeekFrom::Start(0)).map_err(|error| {
                FileControlError::Handle(format!(
                    "rewind held snapshot output {output_path}: {error}"
                ))
            })?;
            let mut verified_digest = Sha256::new();
            let mut verified_bytes = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                if cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
                    return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
                }
                let read = output.read(&mut buffer).map_err(|error| {
                    FileControlError::Handle(format!(
                        "verify held snapshot output {output_path}: {error}"
                    ))
                })?;
                if read == 0 {
                    break;
                }
                verified_digest.update(&buffer[..read]);
                verified_bytes = verified_bytes
                    .checked_add(u64::try_from(read).expect("buffer length fits u64"))
                    .ok_or_else(|| {
                        FileControlError::Handle(
                            "held snapshot byte-count verification overflowed".to_owned(),
                        )
                    })?;
            }
            let verified_digest: [u8; 32] = verified_digest.finalize().into();
            let expected_bytes = u64::try_from(bytes.len()).map_err(|_| {
                FileControlError::Handle("serialized snapshot size does not fit u64".to_owned())
            })?;
            if verified_bytes != expected_bytes || verified_digest != digest {
                return Err(FileControlError::Handle(
                    "held snapshot output failed exact size/digest verification".to_owned(),
                ));
            }
            Ok(SnapshotWriteReceipt {
                byte_count: verified_bytes,
                digest,
            })
        })();
        drop(output);
        let delivered = match operation {
            Ok(receipt) => result_tx.send(Ok((receipt, cleanup))),
            Err(primary) => result_tx.send(Err((primary, cleanup))),
        };
        if let Err(error) = delivered {
            match error.0 {
                Ok((_, mut cleanup)) | Err((_, mut cleanup)) => cleanup.detach_cleanup(),
            }
        }
    });
    let cleanup_cutoff = deadline + std::time::Duration::from_secs(5);
    loop {
        match result_rx.try_recv() {
            Ok(Ok((receipt, mut cleanup))) => {
                if delivery_cancelled.load(Ordering::Acquire)
                    || std::time::Instant::now() >= deadline
                {
                    cleanup.detach_cleanup();
                    return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
                }
                return Ok((receipt, cleanup));
            }
            Ok(Err((primary, mut cleanup))) => {
                let remaining = cleanup_cutoff.saturating_duration_since(std::time::Instant::now());
                let primary = match tokio::time::timeout(remaining, cleanup.cleanup()).await {
                    Ok(Ok(())) => primary,
                    Ok(Err(cleanup_error)) => FileControlError::Handle(format!(
                        "{primary}; snapshot cleanup failed: {cleanup_error}"
                    )),
                    Err(_) => {
                        cleanup.detach_cleanup();
                        FileControlError::Handle(format!(
                            "{primary}; snapshot cleanup exceeded its fixed cutoff"
                        ))
                    }
                };
                return Err(primary);
            }
            Err(std::sync::mpsc::TryRecvError::Empty)
                if std::time::Instant::now() < cleanup_cutoff =>
            {
                tokio::task::yield_now().await;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                return Err(FileControlError::Handle(
                    "snapshot finalization cleanup exceeded its fixed cutoff".to_owned(),
                ));
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err(FileControlError::Handle(
                    "snapshot finalization owner stopped without a result".to_owned(),
                ));
            }
        }
    }
}

struct ManualTransactionToken {
    database_address: usize,
    connection_nonce: u64,
    generation: u64,
    authorizer_address: usize,
    active: bool,
}

impl ManualTransactionToken {
    fn take_authorizer_for_terminal_close(&mut self) -> usize {
        std::mem::take(&mut self.authorizer_address)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ManualTransactionIdentity {
    database_address: usize,
    connection_nonce: u64,
}

static NEXT_MANUAL_TRANSACTION_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_CONNECTION_NONCE: AtomicU64 = AtomicU64::new(1);
static ACTIVE_MANUAL_TRANSACTIONS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<(usize, u64), u64>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

struct ActiveTransactionRegistration {
    key: (usize, u64),
    generation: u64,
    armed: bool,
}

impl ActiveTransactionRegistration {
    fn register(
        identity: ManualTransactionIdentity,
        generation: u64,
    ) -> Result<Self, FileControlError> {
        let key = (identity.database_address, identity.connection_nonce);
        let mut active = ACTIVE_MANUAL_TRANSACTIONS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active.contains_key(&key) {
            return Err(FileControlError::Handle(
                "SQLite handle already has an active manual transaction".to_owned(),
            ));
        }
        active.insert(key, generation);
        Ok(Self {
            key,
            generation,
            armed: true,
        })
    }

    fn into_token(mut self, authorizer_address: usize) -> ManualTransactionToken {
        self.armed = false;
        ManualTransactionToken {
            database_address: self.key.0,
            connection_nonce: self.key.1,
            generation: self.generation,
            authorizer_address,
            active: true,
        }
    }
}

impl Drop for ActiveTransactionRegistration {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut active = ACTIVE_MANUAL_TRANSACTIONS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active.get(&self.key) == Some(&self.generation) {
            active.remove(&self.key);
        }
    }
}

unsafe extern "C" fn drop_connection_nonce(value: *mut std::ffi::c_void) {
    if !value.is_null() {
        // SAFETY: this pointer was allocated as Box<u64> for SQLite client data.
        drop(unsafe { Box::from_raw(value.cast::<u64>()) });
    }
}

fn connection_lifetime_nonce(database: LiveInterruptPointer) -> Result<u64, FileControlError> {
    // SAFETY: the caller holds SQLx's locked live SQLite handle.
    let existing = unsafe {
        libsqlite3_sys::sqlite3_get_clientdata(
            database.as_ptr(),
            c"gta-claw-connection-nonce".as_ptr(),
        )
    };
    if !existing.is_null() {
        // SAFETY: this key is exclusively registered with a Box<u64>.
        return Ok(unsafe { *existing.cast::<u64>() });
    }
    let nonce = NEXT_CONNECTION_NONCE.fetch_add(1, Ordering::Relaxed).max(1);
    let value = Box::into_raw(Box::new(nonce));
    // SAFETY: SQLite owns `value` after successful registration.
    let result = unsafe {
        libsqlite3_sys::sqlite3_set_clientdata(
            database.as_ptr(),
            c"gta-claw-connection-nonce".as_ptr(),
            value.cast(),
            Some(drop_connection_nonce),
        )
    };
    if result != libsqlite3_sys::SQLITE_OK {
        // SQLite invokes the registered destructor even when allocation fails.
        return Err(FileControlError::SQLite(result));
    }
    Ok(nonce)
}

fn registered_connection_nonce(database: LiveInterruptPointer) -> Option<u64> {
    // SAFETY: the caller holds SQLx's locked live SQLite handle.
    let value = unsafe {
        libsqlite3_sys::sqlite3_get_clientdata(
            database.as_ptr(),
            c"gta-claw-connection-nonce".as_ptr(),
        )
    };
    if value.is_null() {
        None
    } else {
        // SAFETY: this key is exclusively registered with a Box<u64>.
        Some(unsafe { *value.cast::<u64>() })
    }
}

fn unregister_manual_transaction(token: &mut ManualTransactionToken) {
    if token.active {
        let mut active = ACTIVE_MANUAL_TRANSACTIONS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (token.database_address, token.connection_nonce);
        if active.get(&key) == Some(&token.generation) {
            active.remove(&key);
        }
        token.active = false;
    }
}

impl Drop for ManualTransactionToken {
    fn drop(&mut self) {
        unregister_manual_transaction(self);
    }
}

/// Linear owner of one physical SQLite connection and its active manual transaction.
pub struct ManualTransaction<Connection: BeginOwnedConnection> {
    connection: Option<TransactionConnection<Connection>>,
    token: Option<ManualTransactionToken>,
    cleanup_owner: Option<BlockingCleanupOwner>,
}

struct TransactionConnection<Connection: BeginOwnedConnection> {
    inner: Connection,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CommitDeliveryDisposition {
    Pending,
    CleanupRequested,
    Accepted,
    Closed,
}

struct CommitDeliveryState<Connection: BeginOwnedConnection> {
    connection: Option<Connection>,
    disposition: CommitDeliveryDisposition,
    cleanup_error: Option<String>,
}

struct CommitDeliveryShared<Connection: BeginOwnedConnection> {
    state: std::sync::Mutex<CommitDeliveryState<Connection>>,
    changed: std::sync::Condvar,
}

struct CommitDelivery<Connection: BeginOwnedConnection> {
    shared: Arc<CommitDeliveryShared<Connection>>,
    armed: bool,
}

impl<Connection: BeginOwnedConnection> CommitDelivery<Connection> {
    fn new(shared: Arc<CommitDeliveryShared<Connection>>) -> Self {
        Self {
            shared,
            armed: true,
        }
    }

    fn accept(mut self) -> Result<Connection, FileControlError> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match state.disposition {
            CommitDeliveryDisposition::Pending => {
                let connection = state
                    .connection
                    .take()
                    .expect("pending COMMIT delivery retains its connection");
                state.disposition = CommitDeliveryDisposition::Accepted;
                self.shared.changed.notify_one();
                self.armed = false;
                Ok(connection)
            }
            CommitDeliveryDisposition::Closed => Err(FileControlError::CommittedAfterDeadline(
                state.cleanup_error.clone(),
            )),
            CommitDeliveryDisposition::CleanupRequested => Err(FileControlError::Handle(
                "COMMIT delivery cleanup is already in progress".to_owned(),
            )),
            CommitDeliveryDisposition::Accepted => Err(FileControlError::Handle(
                "COMMIT connection was already accepted".to_owned(),
            )),
        }
    }

    fn request_cleanup(mut self) -> Arc<CommitDeliveryShared<Connection>> {
        {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.disposition == CommitDeliveryDisposition::Pending {
                state.disposition = CommitDeliveryDisposition::CleanupRequested;
                self.shared.changed.notify_one();
            }
        }
        self.armed = false;
        Arc::clone(&self.shared)
    }

    fn cleanup_result(shared: &CommitDeliveryShared<Connection>) -> Option<Option<String>> {
        let state = shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.disposition == CommitDeliveryDisposition::Closed)
            .then(|| state.cleanup_error.clone())
    }
}

impl<Connection: BeginOwnedConnection> Drop for CommitDelivery<Connection> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.disposition == CommitDeliveryDisposition::Pending {
            state.disposition = CommitDeliveryDisposition::CleanupRequested;
            self.shared.changed.notify_one();
        }
    }
}

async fn cleanup_late_writer_claim<Connection: BeginOwnedConnection>(
    connection: &mut Connection,
    owner: Option<&str>,
    cleanup_deadline: std::time::Instant,
) -> Result<(), FileControlError> {
    let Some(owner) = owner else {
        return Ok(());
    };
    let remaining = cleanup_deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return Err(FileControlError::Handle(
            "late writer claim cleanup cutoff elapsed".to_owned(),
        ));
    }
    set_busy_timeout(connection.sqlite(), remaining).await?;
    tokio::time::timeout(remaining, async {
        sqlx::query(
            "DELETE FROM claw_writer_lock
             WHERE singleton = 1 AND owner = ?",
        )
        .bind(owner)
        .execute(connection.sqlite())
        .await?;
        let remaining = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM claw_writer_lock
             WHERE singleton = 1 AND owner = ?",
        )
        .bind(owner)
        .fetch_one(connection.sqlite())
        .await?;
        if remaining != 0 {
            return Err(sqlx::Error::Protocol(
                "late writer claim cleanup was not verified".to_owned(),
            ));
        }
        Ok::<(), sqlx::Error>(())
    })
    .await
    .map_err(|_| FileControlError::Handle("late writer claim cleanup timed out".to_owned()))?
    .map_err(|error| FileControlError::Handle(error.to_string()))
}

fn drive_commit_delivery<Connection: BeginOwnedConnection>(
    shared: Arc<CommitDeliveryShared<Connection>>,
    runtime: &tokio::runtime::Runtime,
    terminal_closes: &mut TerminalCloseBatch,
    owner: Option<&str>,
    cleanup_deadline: std::time::Instant,
) {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        match state.disposition {
            CommitDeliveryDisposition::Accepted | CommitDeliveryDisposition::Closed => return,
            CommitDeliveryDisposition::CleanupRequested => break,
            CommitDeliveryDisposition::Pending => {
                let remaining =
                    cleanup_deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    state.disposition = CommitDeliveryDisposition::CleanupRequested;
                    break;
                }
                let (next, timeout) = shared
                    .changed
                    .wait_timeout(state, remaining)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state = next;
                if timeout.timed_out() && state.disposition == CommitDeliveryDisposition::Pending {
                    state.disposition = CommitDeliveryDisposition::CleanupRequested;
                }
            }
        }
    }
    let mut connection = state
        .connection
        .take()
        .expect("cleanup-requested COMMIT delivery retains its connection");
    drop(state);
    let cleanup = runtime.block_on(cleanup_late_writer_claim(
        &mut connection,
        owner,
        cleanup_deadline,
    ));
    let close = terminal_closes.close(connection);
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.cleanup_error = cleanup.err().map(|error| error.to_string()).or_else(|| {
        (close != TerminalCloseOutcome::Closed).then(|| format!("terminal close: {close:?}"))
    });
    state.disposition = CommitDeliveryDisposition::Closed;
    shared.changed.notify_all();
}

impl<Connection: BeginOwnedConnection> ManualTransaction<Connection> {
    #[cfg(test)]
    fn into_test_parts(mut self) -> (Connection, ManualTransactionToken) {
        self.cleanup_owner.take();
        (
            self.connection
                .take()
                .expect("test transaction connection remains owned")
                .inner,
            self.token
                .take()
                .expect("test transaction token remains owned"),
        )
    }

    /// Commits and returns the owned connection only after SQLite reaches autocommit.
    pub async fn commit(mut self) -> Result<Connection, FileControlError> {
        let result = commit_synchronously(
            self.connection
                .as_mut()
                .expect("manual transaction connection remains owned")
                .inner
                .sqlite(),
            self.token
                .as_mut()
                .expect("manual transaction token remains owned"),
            None,
        )
        .await;
        match result {
            Ok(()) => {
                self.token.take();
                self.cleanup_owner.take();
                Ok(self
                    .connection
                    .take()
                    .expect("committed connection remains owned")
                    .inner)
            }
            Err(commit_error) => {
                let committed = matches!(
                    commit_error,
                    FileControlError::CommittedWithCleanupFailure(_)
                        | FileControlError::CommitOutcomeUncertain(_, _)
                );
                let rollback =
                    if !committed && self.token.as_ref().is_some_and(|token| token.active) {
                        rollback_synchronously(
                            self.connection
                                .as_mut()
                                .expect("failed commit connection remains owned")
                                .inner
                                .sqlite(),
                            self.token
                                .as_mut()
                                .expect("failed commit token remains owned"),
                        )
                        .await
                    } else {
                        Ok(())
                    };
                let connection = self
                    .connection
                    .take()
                    .expect("failed commit connection remains owned");
                let authorizer_address = self
                    .token
                    .as_mut()
                    .map(ManualTransactionToken::take_authorizer_for_terminal_close)
                    .unwrap_or(0);
                self.token.take();
                let cleanup_owner = self.cleanup_owner.take();
                if let Some(mut owner) = cleanup_owner {
                    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
                    owner.handoff(move |_runtime, mut terminal_closes| {
                        let close = terminal_closes
                            .close_with_authorizer(connection.inner, authorizer_address);
                        let _ = done_tx.send(close);
                    });
                    let close = done_rx.await.unwrap_or(TerminalCloseOutcome::Quarantined);
                    if committed {
                        return Err(append_committed_cleanup(
                            commit_error,
                            format!("terminal close: {close:?}"),
                        ));
                    }
                    if close != TerminalCloseOutcome::Closed {
                        return Err(FileControlError::Handle(format!(
                            "COMMIT failed: {commit_error}; terminal close: {close:?}"
                        )));
                    }
                }
                if committed {
                    return Err(commit_error);
                }
                Err(match rollback {
                    Ok(()) => commit_error,
                    Err(rollback_error) => FileControlError::Handle(format!(
                        "COMMIT failed: {commit_error}; terminal ROLLBACK failed: {rollback_error}"
                    )),
                })
            }
        }
    }

    /// Checks whether SQLite reports that this transaction's main file moved.
    #[cfg(unix)]
    pub async fn main_database_has_moved(&mut self) -> Result<bool, FileControlError> {
        main_database_has_moved(
            self.connection
                .as_mut()
                .expect("manual transaction connection remains owned")
                .inner
                .sqlite(),
        )
        .await
    }

    /// Commits on the dedicated cleanup runtime with one immutable deadline and
    /// cancellation-aware SQLite busy handler.
    pub async fn commit_with_deadline(
        mut self,
        deadline: std::time::Instant,
        cleanup_deadline: std::time::Instant,
        cancelled: Arc<std::sync::atomic::AtomicBool>,
        restore_busy_timeout: std::time::Duration,
        late_writer_owner: Option<String>,
    ) -> Result<Connection, FileControlError> {
        if cancelled.load(std::sync::atomic::Ordering::Acquire)
            || std::time::Instant::now() >= deadline
        {
            let rollback = tokio::time::timeout_at(
                tokio::time::Instant::from_std(cleanup_deadline),
                self.rollback(),
            )
            .await;
            return Err(match rollback {
                Ok(Ok(_)) => FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT),
                Ok(Err(error)) => FileControlError::Handle(format!(
                    "SQLite COMMIT interrupted; terminal rollback failed: {error}"
                )),
                Err(_) => FileControlError::Handle(
                    "SQLite COMMIT interrupted; terminal rollback exceeded cleanup cutoff"
                        .to_owned(),
                ),
            });
        }
        let mut connection = self
            .connection
            .take()
            .expect("bounded commit connection remains owned");
        let mut token = self
            .token
            .take()
            .expect("bounded commit token remains owned");
        let mut cleanup_owner = self
            .cleanup_owner
            .take()
            .expect("bounded commit cleanup owner remains owned");
        let delivery_cancelled = Arc::clone(&cancelled);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        cleanup_owner.handoff(move |runtime, mut terminal_closes| {
            let cancellation = Arc::new(BeginCancellation {
                local: std::sync::atomic::AtomicBool::new(false),
                external: Some(cancelled),
                deadline,
                #[cfg(test)]
                busy_entered: std::sync::Mutex::new(None),
                #[cfg(test)]
                test_key: std::sync::Mutex::new(None),
            });
            let result = runtime.block_on(async {
                let pointer = {
                    let mut handle = connection
                        .inner
                        .sqlite()
                        .lock_handle()
                        .await
                        .map_err(|error| FileControlError::Handle(error.to_string()))?;
                    let pointer = LiveInterruptPointer(handle.as_raw_handle());
                    // SAFETY: cancellation remains alive until the handler is restored below.
                    let result = unsafe {
                        libsqlite3_sys::sqlite3_busy_handler(
                            pointer.as_ptr(),
                            Some(begin_busy_handler),
                            Arc::as_ptr(&cancellation).cast_mut().cast(),
                        )
                    };
                    if result != libsqlite3_sys::SQLITE_OK {
                        return Err(FileControlError::SQLite(result));
                    }
                    pointer
                };
                let commit = if cancellation.is_expired() {
                    Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT))
                } else {
                    commit_synchronously(connection.inner.sqlite(), &mut token, Some(&cancellation))
                        .await
                };
                let restore_ms =
                    i32::try_from(restore_busy_timeout.as_millis()).unwrap_or(i32::MAX);
                let restored = connection
                    .inner
                    .sqlite()
                    .lock_handle()
                    .await
                    .map_err(|error| FileControlError::Handle(error.to_string()))
                    .map(|_handle| {
                        // SAFETY: the same locked SQLite handle remains live.
                        unsafe {
                            libsqlite3_sys::sqlite3_busy_timeout(pointer.as_ptr(), restore_ms);
                        }
                    });
                match (commit, restored) {
                    (Ok(()), Ok(())) => Ok(()),
                    (Ok(()), Err(error)) => {
                        Err(FileControlError::CommittedWithCleanupFailure(error.to_string()))
                    }
                    (
                        Err(FileControlError::CommittedWithCleanupFailure(commit)),
                        Err(error),
                    ) => Err(FileControlError::CommittedWithCleanupFailure(format!(
                        "{commit}; restore busy handler: {error}"
                    ))),
                    (Err(FileControlError::CommitOutcomeUncertain(code, commit)), Err(error)) => {
                        Err(FileControlError::CommitOutcomeUncertain(
                            code,
                            format!("{commit}; restore busy handler: {error}"),
                        ))
                    }
                    (Err(error), Ok(())) => Err(error),
                    (Err(error), Err(restore)) => Err(FileControlError::Handle(format!(
                        "{error}; restore busy handler failed: {restore}"
                    ))),
                }
            });
            match result {
                Ok(()) => {
                    let _runtime = runtime.enter();
                    let mut connection = connection.inner;
                    #[cfg(test)]
                    wait_at_commit_result_test_gate(late_writer_owner.as_deref());
                    if cancellation.is_expired() {
                        let cleanup = runtime.block_on(cleanup_late_writer_claim(
                            &mut connection,
                            late_writer_owner.as_deref(),
                            cleanup_deadline,
                        ));
                        let close = terminal_closes.close(connection);
                        let cleanup = cleanup
                            .err()
                            .map(|error| error.to_string())
                            .or_else(|| {
                                (close != TerminalCloseOutcome::Closed)
                                    .then(|| format!("terminal close: {close:?}"))
                            });
                        let _ = result_tx.send(Err(FileControlError::CommittedAfterDeadline(
                            cleanup,
                        )));
                    } else {
                        let shared = Arc::new(CommitDeliveryShared {
                            state: std::sync::Mutex::new(CommitDeliveryState {
                                connection: Some(connection),
                                disposition: CommitDeliveryDisposition::Pending,
                                cleanup_error: None,
                            }),
                            changed: std::sync::Condvar::new(),
                        });
                        let delivery = CommitDelivery::new(Arc::clone(&shared));
                        let _ = result_tx.send(Ok(delivery));
                        drive_commit_delivery(
                            shared,
                            runtime,
                            &mut terminal_closes,
                            late_writer_owner.as_deref(),
                            cleanup_deadline,
                        );
                    }
                }
                Err(error) => {
                    let committed = matches!(
                        error,
                        FileControlError::CommittedWithCleanupFailure(_)
                            | FileControlError::CommitOutcomeUncertain(_, _)
                    );
                    let rollback = if !committed && token.active {
                        runtime.block_on(rollback_synchronously(
                            connection.inner.sqlite(),
                            &mut token,
                        ))
                    } else {
                        Ok(())
                    };
                    let late_cleanup = if committed {
                        runtime
                            .block_on(cleanup_late_writer_claim(
                                &mut connection.inner,
                                late_writer_owner.as_deref(),
                                cleanup_deadline,
                            ))
                            .err()
                            .map(|error| error.to_string())
                    } else {
                        None
                    };
                    let authorizer_address = token.take_authorizer_for_terminal_close();
                    drop(token);
                    let close = terminal_closes
                        .close_with_authorizer(connection.inner, authorizer_address);
                    let error = if committed {
                        append_committed_cleanup(
                            error,
                            format!(
                                "late claim cleanup: {}; terminal close: {close:?}",
                                late_cleanup.as_deref().unwrap_or("ok")
                            ),
                        )
                    } else {
                        match rollback {
                        Ok(()) if close == TerminalCloseOutcome::Closed => error,
                        Ok(()) => FileControlError::Handle(format!(
                            "{error}; terminal close: {close:?}"
                        )),
                        Err(rollback_error) => FileControlError::Handle(format!(
                            "{error}; terminal rollback failed: {rollback_error}; terminal close: {close:?}"
                        )),
                        }
                    };
                    let _ = result_tx.send(Err(error));
                }
            }
        });
        loop {
            match result_rx.try_recv() {
                Ok(Ok(delivery))
                    if delivery_cancelled.load(std::sync::atomic::Ordering::Acquire)
                        || std::time::Instant::now() >= deadline =>
                {
                    let cleanup = delivery.request_cleanup();
                    loop {
                        match CommitDelivery::cleanup_result(&cleanup) {
                            Some(cleanup) => {
                                return Err(FileControlError::CommittedAfterDeadline(cleanup));
                            }
                            None if std::time::Instant::now() < cleanup_deadline => {
                                tokio::task::yield_now().await;
                            }
                            None => {
                                return Err(FileControlError::Handle(
                                    "late COMMIT result cleanup exceeded its cutoff".to_owned(),
                                ));
                            }
                        }
                    }
                }
                Ok(Ok(delivery)) => return delivery.accept(),
                Ok(Err(error)) => return Err(error),
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    if std::time::Instant::now() >= cleanup_deadline {
                        return Err(FileControlError::Handle(
                            "bounded COMMIT exceeded its cleanup cutoff".to_owned(),
                        ));
                    }
                    tokio::task::yield_now().await;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err(FileControlError::Handle(
                        "bounded COMMIT cleanup owner stopped without a result".to_owned(),
                    ));
                }
            }
        }
    }

    /// Rolls back and returns the owned connection only after SQLite reaches autocommit.
    pub async fn rollback(mut self) -> Result<Connection, FileControlError> {
        let mut connection = self
            .connection
            .take()
            .expect("rollback connection remains owned");
        let mut token = self.token.take().expect("rollback token remains owned");
        let mut owner = self
            .cleanup_owner
            .take()
            .expect("rollback cleanup owner remains owned");
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        owner.handoff(move |runtime, mut terminal_closes| {
            let rollback = runtime.block_on(rollback_synchronously(
                connection.inner.sqlite(),
                &mut token,
            ));
            let result = match rollback {
                Ok(()) => Ok(connection.inner),
                Err(error) => {
                    let authorizer_address = token.take_authorizer_for_terminal_close();
                    drop(token);
                    let close =
                        terminal_closes.close_with_authorizer(connection.inner, authorizer_address);
                    Err(if close == TerminalCloseOutcome::Closed {
                        error
                    } else {
                        FileControlError::Handle(format!("{error}; terminal close: {close:?}"))
                    })
                }
            };
            if let Err(result) = result_tx.send(result)
                && let Ok(connection) = result
            {
                let _ = terminal_closes.close(connection);
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), result_rx)
            .await
            .map_err(|_| {
                FileControlError::Handle(
                    "terminal rollback exceeded its fixed cleanup cutoff".to_owned(),
                )
            })?
            .map_err(|_| {
                FileControlError::Handle(
                    "terminal rollback owner stopped without result".to_owned(),
                )
            })?
    }
}

impl<Connection: BeginOwnedConnection> std::fmt::Debug for ManualTransaction<Connection> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManualTransaction")
            .field(
                "active",
                &self.token.as_ref().is_some_and(|token| token.active),
            )
            .finish_non_exhaustive()
    }
}

impl<Connection: BeginOwnedConnection> std::fmt::Debug for TransactionConnection<Connection> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransactionConnection")
            .finish_non_exhaustive()
    }
}

impl<'connection, Connection: BeginOwnedConnection> sqlx::Executor<'connection>
    for &'connection mut ManualTransaction<Connection>
{
    type Database = sqlx::Sqlite;

    fn fetch_many<'executor, 'query: 'executor, Execute>(
        self,
        query: Execute,
    ) -> futures_core::stream::BoxStream<
        'executor,
        Result<sqlx::Either<sqlx::sqlite::SqliteQueryResult, sqlx::sqlite::SqliteRow>, sqlx::Error>,
    >
    where
        'connection: 'executor,
        Execute: 'query + sqlx::Execute<'query, sqlx::Sqlite>,
    {
        sqlx::Executor::fetch_many(
            self.connection
                .as_mut()
                .expect("manual transaction connection remains owned")
                .inner
                .sqlite(),
            query,
        )
    }

    fn fetch_optional<'executor, 'query: 'executor, Execute>(
        self,
        query: Execute,
    ) -> futures_core::future::BoxFuture<
        'executor,
        Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error>,
    >
    where
        'connection: 'executor,
        Execute: 'query + sqlx::Execute<'query, sqlx::Sqlite>,
    {
        sqlx::Executor::fetch_optional(
            self.connection
                .as_mut()
                .expect("manual transaction connection remains owned")
                .inner
                .sqlite(),
            query,
        )
    }

    fn prepare_with<'executor>(
        self,
        sql: sqlx::SqlStr,
        parameters: &'executor [sqlx::sqlite::SqliteTypeInfo],
    ) -> futures_core::future::BoxFuture<
        'executor,
        Result<sqlx::sqlite::SqliteStatement, sqlx::Error>,
    >
    where
        'connection: 'executor,
    {
        sqlx::Executor::prepare_with(
            self.connection
                .as_mut()
                .expect("manual transaction connection remains owned")
                .inner
                .sqlite(),
            sql,
            parameters,
        )
    }
}

impl<Connection: BeginOwnedConnection> Drop for ManualTransaction<Connection> {
    fn drop(&mut self) {
        let (Some(mut connection), Some(mut token), Some(mut cleanup_owner)) = (
            self.connection.take(),
            self.token.take(),
            self.cleanup_owner.take(),
        ) else {
            return;
        };
        cleanup_owner.handoff(move |runtime, mut terminal_closes| {
            let rollback = runtime.block_on(rollback_synchronously(
                connection.inner.sqlite(),
                &mut token,
            ));
            let _ = rollback;
            let authorizer_address = token.take_authorizer_for_terminal_close();
            drop(token);
            let _ = terminal_closes.close_with_authorizer(connection.inner, authorizer_address);
        });
    }
}
enum BeginWorkerCommand {
    Accept(u64),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum BeginTestStage {
    BeforeDispatch,
    AfterBegin,
    AfterAccept,
    AfterFailureOutcome,
    PanicAfterPointerPublication,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum BeginTestOperation {
    Stage(BeginTestStage),
    BusyObserver,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct BeginTestKey {
    path: String,
    connection_nonce: u64,
    operation_generation: u64,
    operation: BeginTestOperation,
}

#[cfg(test)]
struct BeginTestGate {
    stage: BeginTestStage,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<std::sync::atomic::AtomicBool>,
    hold_after_cancellation: bool,
}

#[cfg(test)]
static BEGIN_TEST_GATE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<BeginTestKey, BeginTestGate>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static BEGIN_BUSY_OBSERVERS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<BeginTestKey, Arc<tokio::sync::Notify>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static PENDING_BEGIN_TEST_KEYS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u64, BeginTestKey>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static NEXT_BEGIN_TEST_GENERATION: AtomicU64 = AtomicU64::new(1);
#[cfg(test)]
static BEGIN_TEST_SERIAL: std::sync::LazyLock<Arc<tokio::sync::Mutex<()>>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

#[cfg(test)]
struct CommitResultTestGate {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
static COMMIT_RESULT_TEST_GATES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, CommitResultTestGate>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static EXECUTOR_TEST_SERIAL: std::sync::LazyLock<Arc<tokio::sync::Mutex<()>>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

#[cfg(test)]
fn wait_at_commit_result_test_gate(owner: Option<&str>) {
    let Some(owner) = owner else {
        return;
    };
    let gate = COMMIT_RESULT_TEST_GATES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(owner)
        .map(|gate| (Arc::clone(&gate.entered), Arc::clone(&gate.release)));
    if let Some((entered, release)) = gate {
        entered.notify_one();
        while !release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
    }
}

#[cfg(test)]
fn wait_at_begin_test_gate(
    stage: BeginTestStage,
    cancellation: &BeginCancellation,
    command: &std::sync::mpsc::Receiver<BeginWorkerCommand>,
) -> bool {
    let key = cancellation
        .test_key
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let gate = BEGIN_TEST_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(key.as_ref().unwrap_or(&BeginTestKey {
            path: String::new(),
            connection_nonce: 0,
            operation_generation: 0,
            operation: BeginTestOperation::Stage(stage),
        }))
        .filter(|gate| gate.stage == stage)
        .map(|gate| {
            (
                Arc::clone(&gate.entered),
                Arc::clone(&gate.release),
                gate.hold_after_cancellation,
            )
        });
    let Some((entered, release, hold_after_cancellation)) = gate else {
        return true;
    };
    entered.notify_one();
    while !release.load(std::sync::atomic::Ordering::Acquire) {
        if hold_after_cancellation {
            std::thread::yield_now();
            continue;
        }
        match command.try_recv() {
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                std::thread::yield_now();
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return false,
            Ok(BeginWorkerCommand::Accept(_)) => return false,
        }
    }
    true
}

#[cfg(test)]
fn begin_test_gate_is_configured(stage: BeginTestStage, cancellation: &BeginCancellation) -> bool {
    let key = cancellation
        .test_key
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    key.is_some_and(|key| {
        BEGIN_TEST_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .is_some_and(|gate| gate.stage == stage)
    })
}

#[cfg(test)]
fn wait_at_begin_failure_cleanup_gate(cancellation: &BeginCancellation) {
    let key = cancellation
        .test_key
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let gate = BEGIN_TEST_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(key.as_ref().unwrap_or(&BeginTestKey {
            path: String::new(),
            connection_nonce: 0,
            operation_generation: 0,
            operation: BeginTestOperation::Stage(BeginTestStage::AfterFailureOutcome),
        }))
        .filter(|gate| gate.stage == BeginTestStage::AfterFailureOutcome)
        .map(|gate| (Arc::clone(&gate.entered), Arc::clone(&gate.release)));
    if let Some((entered, release)) = gate {
        entered.notify_one();
        while !release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
    }
}

/// Connection ownership supported by [`ManualTransaction`].
pub trait BeginOwnedConnection: Send + 'static {
    /// Borrows the underlying SQLite connection.
    fn sqlite_ref(&self) -> &sqlx::SqliteConnection;

    /// Mutably borrows the underlying SQLite connection.
    fn sqlite(&mut self) -> &mut sqlx::SqliteConnection;

    /// Closes the owned physical connection on a terminal-close runtime.
    fn close_on_runtime(self, runtime: &tokio::runtime::Runtime) -> Result<(), String>;
}

impl BeginOwnedConnection for sqlx::SqliteConnection {
    fn sqlite_ref(&self) -> &sqlx::SqliteConnection {
        self
    }

    fn sqlite(&mut self) -> &mut sqlx::SqliteConnection {
        self
    }

    fn close_on_runtime(self, runtime: &tokio::runtime::Runtime) -> Result<(), String> {
        runtime
            .block_on(sqlx::Connection::close(self))
            .map_err(|error| error.to_string())
    }
}

impl BeginOwnedConnection for sqlx::pool::PoolConnection<sqlx::Sqlite> {
    fn sqlite_ref(&self) -> &sqlx::SqliteConnection {
        self
    }

    fn sqlite(&mut self) -> &mut sqlx::SqliteConnection {
        self
    }

    fn close_on_runtime(self, runtime: &tokio::runtime::Runtime) -> Result<(), String> {
        runtime
            .block_on(self.close())
            .map_err(|error| error.to_string())
    }
}

enum BeginWorkerOutput<Connection> {
    Accepted(Connection, ManualTransactionIdentity, usize),
    Terminal(TerminalCloseOutcome),
}

struct BeginCancellation {
    local: std::sync::atomic::AtomicBool,
    external: Option<Arc<std::sync::atomic::AtomicBool>>,
    deadline: std::time::Instant,
    #[cfg(test)]
    busy_entered: std::sync::Mutex<Option<Arc<tokio::sync::Notify>>>,
    #[cfg(test)]
    test_key: std::sync::Mutex<Option<BeginTestKey>>,
}

struct BusyHandlerRestore {
    database: LiveInterruptPointer,
    timeout_ms: i32,
}

impl Drop for BusyHandlerRestore {
    fn drop(&mut self) {
        // SAFETY: the worker still owns SQLx's locked live handle while this
        // generation-bound restore guard is in scope.
        unsafe {
            libsqlite3_sys::sqlite3_busy_timeout(self.database.as_ptr(), self.timeout_ms);
        }
    }
}

impl BeginCancellation {
    fn is_cancelled(&self) -> bool {
        self.local.load(std::sync::atomic::Ordering::Acquire)
            || self
                .external
                .as_ref()
                .is_some_and(|state| state.load(std::sync::atomic::Ordering::Acquire))
    }

    fn is_expired(&self) -> bool {
        self.is_cancelled() || std::time::Instant::now() >= self.deadline
    }
}

unsafe extern "C" fn begin_busy_handler(
    context: *mut std::ffi::c_void,
    _prior_calls: std::ffi::c_int,
) -> std::ffi::c_int {
    // SAFETY: `context` points to an Arc-owned BeginCancellation retained for
    // the complete handler registration.
    let cancellation = unsafe { &*context.cast::<BeginCancellation>() };
    #[cfg(test)]
    if let Some(entered) = cancellation
        .busy_entered
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
    {
        entered.notify_one();
    }
    if cancellation.is_expired() {
        0
    } else {
        std::thread::sleep(std::time::Duration::from_millis(1));
        1
    }
}

unsafe extern "C" fn deny_transaction_control(
    context: *mut std::ffi::c_void,
    action: std::ffi::c_int,
    _detail_one: *const std::ffi::c_char,
    _detail_two: *const std::ffi::c_char,
    _database: *const std::ffi::c_char,
    _trigger: *const std::ffi::c_char,
) -> std::ffi::c_int {
    if action != libsqlite3_sys::SQLITE_TRANSACTION && action != libsqlite3_sys::SQLITE_SAVEPOINT {
        return libsqlite3_sys::SQLITE_OK;
    }
    if context.is_null() {
        return libsqlite3_sys::SQLITE_DENY;
    }
    // SAFETY: the context remains owned by the active transaction token until
    // the authorizer is removed from this exact connection.
    let context = unsafe { &*context.cast::<TransactionAuthorizerContext>() };
    let active = ACTIVE_MANUAL_TRANSACTIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(context.database_address, context.connection_nonce))
        == Some(&context.generation);
    if active && context.internal_permit.load(Ordering::Acquire) {
        libsqlite3_sys::SQLITE_OK
    } else {
        libsqlite3_sys::SQLITE_DENY
    }
}

struct TransactionAuthorizerContext {
    database_address: usize,
    connection_nonce: u64,
    generation: u64,
    internal_permit: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
static FAIL_AUTHORIZER_DETACH_GENERATIONS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<u64>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static DROPPED_AUTHORIZER_GENERATIONS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u64, usize>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

impl Drop for TransactionAuthorizerContext {
    fn drop(&mut self) {
        #[cfg(test)]
        {
            *DROPPED_AUTHORIZER_GENERATIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(self.generation)
                .or_insert(0) += 1;
        }
    }
}

fn install_transaction_authorizer(
    database: LiveInterruptPointer,
    identity: ManualTransactionIdentity,
    generation: u64,
) -> Result<usize, FileControlError> {
    let context = Box::new(TransactionAuthorizerContext {
        database_address: identity.database_address,
        connection_nonce: identity.connection_nonce,
        generation,
        internal_permit: std::sync::atomic::AtomicBool::new(false),
    });
    let context = Box::into_raw(context);
    // SAFETY: `context` stays allocated until the owner clears this authorizer.
    let result = unsafe {
        libsqlite3_sys::sqlite3_set_authorizer(
            database.as_ptr(),
            Some(deny_transaction_control),
            context.cast(),
        )
    };
    if result != libsqlite3_sys::SQLITE_OK {
        // SAFETY: SQLite rejected the registration and cannot retain the context.
        drop(unsafe { Box::from_raw(context) });
        return Err(FileControlError::SQLite(result));
    }
    Ok(context as usize)
}

struct InternalTransactionPermit<'context> {
    context: &'context TransactionAuthorizerContext,
}

impl InternalTransactionPermit<'_> {
    fn activate(token: &ManualTransactionToken) -> Result<Self, FileControlError> {
        if token.authorizer_address == 0 {
            return Err(FileControlError::Handle(
                "manual transaction authorizer context is missing".to_owned(),
            ));
        }
        // SAFETY: an active token exclusively owns this installed context.
        let context =
            unsafe { &*(token.authorizer_address as *const TransactionAuthorizerContext) };
        if (
            context.database_address,
            context.connection_nonce,
            context.generation,
        ) != (
            token.database_address,
            token.connection_nonce,
            token.generation,
        ) {
            return Err(FileControlError::Handle(
                "manual transaction authorizer generation is stale".to_owned(),
            ));
        }
        if context.internal_permit.swap(true, Ordering::AcqRel) {
            return Err(FileControlError::Handle(
                "manual transaction internal permit is already active".to_owned(),
            ));
        }
        Ok(Self { context })
    }
}

impl Drop for InternalTransactionPermit<'_> {
    fn drop(&mut self) {
        self.context.internal_permit.store(false, Ordering::Release);
    }
}

fn clear_transaction_authorizer(
    database: LiveInterruptPointer,
    authorizer_address: &mut usize,
) -> Result<(), FileControlError> {
    if *authorizer_address == 0 {
        return Ok(());
    }
    #[cfg(test)]
    {
        // SAFETY: a nonzero owner address names its live authorizer context.
        let generation =
            unsafe { (*(*authorizer_address as *const TransactionAuthorizerContext)).generation };
        if FAIL_AUTHORIZER_DETACH_GENERATIONS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&generation)
        {
            return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_ERROR));
        }
    }
    // SAFETY: the locked handle owns this exact callback registration.
    let result = unsafe {
        libsqlite3_sys::sqlite3_set_authorizer(database.as_ptr(), None, std::ptr::null_mut())
    };
    if result != libsqlite3_sys::SQLITE_OK {
        return Err(FileControlError::SQLite(result));
    }
    // SAFETY: SQLite accepted the unregister operation and no longer retains pApp.
    unsafe {
        drop(Box::from_raw(
            *authorizer_address as *mut TransactionAuthorizerContext,
        ));
    }
    *authorizer_address = 0;
    Ok(())
}

struct OwnedBeginGuard<Connection: BeginOwnedConnection> {
    worker_result: Option<std::sync::mpsc::Receiver<BeginWorkerOutput<Connection>>>,
    command: Option<std::sync::mpsc::Sender<BeginWorkerCommand>>,
    database: Arc<std::sync::Mutex<Option<LiveInterruptPointer>>>,
    cancellation: Arc<BeginCancellation>,
    cleanup_owner: Option<BlockingCleanupOwner>,
    armed: bool,
}

impl<Connection: BeginOwnedConnection> OwnedBeginGuard<Connection> {
    fn request_cancellation(&mut self) {
        self.cancellation
            .local
            .store(true, std::sync::atomic::Ordering::Release);
        self.command.take();
        let database = self
            .database
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(database) = database.as_ref() {
            // SAFETY: the worker owns the connection and clears this slot under
            // the same mutex before terminal connection cleanup.
            unsafe {
                libsqlite3_sys::sqlite3_interrupt(database.as_ptr());
            }
        }
    }

    async fn receive_worker_result(
        &mut self,
    ) -> Result<BeginWorkerOutput<Connection>, FileControlError> {
        let cutoff = self.cancellation.deadline + std::time::Duration::from_secs(1);
        loop {
            let received = self
                .worker_result
                .as_ref()
                .ok_or_else(|| {
                    FileControlError::Handle("BEGIN worker result owner is missing".to_owned())
                })?
                .try_recv();
            match received {
                Ok(result) => {
                    self.worker_result.take();
                    return Ok(result);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) if std::time::Instant::now() < cutoff => {
                    tokio::task::yield_now().await;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    return Err(FileControlError::Handle(
                        "BEGIN terminal cleanup exceeded its fixed cutoff".to_owned(),
                    ));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.worker_result.take();
                    return Err(FileControlError::Handle(
                        "BEGIN owner stopped without a terminal result".to_owned(),
                    ));
                }
            }
        }
    }

    async fn accept(
        mut self,
        generation: u64,
    ) -> Result<
        (
            Connection,
            ManualTransactionIdentity,
            usize,
            BlockingCleanupOwner,
        ),
        FileControlError,
    > {
        self.command
            .take()
            .ok_or_else(|| FileControlError::Handle("BEGIN command channel is missing".to_owned()))?
            .send(BeginWorkerCommand::Accept(generation))
            .map_err(|_| {
                FileControlError::Handle("BEGIN worker stopped before accept".to_owned())
            })?;
        let result = match self.receive_worker_result().await? {
            BeginWorkerOutput::Accepted(connection, identity, authorizer_address) => {
                (connection, identity, authorizer_address)
            }
            BeginWorkerOutput::Terminal(close) => {
                return Err(FileControlError::Handle(format!(
                    "BEGIN worker discarded the connection; terminal close: {close:?}"
                )));
            }
        };
        let cleanup_owner = self
            .cleanup_owner
            .take()
            .ok_or_else(|| FileControlError::Handle("BEGIN cleanup owner is missing".to_owned()))?;
        self.armed = false;
        Ok((result.0, result.1, result.2, cleanup_owner))
    }

    async fn join_failure(mut self) -> Result<(), FileControlError> {
        self.command.take();
        if let BeginWorkerOutput::Terminal(close) = self.receive_worker_result().await?
            && close != TerminalCloseOutcome::Closed
        {
            return Err(FileControlError::Handle(format!(
                "BEGIN terminal cleanup degraded: {close:?}"
            )));
        }
        self.shutdown_cleanup_owner()?;
        self.armed = false;
        Ok(())
    }

    fn shutdown_cleanup_owner(&mut self) -> Result<(), FileControlError> {
        self.cleanup_owner
            .take()
            .ok_or_else(|| FileControlError::Handle("BEGIN cleanup owner is missing".to_owned()))?
            .shutdown()
            .map_err(FileControlError::Handle)
    }
}

impl<Connection: BeginOwnedConnection> Drop for OwnedBeginGuard<Connection> {
    fn drop(&mut self) {
        if self.armed {
            self.request_cancellation();
        }
    }
}

fn close_owned_begin_connection<Connection: BeginOwnedConnection>(
    terminal_closes: &mut TerminalCloseBatch,
    connection: Connection,
) -> TerminalCloseOutcome {
    terminal_closes.close(connection)
}

enum LockedBeginOutcome {
    Accepted(ManualTransactionIdentity, usize),
    Failed(FileControlError),
    Cancelled,
}

fn run_locked_begin<Connection: BeginOwnedConnection>(
    runtime: &tokio::runtime::Runtime,
    connection: &mut Connection,
    outcome: &std::sync::mpsc::SyncSender<Result<ManualTransactionIdentity, FileControlError>>,
    command: &std::sync::mpsc::Receiver<BeginWorkerCommand>,
    database_slot: &Arc<std::sync::Mutex<Option<LiveInterruptPointer>>>,
    restore_busy_timeout: std::time::Duration,
    cancellation: &Arc<BeginCancellation>,
) -> LockedBeginOutcome {
    let mut database = match runtime.block_on(connection.sqlite().lock_handle()) {
        Ok(database) => database,
        Err(error) => {
            return LockedBeginOutcome::Failed(FileControlError::Handle(error.to_string()));
        }
    };
    let pointer = LiveInterruptPointer(database.as_raw_handle());
    let connection_nonce = match connection_lifetime_nonce(pointer) {
        Ok(nonce) => nonce,
        Err(error) => return LockedBeginOutcome::Failed(error),
    };
    #[cfg(test)]
    {
        let key = PENDING_BEGIN_TEST_KEYS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&connection_nonce);
        *cancellation
            .test_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = key.clone();
        if let Some(key) = key {
            *cancellation
                .busy_entered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = BEGIN_BUSY_OBSERVERS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&key)
                .cloned();
        }
    }
    let restore_busy_timeout_ms =
        i32::try_from(restore_busy_timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: the worker exclusively owns the locked SQLite handle and retains
    // `cancellation` until this handler is cleared.
    let busy_result = unsafe {
        libsqlite3_sys::sqlite3_busy_handler(
            pointer.as_ptr(),
            Some(begin_busy_handler),
            Arc::as_ptr(cancellation).cast_mut().cast(),
        )
    };
    if busy_result != libsqlite3_sys::SQLITE_OK {
        return LockedBeginOutcome::Failed(FileControlError::SQLite(busy_result));
    }
    let _busy_restore = BusyHandlerRestore {
        database: pointer,
        timeout_ms: restore_busy_timeout_ms,
    };
    let _interrupt_registration =
        LiveInterruptRegistration::publish(Arc::clone(database_slot), pointer);
    #[cfg(test)]
    if !wait_at_begin_test_gate(
        BeginTestStage::PanicAfterPointerPublication,
        cancellation,
        command,
    ) {
        return LockedBeginOutcome::Cancelled;
    } else if begin_test_gate_is_configured(
        BeginTestStage::PanicAfterPointerPublication,
        cancellation,
    ) {
        panic!("injected BEGIN panic after pointer publication");
    }
    #[cfg(test)]
    if !wait_at_begin_test_gate(BeginTestStage::BeforeDispatch, cancellation, command) {
        return LockedBeginOutcome::Cancelled;
    }
    if cancellation.is_expired() {
        return LockedBeginOutcome::Cancelled;
    }
    let mut message = std::ptr::null_mut();
    // SAFETY: the dedicated worker owns the connection, retains SQLx's locked
    // handle for the complete raw operation, and joins before ownership moves.
    let result = unsafe {
        libsqlite3_sys::sqlite3_exec(
            pointer.as_ptr(),
            c"BEGIN IMMEDIATE".as_ptr(),
            None,
            std::ptr::null_mut(),
            &raw mut message,
        )
    };
    if !message.is_null() {
        // SAFETY: sqlite3_exec allocated this diagnostic.
        unsafe {
            libsqlite3_sys::sqlite3_free(message.cast());
        }
    }
    if result != libsqlite3_sys::SQLITE_OK {
        return LockedBeginOutcome::Failed(FileControlError::SQLite(result));
    }
    #[cfg(test)]
    if !wait_at_begin_test_gate(BeginTestStage::AfterBegin, cancellation, command) {
        let mut rollback_message = std::ptr::null_mut();
        // SAFETY: cancellation is handled by the same locked worker.
        unsafe {
            libsqlite3_sys::sqlite3_exec(
                pointer.as_ptr(),
                c"ROLLBACK".as_ptr(),
                None,
                std::ptr::null_mut(),
                &raw mut rollback_message,
            );
            if !rollback_message.is_null() {
                libsqlite3_sys::sqlite3_free(rollback_message.cast());
            }
        }
        return LockedBeginOutcome::Cancelled;
    }
    let identity = ManualTransactionIdentity {
        database_address: pointer.as_ptr() as usize,
        connection_nonce,
    };
    let accepted_generation = if outcome.send(Ok(identity)).is_ok() {
        match command.recv() {
            Ok(BeginWorkerCommand::Accept(generation)) => Some(generation),
            Err(_) => None,
        }
    } else {
        None
    };
    #[cfg(test)]
    let accept_gate_open = accepted_generation.is_none()
        || wait_at_begin_test_gate(BeginTestStage::AfterAccept, cancellation, command);
    #[cfg(not(test))]
    let accept_gate_open = true;
    if let Some(generation) = accepted_generation
        && accept_gate_open
        && !cancellation.is_expired()
    {
        return match install_transaction_authorizer(pointer, identity, generation) {
            Ok(authorizer_address) => LockedBeginOutcome::Accepted(identity, authorizer_address),
            Err(error) => LockedBeginOutcome::Failed(error),
        };
    }

    let mut rollback_message = std::ptr::null_mut();
    // SAFETY: this worker still owns the same locked handle and transaction.
    unsafe {
        libsqlite3_sys::sqlite3_exec(
            pointer.as_ptr(),
            c"ROLLBACK".as_ptr(),
            None,
            std::ptr::null_mut(),
            &raw mut rollback_message,
        );
        if !rollback_message.is_null() {
            libsqlite3_sys::sqlite3_free(rollback_message.cast());
        }
    }
    LockedBeginOutcome::Cancelled
}

struct BeginWorkerExecutors<'worker> {
    runtime: &'worker tokio::runtime::Runtime,
    terminal_closes: &'worker mut TerminalCloseBatch,
}

fn run_owned_begin_worker<Connection: BeginOwnedConnection>(
    mut connection: Connection,
    outcome: std::sync::mpsc::SyncSender<Result<ManualTransactionIdentity, FileControlError>>,
    command: std::sync::mpsc::Receiver<BeginWorkerCommand>,
    database_slot: Arc<std::sync::Mutex<Option<LiveInterruptPointer>>>,
    restore_busy_timeout: std::time::Duration,
    cancellation: Arc<BeginCancellation>,
    executors: BeginWorkerExecutors<'_>,
) -> BeginWorkerOutput<Connection> {
    let begin = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_locked_begin(
            executors.runtime,
            &mut connection,
            &outcome,
            &command,
            &database_slot,
            restore_busy_timeout,
            &cancellation,
        )
    }));
    let begin = match begin {
        Ok(begin) => begin,
        Err(_) => {
            let _ = outcome.try_send(Err(FileControlError::Handle(
                "BEGIN worker panicked after taking connection ownership".to_owned(),
            )));
            let close = close_owned_begin_connection(executors.terminal_closes, connection);
            return BeginWorkerOutput::Terminal(close);
        }
    };
    match begin {
        LockedBeginOutcome::Accepted(identity, authorizer_address) => {
            BeginWorkerOutput::Accepted(connection, identity, authorizer_address)
        }
        LockedBeginOutcome::Failed(error) => {
            let _ = outcome.try_send(Err(error));
            #[cfg(test)]
            wait_at_begin_failure_cleanup_gate(&cancellation);
            let close = close_owned_begin_connection(executors.terminal_closes, connection);
            BeginWorkerOutput::Terminal(close)
        }
        LockedBeginOutcome::Cancelled => {
            let _ = outcome.try_send(Err(FileControlError::SQLite(
                libsqlite3_sys::SQLITE_INTERRUPT,
            )));
            let close = close_owned_begin_connection(executors.terminal_closes, connection);
            BeginWorkerOutput::Terminal(close)
        }
    }
}

async fn begin_manual_transaction_inner<Connection: BeginOwnedConnection>(
    connection: Connection,
    busy_timeout: std::time::Duration,
    restore_busy_timeout: std::time::Duration,
    external_cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Result<ManualTransaction<Connection>, FileControlError> {
    let operation_deadline = std::time::Instant::now()
        .checked_add(busy_timeout)
        .unwrap_or(std::time::Instant::now());
    let mut owners = BlockingCleanupOwner::acquire_many_until(
        "claw-sqlite-begin-owner",
        2,
        Some(operation_deadline),
    )
    .await
    .map_err(|error| {
        FileControlError::Handle(format!("acquire BEGIN worker and cleanup owners: {error}"))
    })?;
    let cleanup_owner = owners.pop().expect("terminal BEGIN cleanup owner");
    let mut worker_owner = owners.pop().expect("BEGIN worker owner");
    let database = Arc::new(std::sync::Mutex::new(None));
    let worker_database = Arc::clone(&database);
    let cancellation = Arc::new(BeginCancellation {
        local: std::sync::atomic::AtomicBool::new(false),
        external: external_cancellation,
        deadline: operation_deadline,
        #[cfg(test)]
        busy_entered: std::sync::Mutex::new(None),
        #[cfg(test)]
        test_key: std::sync::Mutex::new(None),
    });
    let worker_cancellation = Arc::clone(&cancellation);
    let (outcome_tx, outcome_rx) = std::sync::mpsc::sync_channel(1);
    let (command_tx, command_rx) = std::sync::mpsc::channel();
    let (worker_result_tx, worker_result_rx) = std::sync::mpsc::sync_channel(0);
    worker_owner.handoff(move |runtime, mut terminal_closes| {
        let result = run_owned_begin_worker(
            connection,
            outcome_tx,
            command_rx,
            worker_database,
            restore_busy_timeout,
            worker_cancellation,
            BeginWorkerExecutors {
                runtime,
                terminal_closes: &mut terminal_closes,
            },
        );
        if let Err(error) = worker_result_tx.send(result)
            && let BeginWorkerOutput::Accepted(mut connection, _, authorizer_address) = error.0
        {
            let mut authorizer_address = authorizer_address;
            let _ = runtime.block_on(async {
                let mut handle = connection.sqlite().lock_handle().await?;
                clear_transaction_authorizer(
                    LiveInterruptPointer(handle.as_raw_handle()),
                    &mut authorizer_address,
                )
                .map_err(|error| sqlx::Error::Protocol(error.to_string()))
            });
            let _ = terminal_closes.close_with_authorizer(connection, authorizer_address);
        }
    });
    let mut guard = OwnedBeginGuard {
        worker_result: Some(worker_result_rx),
        command: Some(command_tx),
        database,
        cancellation: Arc::clone(&cancellation),
        cleanup_owner: Some(cleanup_owner),
        armed: true,
    };
    let outcome = loop {
        match outcome_rx.try_recv() {
            Ok(outcome) => break outcome,
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                if cancellation.is_cancelled()
                    || std::time::Instant::now()
                        >= cancellation.deadline + std::time::Duration::from_secs(1)
                {
                    guard.request_cancellation();
                    if let Err(cleanup) = guard.join_failure().await {
                        return Err(FileControlError::Handle(format!(
                            "SQLite BEGIN interrupted; terminal cleanup failed: {cleanup}"
                        )));
                    }
                    return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                guard.join_failure().await?;
                return Err(FileControlError::Handle(
                    "BEGIN worker stopped without an outcome".to_owned(),
                ));
            }
        }
    };
    let identity = match outcome {
        Ok(identity) => identity,
        Err(error) => {
            if cancellation.is_cancelled() {
                drop(guard);
                return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
            }
            if let Err(cleanup) = guard.join_failure().await {
                return Err(FileControlError::Handle(format!(
                    "{error}; terminal cleanup failed: {cleanup}"
                )));
            }
            return Err(error);
        }
    };
    if cancellation.is_expired() {
        drop(guard);
        return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
    }
    let generation = NEXT_MANUAL_TRANSACTION_GENERATION.fetch_add(1, Ordering::Relaxed);
    let generation = generation.max(1);
    let registration = ActiveTransactionRegistration::register(identity, generation)?;
    let (connection, worker_identity, authorizer_address, cleanup_owner) =
        guard.accept(generation).await?;
    debug_assert_eq!(worker_identity, identity);
    let transaction = ManualTransaction {
        connection: Some(TransactionConnection { inner: connection }),
        token: Some(registration.into_token(authorizer_address)),
        cleanup_owner: Some(cleanup_owner),
    };
    if cancellation.is_expired() {
        let cleanup_cutoff = tokio::time::Instant::from_std(
            cancellation.deadline + std::time::Duration::from_secs(1),
        );
        let rollback = tokio::time::timeout_at(cleanup_cutoff, transaction.rollback()).await;
        return Err(match rollback {
            Ok(Ok(_)) => FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT),
            Ok(Err(error)) => FileControlError::Handle(format!(
                "SQLite BEGIN expired after acceptance; terminal rollback failed: {error}"
            )),
            Err(_) => FileControlError::Handle(
                "SQLite BEGIN expired after acceptance; terminal rollback exceeded cleanup cutoff"
                    .to_owned(),
            ),
        });
    }
    Ok(transaction)
}

/// Starts a manual immediate transaction on an owned, non-pool-returnable connection.
pub async fn begin_manual_transaction(
    connection: sqlx::SqliteConnection,
    busy_timeout: std::time::Duration,
    external_cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Result<ManualTransaction<sqlx::SqliteConnection>, FileControlError> {
    begin_manual_transaction_inner(
        connection,
        busy_timeout,
        busy_timeout,
        external_cancellation,
    )
    .await
}

/// Starts a manual immediate transaction while retaining the pool connection lease.
pub async fn begin_manual_pool_transaction(
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    busy_timeout: std::time::Duration,
) -> Result<ManualTransaction<sqlx::pool::PoolConnection<sqlx::Sqlite>>, FileControlError> {
    begin_manual_transaction_inner(connection, busy_timeout, busy_timeout, None).await
}

/// Starts a pool transaction with a temporary BEGIN busy bound and restores the configured bound.
pub async fn begin_manual_pool_transaction_with_restore(
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    begin_busy_timeout: std::time::Duration,
    restore_busy_timeout: std::time::Duration,
    external_cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Result<ManualTransaction<sqlx::pool::PoolConnection<sqlx::Sqlite>>, FileControlError> {
    begin_manual_transaction_inner(
        connection,
        begin_busy_timeout,
        restore_busy_timeout,
        external_cancellation,
    )
    .await
}

/// Commits a transaction created by [`begin_manual_transaction`] synchronously
/// while holding SQLx's connection lock.
async fn commit_synchronously(
    connection: &mut sqlx::SqliteConnection,
    token: &mut ManualTransactionToken,
    cancellation: Option<&BeginCancellation>,
) -> Result<(), FileControlError> {
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    if !token.active {
        return Err(FileControlError::Handle(
            "manual transaction token is no longer active".to_owned(),
        ));
    }
    if database.as_raw_handle().as_ptr() as usize != token.database_address {
        return Err(FileControlError::Handle(
            "manual transaction token belongs to another SQLite connection".to_owned(),
        ));
    }
    if registered_connection_nonce(LiveInterruptPointer(database.as_raw_handle()))
        != Some(token.connection_nonce)
    {
        return Err(FileControlError::Handle(
            "manual transaction token belongs to another SQLite connection lifetime".to_owned(),
        ));
    }
    let key = (token.database_address, token.connection_nonce);
    if ACTIVE_MANUAL_TRANSACTIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
        != Some(&token.generation)
    {
        return Err(FileControlError::Handle(
            "manual transaction token generation is stale".to_owned(),
        ));
    }
    if cancellation.is_some_and(BeginCancellation::is_expired) {
        return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
    }
    let internal_permit = InternalTransactionPermit::activate(token)?;
    let mut message = std::ptr::null_mut();
    // SAFETY: The SQL string is static and NUL-terminated. SQLx's locked handle
    // prevents concurrent worker access for the duration of sqlite3_exec.
    let result = unsafe {
        libsqlite3_sys::sqlite3_exec(
            database.as_raw_handle().as_ptr(),
            c"COMMIT".as_ptr(),
            None,
            std::ptr::null_mut(),
            &raw mut message,
        )
    };
    drop(internal_permit);
    // A failed COMMIT can leave the transaction active (notably SQLITE_BUSY).
    // Invalidate the linear token only once SQLite confirms autocommit.
    let autocommit =
        unsafe { libsqlite3_sys::sqlite3_get_autocommit(database.as_raw_handle().as_ptr()) } != 0;
    let authorizer = if result == libsqlite3_sys::SQLITE_OK || autocommit {
        let authorizer = clear_transaction_authorizer(
            LiveInterruptPointer(database.as_raw_handle()),
            &mut token.authorizer_address,
        );
        if authorizer.is_ok() {
            unregister_manual_transaction(token);
        }
        authorizer
    } else {
        Ok(())
    };
    if !message.is_null() {
        // SAFETY: sqlite3_exec allocates an error message with sqlite3_malloc.
        unsafe {
            libsqlite3_sys::sqlite3_free(message.cast());
        }
    }
    if let Err(error) = authorizer {
        return Err(if result == libsqlite3_sys::SQLITE_OK || autocommit {
            if result == libsqlite3_sys::SQLITE_OK {
                FileControlError::CommittedWithCleanupFailure(error.to_string())
            } else {
                FileControlError::CommitOutcomeUncertain(result, error.to_string())
            }
        } else {
            FileControlError::Handle(format!(
                "SQLite COMMIT failed with code {result}; authorizer cleanup failed: {error}"
            ))
        });
    }
    if result == libsqlite3_sys::SQLITE_OK {
        Ok(())
    } else if autocommit {
        Err(FileControlError::CommitOutcomeUncertain(
            result,
            "autocommit was restored before the error was reported".to_owned(),
        ))
    } else {
        Err(FileControlError::SQLite(result))
    }
}

/// Rolls back a transaction created by [`begin_manual_transaction`] while
/// holding SQLx's connection lock.
async fn rollback_synchronously(
    connection: &mut sqlx::SqliteConnection,
    token: &mut ManualTransactionToken,
) -> Result<(), FileControlError> {
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    if !token.active {
        return Err(FileControlError::Handle(
            "manual transaction token is no longer active".to_owned(),
        ));
    }
    if database.as_raw_handle().as_ptr() as usize != token.database_address {
        return Err(FileControlError::Handle(
            "manual transaction token belongs to another SQLite connection".to_owned(),
        ));
    }
    if registered_connection_nonce(LiveInterruptPointer(database.as_raw_handle()))
        != Some(token.connection_nonce)
    {
        return Err(FileControlError::Handle(
            "manual transaction token belongs to another SQLite connection lifetime".to_owned(),
        ));
    }
    let key = (token.database_address, token.connection_nonce);
    if ACTIVE_MANUAL_TRANSACTIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
        != Some(&token.generation)
    {
        return Err(FileControlError::Handle(
            "manual transaction token generation is stale".to_owned(),
        ));
    }
    let internal_permit = InternalTransactionPermit::activate(token)?;
    let mut message = std::ptr::null_mut();
    // SAFETY: The static SQL is NUL-terminated and the handle is exclusively locked.
    let result = unsafe {
        libsqlite3_sys::sqlite3_exec(
            database.as_raw_handle().as_ptr(),
            c"ROLLBACK".as_ptr(),
            None,
            std::ptr::null_mut(),
            &raw mut message,
        )
    };
    drop(internal_permit);
    let autocommit =
        unsafe { libsqlite3_sys::sqlite3_get_autocommit(database.as_raw_handle().as_ptr()) } != 0;
    let authorizer = if result == libsqlite3_sys::SQLITE_OK || autocommit {
        let authorizer = clear_transaction_authorizer(
            LiveInterruptPointer(database.as_raw_handle()),
            &mut token.authorizer_address,
        );
        if authorizer.is_ok() {
            unregister_manual_transaction(token);
        }
        authorizer
    } else {
        Ok(())
    };
    if !message.is_null() {
        // SAFETY: sqlite3_exec allocated this diagnostic with sqlite3_malloc.
        unsafe {
            libsqlite3_sys::sqlite3_free(message.cast());
        }
    }
    authorizer?;
    if result == libsqlite3_sys::SQLITE_OK {
        Ok(())
    } else {
        Err(FileControlError::SQLite(result))
    }
}

/// Returns whether SQLite currently has no active transaction.
pub async fn is_autocommit(
    connection: &mut sqlx::SqliteConnection,
) -> Result<bool, FileControlError> {
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    // SAFETY: SQLx's locked handle guarantees a live SQLite connection.
    Ok(unsafe { libsqlite3_sys::sqlite3_get_autocommit(database.as_raw_handle().as_ptr()) } != 0)
}

/// Sets SQLite's native busy timeout on one locked connection.
pub async fn set_busy_timeout(
    connection: &mut sqlx::SqliteConnection,
    timeout: std::time::Duration,
) -> Result<(), FileControlError> {
    let milliseconds = i32::try_from(timeout.as_millis())
        .map_err(|_| FileControlError::Handle("busy timeout is too large".to_owned()))?;
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    // SAFETY: SQLx's locked handle guarantees a live SQLite connection.
    let result = unsafe {
        libsqlite3_sys::sqlite3_busy_timeout(database.as_raw_handle().as_ptr(), milliseconds)
    };
    if result == libsqlite3_sys::SQLITE_OK {
        Ok(())
    } else {
        Err(FileControlError::SQLite(result))
    }
}

/// Installs a commit hook that rolls back if SQLite's main file was moved.
#[cfg(unix)]
pub async fn install_moved_commit_guard(
    connection: &mut sqlx::SqliteConnection,
) -> Result<(), FileControlError> {
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let database = database.as_raw_handle();
    // SAFETY: SQLx's locked handle is live for registration. SQLite stores the
    // connection pointer as callback context and removes the hook on close.
    unsafe {
        libsqlite3_sys::sqlite3_commit_hook(
            database.as_ptr(),
            Some(reject_moved_commit),
            database.as_ptr().cast(),
        );
    }
    Ok(())
}

/// Installs a commit hook that also binds a Unix lock pathname to the held lock inode.
#[cfg(unix)]
pub async fn install_identity_commit_guard(
    connection: &mut sqlx::SqliteConnection,
    database_parent: (&std::path::Path, &std::fs::File),
    database: (&std::path::Path, &std::fs::File),
    lock: (&std::path::Path, &std::fs::File),
    expected_identity: &[u8],
    writer_generation: (Arc<AtomicU64>, u64),
) -> Result<(), FileControlError> {
    let (database_parent_path, database_parent) = database_parent;
    let (database_path, database_file) = database;
    let (lock_path, lock_file) = lock;
    let (writer_generation, expected_writer_generation) = writer_generation;
    let database_parent = database_parent
        .try_clone()
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let database_file = database_file
        .try_clone()
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let expected_uid = {
        use std::os::unix::fs::MetadataExt as _;
        database_file
            .metadata()
            .map_err(|error| FileControlError::Handle(error.to_string()))?
            .uid()
    };
    let lock_file = lock_file
        .try_clone()
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let sidecars = unix_pinned_sidecars(database_path, expected_identity, expected_uid)?;
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let database = database.as_raw_handle();
    let context = Box::new(IdentityCommitContext {
        database,
        database_parent_path: database_parent_path.to_owned(),
        database_parent,
        database_path: database_path.to_owned(),
        database_file,
        lock_path: lock_path.to_owned(),
        lock_file,
        expected_identity: expected_identity.to_vec(),
        expected_uid,
        sidecars,
        writer_generation,
        expected_writer_generation,
    });
    let context = Box::into_raw(context);
    // SAFETY: SQLite assumes ownership of the boxed context and invokes the
    // destructor exactly once on registration failure, replacement, or close.
    let registered = unsafe {
        libsqlite3_sys::sqlite3_set_clientdata(
            database.as_ptr(),
            c"gta-claw-commit-identity".as_ptr(),
            context.cast(),
            Some(drop_identity_commit_context),
        )
    };
    if registered != libsqlite3_sys::SQLITE_OK {
        return Err(FileControlError::SQLite(registered));
    }
    // SAFETY: The client-data context remains owned by this live SQLite
    // connection until close. Reinstalling this hook replaces only the hook,
    // not the named client data.
    unsafe {
        libsqlite3_sys::sqlite3_commit_hook(
            database.as_ptr(),
            Some(reject_moved_or_unbound_commit),
            context.cast(),
        );
    }
    Ok(())
}

#[cfg(unix)]
struct IdentityCommitContext {
    database: NonNull<libsqlite3_sys::sqlite3>,
    database_parent_path: std::path::PathBuf,
    database_parent: std::fs::File,
    database_path: std::path::PathBuf,
    database_file: std::fs::File,
    lock_path: std::path::PathBuf,
    lock_file: std::fs::File,
    expected_identity: Vec<u8>,
    expected_uid: u32,
    sidecars: Vec<PinnedSidecar>,
    writer_generation: Arc<AtomicU64>,
    expected_writer_generation: u64,
}

#[cfg(any(unix, windows))]
struct PinnedSidecar {
    path: std::path::PathBuf,
    file: std::fs::File,
}

#[cfg(unix)]
unsafe extern "C" fn drop_identity_commit_context(context: *mut std::ffi::c_void) {
    if !context.is_null() {
        // SAFETY: sqlite3_set_clientdata invokes this exactly once for the Box
        // allocated by install_identity_commit_guard.
        drop(unsafe { Box::from_raw(context.cast::<IdentityCommitContext>()) });
    }
}

#[cfg(unix)]
unsafe extern "C" fn reject_moved_or_unbound_commit(context: *mut std::ffi::c_void) -> i32 {
    let Some(context) = NonNull::new(context.cast::<IdentityCommitContext>()) else {
        return 1;
    };
    // SAFETY: SQLite invokes the hook only while its client-data context and
    // connection are live.
    let context = unsafe { context.as_ref() };
    let valid = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        !database_has_moved(context.database) && unix_identity_matches(context)
    }))
    .unwrap_or(false);
    i32::from(!valid)
}

#[cfg(unix)]
fn unix_identity_matches(context: &IdentityCommitContext) -> bool {
    use std::os::unix::fs::FileExt as _;
    use xattr::FileExt as _;

    if context.writer_generation.load(Ordering::Acquire) != context.expected_writer_generation
        || !unix_path_matches_private_directory(
            &context.database_parent_path,
            &context.database_parent,
            context.expected_uid,
        )
        || !unix_path_matches_private_file(
            &context.database_path,
            &context.database_file,
            0o600,
            context.expected_uid,
        )
        || !unix_path_matches_private_file(
            &context.lock_path,
            &context.lock_file,
            0o600,
            context.expected_uid,
        )
    {
        return false;
    }
    let Ok(Some(identity)) = context
        .database_file
        .get_xattr("user.gta-claw.writer-lock-path")
    else {
        return false;
    };
    if identity != context.expected_identity {
        return false;
    }
    for sidecar in &context.sidecars {
        let expected_generation = unix_sidecar_generation_record(
            &context.database_path,
            &sidecar.path,
            &context.expected_identity,
        );
        if !unix_path_matches_private_file(
            &sidecar.path,
            &sidecar.file,
            0o600,
            context.expected_uid,
        ) || !matches!(
            sidecar
                .file
                .get_xattr("user.gta-claw.sidecar-generation"),
            Ok(Some(generation)) if generation == expected_generation
        ) {
            return false;
        }
    }
    let mut journal = context.database_path.as_os_str().to_owned();
    journal.push("-journal");
    if !unix_sidecar_matches_generation(
        &context.database_path,
        std::path::Path::new(&journal),
        context.expected_uid,
        &context.expected_identity,
        false,
    ) {
        return false;
    }
    let Ok(metadata) = context.lock_file.metadata() else {
        return false;
    };
    if usize::try_from(metadata.len()).ok() != Some(context.expected_identity.len()) {
        return false;
    }

    #[cfg(unix)]
    fn unix_path_matches_private_directory(
        path: &std::path::Path,
        file: &std::fs::File,
        expected_uid: u32,
    ) -> bool {
        use std::os::unix::fs::MetadataExt as _;

        let Ok(held) = file.metadata() else {
            return false;
        };
        let Ok(current) = std::fs::symlink_metadata(path) else {
            return false;
        };
        held.file_type().is_dir()
            && current.file_type().is_dir()
            && held.dev() == current.dev()
            && held.ino() == current.ino()
            && held.uid() == expected_uid
            && current.uid() == expected_uid
            && unix_file_is_service_private(file, expected_uid, 0o700).unwrap_or(false)
    }

    #[cfg(unix)]
    fn unix_sidecar_matches_generation(
        database_path: &std::path::Path,
        path: &std::path::Path,
        expected_uid: u32,
        expected_identity: &[u8],
        required: bool,
    ) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        use xattr::FileExt as _;

        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return !required,
            Err(_) => return false,
            Ok(metadata) if metadata.file_type().is_symlink() => return false,
            Ok(_) => {}
        }
        let Ok(file) = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map(std::fs::File::from) else {
            return false;
        };
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        if !metadata.file_type().is_file()
            || !unix_file_is_service_private(&file, expected_uid, 0o600).unwrap_or(false)
            || metadata.nlink() != 1
        {
            return false;
        }
        let expected_generation =
            unix_sidecar_generation_record(database_path, path, expected_identity);
        matches!(
            file.get_xattr("user.gta-claw.sidecar-generation"),
            Ok(Some(generation)) if generation == expected_generation
        )
    }
    let mut contents = vec![0_u8; context.expected_identity.len()];
    match context.lock_file.read_at(&mut contents, 0) {
        Ok(read) => read == contents.len() && contents == context.expected_identity,
        Err(_) => false,
    }
}

#[cfg(unix)]
fn unix_pinned_sidecars(
    database_path: &std::path::Path,
    expected_identity: &[u8],
    expected_uid: u32,
) -> Result<Vec<PinnedSidecar>, FileControlError> {
    use std::os::unix::fs::MetadataExt as _;
    use xattr::FileExt as _;

    ["-wal", "-shm"]
        .into_iter()
        .map(|suffix| {
            let mut path = database_path.as_os_str().to_owned();
            path.push(suffix);
            let path = std::path::PathBuf::from(path);
            let file = rustix::fs::open(
                &path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::empty(),
            )
            .map(std::fs::File::from)
            .map_err(|error| FileControlError::Handle(error.to_string()))?;
            let metadata = file
                .metadata()
                .map_err(|error| FileControlError::Handle(error.to_string()))?;
            let expected_generation =
                unix_sidecar_generation_record(database_path, &path, expected_identity);
            if !metadata.file_type().is_file()
                || !unix_file_is_service_private(&file, expected_uid, 0o600).unwrap_or(false)
                || metadata.nlink() != 1
                || !matches!(
                    file.get_xattr("user.gta-claw.sidecar-generation"),
                    Ok(Some(generation)) if generation == expected_generation
                )
            {
                return Err(FileControlError::Handle(
                    "SQLite sidecar identity is not private and generation-bound".to_owned(),
                ));
            }
            Ok(PinnedSidecar { path, file })
        })
        .collect()
}

#[cfg(unix)]
fn unix_path_matches_private_file(
    path: &std::path::Path,
    file: &std::fs::File,
    expected_mode: u32,
    expected_uid: u32,
) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    let Ok(held) = file.metadata() else {
        return false;
    };
    let Ok(current) = std::fs::symlink_metadata(path) else {
        return false;
    };
    held.file_type().is_file()
        && current.file_type().is_file()
        && !current.file_type().is_symlink()
        && current.dev() == held.dev()
        && current.ino() == held.ino()
        && current.uid() == expected_uid
        && unix_file_is_service_private(file, expected_uid, expected_mode).unwrap_or(false)
        && held.nlink() == 1
        && current.nlink() == 1
}

/// Installs a Windows commit hook bound to held database/lock handles and lock generation.
#[cfg(windows)]
pub async fn install_windows_identity_commit_guard(
    connection: &mut sqlx::SqliteConnection,
    database_parent: (&std::path::Path, &std::fs::File),
    database: (&std::path::Path, &std::fs::File),
    lock: (&std::path::Path, &std::fs::File),
    expected_identity: &[u8],
    writer_generation: (Arc<AtomicU64>, u64),
) -> Result<(), FileControlError> {
    let (database_parent_path, database_parent) = database_parent;
    let (database_path, database_file) = database;
    let (lock_path, lock_file) = lock;
    let (writer_generation, expected_writer_generation) = writer_generation;
    let database_parent = database_parent
        .try_clone()
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let database_file = database_file
        .try_clone()
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let lock_file = lock_file
        .try_clone()
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let sidecars = windows_pinned_sidecars(database_path, expected_identity)?;
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let database = database.as_raw_handle();
    let context = Box::new(WindowsIdentityCommitContext {
        database_parent_path: database_parent_path.to_owned(),
        database_parent,
        database_path: database_path.to_owned(),
        database_file,
        lock_path: lock_path.to_owned(),
        lock_file,
        expected_identity: expected_identity.to_vec(),
        sidecars,
        writer_generation,
        expected_writer_generation,
    });
    let context = Box::into_raw(context);
    // SAFETY: SQLite owns the context and invokes its destructor exactly once.
    let registered = unsafe {
        libsqlite3_sys::sqlite3_set_clientdata(
            database.as_ptr(),
            c"gta-claw-windows-commit-identity".as_ptr(),
            context.cast(),
            Some(drop_windows_identity_commit_context),
        )
    };
    if registered != libsqlite3_sys::SQLITE_OK {
        return Err(FileControlError::SQLite(registered));
    }
    // SAFETY: The registered context remains live until connection close.
    unsafe {
        libsqlite3_sys::sqlite3_commit_hook(
            database.as_ptr(),
            Some(reject_unbound_windows_commit),
            context.cast(),
        );
    }
    Ok(())
}

#[cfg(windows)]
struct WindowsIdentityCommitContext {
    database_parent_path: std::path::PathBuf,
    database_parent: std::fs::File,
    database_path: std::path::PathBuf,
    database_file: std::fs::File,
    lock_path: std::path::PathBuf,
    lock_file: std::fs::File,
    expected_identity: Vec<u8>,
    sidecars: Vec<PinnedSidecar>,
    writer_generation: Arc<AtomicU64>,
    expected_writer_generation: u64,
}

#[cfg(windows)]
unsafe extern "C" fn drop_windows_identity_commit_context(context: *mut std::ffi::c_void) {
    if !context.is_null() {
        // SAFETY: sqlite3_set_clientdata calls this once for the allocated Box.
        drop(unsafe { Box::from_raw(context.cast::<WindowsIdentityCommitContext>()) });
    }
}

#[cfg(windows)]
unsafe extern "C" fn reject_unbound_windows_commit(context: *mut std::ffi::c_void) -> i32 {
    let Some(context) = NonNull::new(context.cast::<WindowsIdentityCommitContext>()) else {
        return 1;
    };
    // SAFETY: SQLite invokes this while the client-data context is live.
    let context = unsafe { context.as_ref() };
    let valid = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        windows_identity_matches(context)
    }))
    .unwrap_or(false);
    i32::from(!valid)
}

#[cfg(windows)]
fn read_windows_generation(
    path: std::path::PathBuf,
    expected_len: usize,
) -> Result<Vec<u8>, FileControlError> {
    use std::io::Read as _;

    let mut file =
        std::fs::File::open(path).map_err(|error| FileControlError::Handle(error.to_string()))?;
    if file
        .metadata()
        .map_err(|error| FileControlError::Handle(error.to_string()))?
        .len()
        != u64::try_from(expected_len)
            .map_err(|_| FileControlError::Handle("generation length is too large".to_owned()))?
    {
        return Err(FileControlError::Handle(
            "Windows sidecar generation has an invalid length".to_owned(),
        ));
    }
    let mut generation = vec![0_u8; expected_len];
    file.read_exact(&mut generation)
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|error| FileControlError::Handle(error.to_string()))?
        != 0
    {
        return Err(FileControlError::Handle(
            "Windows sidecar generation exceeds its expected length".to_owned(),
        ));
    }
    Ok(generation)
}

#[cfg(windows)]
fn windows_identity_matches(context: &WindowsIdentityCommitContext) -> bool {
    use std::os::windows::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    if context.writer_generation.load(Ordering::Acquire) != context.expected_writer_generation {
        return false;
    }
    let open_current = |path: &std::path::Path, directory: bool| {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    },
            )
            .open(path)?;
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::other(
                "Windows commit identity path is a reparse point",
            ));
        }
        Ok(file)
    };
    let Ok(parent_current) = open_current(&context.database_parent_path, true) else {
        return false;
    };
    let Ok(database_current) = open_current(&context.database_path, false) else {
        return false;
    };
    let Ok(lock_current) = open_current(&context.lock_path, false) else {
        return false;
    };
    let Ok(parent_expected) = windows_file_identity(&context.database_parent) else {
        return false;
    };
    let Ok(parent_actual) = windows_file_identity(&parent_current) else {
        return false;
    };
    let Ok(database_expected) = windows_file_identity(&context.database_file) else {
        return false;
    };
    let Ok(database_actual) = windows_file_identity(&database_current) else {
        return false;
    };
    let Ok(lock_expected) = windows_file_identity(&context.lock_file) else {
        return false;
    };
    let Ok(lock_actual) = windows_file_identity(&lock_current) else {
        return false;
    };
    if parent_expected != parent_actual
        || database_expected != database_actual
        || lock_expected != lock_actual
        || !windows_file_is_service_private(&context.database_parent).unwrap_or(false)
        || !windows_file_is_service_private(&context.database_file).unwrap_or(false)
        || !windows_file_is_service_private(&context.lock_file).unwrap_or(false)
    {
        return false;
    }
    let Ok(length) = context.lock_file.metadata().map(|metadata| metadata.len()) else {
        return false;
    };
    if usize::try_from(length).ok() != Some(context.expected_identity.len()) {
        return false;
    }
    let mut contents = vec![0_u8; context.expected_identity.len()];
    let header_matches = match context.lock_file.seek_read(&mut contents, 0) {
        Ok(read) => read == contents.len() && contents == context.expected_identity,
        Err(_) => false,
    };
    if !header_matches {
        return false;
    }
    for sidecar in &context.sidecars {
        let Ok(current) = open_current(&sidecar.path, false) else {
            return false;
        };
        let Ok(current_identity) = windows_file_identity(&current) else {
            return false;
        };
        let Ok(expected_identity) = windows_file_identity(&sidecar.file) else {
            return false;
        };
        if current_identity != expected_identity
            || !windows_file_is_service_private(&sidecar.file).unwrap_or(false)
        {
            return false;
        }
        let mut generation_path = sidecar.path.as_os_str().to_owned();
        generation_path.push(":gta-claw-generation");
        let expected_record = windows_sidecar_generation_record(&context.expected_identity);
        let Ok(generation) = read_windows_generation(
            std::path::PathBuf::from(generation_path),
            expected_record.len(),
        ) else {
            return false;
        };
        if generation != expected_record {
            return false;
        }
    }
    let mut journal_path = context.database_path.as_os_str().to_owned();
    journal_path.push("-journal");
    let journal_path = std::path::PathBuf::from(journal_path);
    match open_current(&journal_path, false) {
        Ok(journal) => {
            if windows_file_identity(&journal).is_err()
                || !windows_file_is_service_private(&journal).unwrap_or(false)
            {
                return false;
            }
            let mut generation_path = journal_path.as_os_str().to_owned();
            generation_path.push(":gta-claw-generation");
            let expected_record = windows_sidecar_generation_record(&context.expected_identity);
            let Ok(generation) = read_windows_generation(
                std::path::PathBuf::from(generation_path),
                expected_record.len(),
            ) else {
                return false;
            };
            if generation != expected_record {
                return false;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return false,
    }
    true
}

#[cfg(windows)]
fn windows_pinned_sidecars(
    database_path: &std::path::Path,
    expected_identity: &[u8],
) -> Result<Vec<PinnedSidecar>, FileControlError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    ["-wal", "-shm"]
        .into_iter()
        .map(|suffix| {
            let mut path = database_path.as_os_str().to_owned();
            path.push(suffix);
            let path = std::path::PathBuf::from(path);
            let file = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)
                .map_err(|error| FileControlError::Handle(error.to_string()))?;
            if file
                .metadata()
                .map_err(|error| FileControlError::Handle(error.to_string()))?
                .file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            {
                return Err(FileControlError::Handle(
                    "Windows SQLite sidecar is a reparse point".to_owned(),
                ));
            }
            if !windows_file_is_service_private(&file)
                .map_err(|error| FileControlError::Handle(error.to_string()))?
            {
                return Err(FileControlError::Handle(
                    "Windows SQLite sidecar is not service-private".to_owned(),
                ));
            }
            let mut generation_path = path.as_os_str().to_owned();
            generation_path.push(":gta-claw-generation");
            let expected_record = windows_sidecar_generation_record(expected_identity);
            let generation = read_windows_generation(
                std::path::PathBuf::from(generation_path),
                expected_record.len(),
            )?;
            if generation != expected_record {
                return Err(FileControlError::Handle(
                    "Windows SQLite sidecar generation changed".to_owned(),
                ));
            }
            Ok(PinnedSidecar { path, file })
        })
        .collect()
}

#[cfg(unix)]
unsafe extern "C" fn reject_moved_commit(context: *mut std::ffi::c_void) -> i32 {
    let Some(database) = NonNull::new(context.cast::<libsqlite3_sys::sqlite3>()) else {
        return 1;
    };
    i32::from(database_has_moved(database))
}

#[cfg(unix)]
fn database_has_moved(database: NonNull<libsqlite3_sys::sqlite3>) -> bool {
    let mut moved = 0_i32;
    // SAFETY: Callers hold a live SQLite connection. The output pointer remains
    // valid for this call.
    let result = unsafe {
        libsqlite3_sys::sqlite3_file_control(
            database.as_ptr(),
            c"main".as_ptr(),
            libsqlite3_sys::SQLITE_FCNTL_HAS_MOVED,
            (&raw mut moved).cast(),
        )
    };
    result != libsqlite3_sys::SQLITE_OK || moved != 0
}

/// Protects bytes with the current Windows user's DPAPI credentials.
#[cfg(windows)]
pub fn protect_for_current_windows_user(data: &[u8]) -> Result<Vec<u8>, FileControlError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };

    let input_length = u32::try_from(data.len())
        .map_err(|_| FileControlError::Handle("DPAPI input is too large".to_owned()))?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_length,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: The input slice remains live for the call. DPAPI initializes the
    // output blob on success; its LocalAlloc buffer is copied and freed below.
    let protected = unsafe {
        CryptProtectData(
            &raw const input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    };
    if protected == 0 {
        return Err(FileControlError::Handle(format!(
            "DPAPI protection failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: DPAPI returned a valid buffer of cbData bytes on success.
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    // SAFETY: DPAPI allocates the output with LocalAlloc.
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(bytes)
}

/// Unprotects bytes with the current Windows user's DPAPI credentials.
#[cfg(windows)]
pub fn unprotect_for_current_windows_user(data: &[u8]) -> Result<Vec<u8>, FileControlError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let input_length = u32::try_from(data.len())
        .map_err(|_| FileControlError::Handle("DPAPI input is too large".to_owned()))?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_length,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: The input slice remains live for the call. DPAPI initializes the
    // output blob on success; its LocalAlloc buffer is copied and freed below.
    let unprotected = unsafe {
        CryptUnprotectData(
            &raw const input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    };
    if unprotected == 0 {
        return Err(FileControlError::Handle(format!(
            "DPAPI unprotection failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: DPAPI returned a valid buffer of cbData bytes on success.
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    // SAFETY: DPAPI allocates the output with LocalAlloc.
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(bytes)
}

/// Returns the Windows volume serial and 128-bit file identifier.
#[cfg(windows)]
pub fn windows_file_identity(file: &std::fs::File) -> Result<[u8; 24], FileControlError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let mut information = FILE_ID_INFO::default();
    // SAFETY: The file handle is live, and the output points to a correctly
    // sized FILE_ID_INFO for the requested information class.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut information).cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO size fits u32"),
        )
    };
    if succeeded == 0 {
        return Err(FileControlError::Handle(format!(
            "Windows file identity query failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut identity = [0_u8; 24];
    identity[..8].copy_from_slice(&information.VolumeSerialNumber.to_le_bytes());
    identity[8..].copy_from_slice(&information.FileId.Identifier);
    Ok(identity)
}

/// Tries to lock a private marker byte outside ordinary file contents.
#[cfg(windows)]
pub fn windows_try_lock_writer_marker(file: &std::fs::File) -> std::io::Result<bool> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::LockFile;

    // SAFETY: The borrowed file handle remains live for the call. The
    // one-byte range ends at u64::MAX and is intentionally beyond file data.
    let locked = unsafe { LockFile(file.as_raw_handle(), u32::MAX - 1, u32::MAX, 1, 0) };
    if locked != 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(33) {
        Ok(false)
    } else {
        Err(error)
    }
}

/// Returns whether a Windows file is owned by the current service identity and
/// grants no write/delete authority to other non-administrative principals.
#[cfg(windows)]
pub fn windows_file_is_service_private(file: &std::fs::File) -> Result<bool, FileControlError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
        GetSecurityDescriptorControl, GetTokenInformation, IsWellKnownSid,
        OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle valid for this call;
    // token points to writable storage.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(FileControlError::Handle(format!(
            "open current process token: {}",
            std::io::Error::last_os_error()
        )));
    }
    let result = (|| {
        let mut required = 0_u32;
        // SAFETY: The null probe is the documented way to obtain buffer size.
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &raw mut required);
        }
        if required == 0 {
            return Err(FileControlError::Handle(format!(
                "size current token user: {}",
                std::io::Error::last_os_error()
            )));
        }
        let word = std::mem::size_of::<usize>();
        let words = usize::try_from(required)
            .map_err(|_| FileControlError::Handle("token user buffer is too large".to_owned()))?
            .div_ceil(word);
        let mut token_buffer = vec![0_usize; words];
        // SAFETY: The aligned buffer is at least `required` bytes and writable.
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                token_buffer.as_mut_ptr().cast(),
                required,
                &raw mut required,
            )
        } == 0
        {
            return Err(FileControlError::Handle(format!(
                "read current token user: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: GetTokenInformation initialized a TOKEN_USER at the buffer start.
        let current_sid = unsafe { (*(token_buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };

        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: The file handle is live and all output pointers are writable.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &raw mut owner,
                std::ptr::null_mut(),
                &raw mut dacl,
                std::ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        if status != 0 {
            return Err(FileControlError::Handle(format!(
                "read file security descriptor: Windows error {status}"
            )));
        }
        let private = (|| {
            if owner.is_null()
                || dacl.is_null()
                // SAFETY: Both SIDs come from live token/security buffers.
                || unsafe { EqualSid(owner, current_sid) } == 0
            {
                return Ok(false);
            }
            let mut control = 0_u16;
            let mut revision = 0_u32;
            if unsafe {
                GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
            } == 0
                || control & SE_DACL_PROTECTED == 0
            {
                return Ok(false);
            }
            let mut acl_info = ACL_SIZE_INFORMATION::default();
            // SAFETY: dacl is owned by descriptor and acl_info is writable.
            if unsafe {
                GetAclInformation(
                    dacl,
                    (&raw mut acl_info).cast(),
                    u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>())
                        .expect("ACL_SIZE_INFORMATION size fits u32"),
                    AclSizeInformation,
                )
            } == 0
            {
                return Err(FileControlError::Handle(format!(
                    "inspect file DACL: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let mut current_seen = false;
            let mut system_seen = false;
            let mut administrators_seen = false;
            for index in 0..acl_info.AceCount {
                let mut ace = std::ptr::null_mut();
                // SAFETY: index is within AceCount and ace is writable.
                if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 {
                    return Err(FileControlError::Handle(format!(
                        "read file DACL entry: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                // Standard access-allowed ACE type is zero.
                // SAFETY: GetAce returned a valid ACE pointer.
                let header = unsafe { &*(ace.cast::<windows_sys::Win32::Security::ACE_HEADER>()) };
                if header.AceType != 0 || header.AceFlags != 0 {
                    return Ok(false);
                }
                // SAFETY: A type-zero ACE has ACCESS_ALLOWED_ACE layout.
                let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
                if allowed.Mask != FILE_ALL_ACCESS {
                    return Ok(false);
                }
                let sid = (&raw const allowed.SidStart).cast_mut().cast();
                // SAFETY: sid points into the live ACE and current_sid is live.
                let (is_current, is_system, is_administrators) = unsafe {
                    (
                        EqualSid(sid, current_sid) != 0,
                        IsWellKnownSid(sid, WinLocalSystemSid) != 0,
                        IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0,
                    )
                };
                if !is_current && !is_system && !is_administrators {
                    return Ok(false);
                }
                if (is_current && current_seen)
                    || (is_system && system_seen)
                    || (is_administrators && administrators_seen)
                {
                    return Ok(false);
                }
                current_seen |= is_current;
                system_seen |= is_system;
                administrators_seen |= is_administrators;
            }
            Ok(current_seen && system_seen && administrators_seen)
        })();
        // SAFETY: GetSecurityInfo allocated descriptor with LocalAlloc.
        unsafe {
            LocalFree(descriptor);
        }
        private
    })();
    // SAFETY: OpenProcessToken returned an owned token handle.
    unsafe {
        CloseHandle(token);
    }
    result
}

/// Applies a protected current-service owner/DACL to a newly created Windows file.
#[cfg(windows)]
pub fn secure_new_windows_file(file: &std::fs::File) -> Result<(), FileControlError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetTokenInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetKernelObjectSecurity,
        TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(FileControlError::Handle(format!(
            "open current process token for file security: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut sid_string = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let result = (|| {
        let mut required = 0_u32;
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &raw mut required);
        }
        if required == 0 {
            return Err(FileControlError::Handle(format!(
                "size current token user for file security: {}",
                std::io::Error::last_os_error()
            )));
        }
        let word = std::mem::size_of::<usize>();
        let words = usize::try_from(required)
            .map_err(|_| FileControlError::Handle("token user buffer is too large".to_owned()))?
            .div_ceil(word);
        let mut token_buffer = vec![0_usize; words];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                token_buffer.as_mut_ptr().cast(),
                required,
                &raw mut required,
            )
        } == 0
        {
            return Err(FileControlError::Handle(format!(
                "read current token user for file security: {}",
                std::io::Error::last_os_error()
            )));
        }
        let current_sid = unsafe { (*(token_buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };
        if unsafe { ConvertSidToStringSidW(current_sid, &raw mut sid_string) } == 0 {
            return Err(FileControlError::Handle(format!(
                "render current SID for file security: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut length = 0_usize;
        while unsafe { *sid_string.add(length) } != 0 {
            length += 1;
        }
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_string, length) })
            .map_err(|_| FileControlError::Handle("current SID is not valid UTF-16".to_owned()))?;
        let mut aces = format!("(A;;FA;;;{sid})");
        if unsafe { IsWellKnownSid(current_sid, WinLocalSystemSid) } == 0 {
            aces.push_str("(A;;FA;;;SY)");
        }
        if unsafe { IsWellKnownSid(current_sid, WinBuiltinAdministratorsSid) } == 0 {
            aces.push_str("(A;;FA;;;BA)");
        }
        let sddl = format!("O:{sid}D:P{aces}");
        let mut encoded = sddl.encode_utf16().collect::<Vec<_>>();
        encoded.push(0);
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                encoded.as_ptr(),
                1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(FileControlError::Handle(format!(
                "build protected file security descriptor: {}",
                std::io::Error::last_os_error()
            )));
        }
        if unsafe {
            SetKernelObjectSecurity(
                file.as_raw_handle(),
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        } == 0
        {
            return Err(FileControlError::Handle(format!(
                "apply protected file security descriptor: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    })();
    unsafe {
        if !descriptor.is_null() {
            LocalFree(descriptor);
        }
        if !sid_string.is_null() {
            LocalFree(sid_string.cast());
        }
        CloseHandle(token);
    }
    result
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use sqlx::{Connection as _, Executor as _, Row as _};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct StallingPoolConnection {
        connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
        entered: Arc<AtomicUsize>,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }

    impl BeginOwnedConnection for StallingPoolConnection {
        fn sqlite_ref(&self) -> &sqlx::SqliteConnection {
            &self.connection
        }

        fn sqlite(&mut self) -> &mut sqlx::SqliteConnection {
            &mut self.connection
        }

        fn close_on_runtime(self, runtime: &tokio::runtime::Runtime) -> Result<(), String> {
            self.entered.fetch_add(1, Ordering::AcqRel);
            let (released, changed) = &*self.release;
            let mut released = released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*released {
                released = changed
                    .wait(released)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            drop(released);
            runtime
                .block_on(self.connection.close())
                .map_err(|error| error.to_string())
        }
    }

    async fn manual_transaction_connection(path: &std::path::Path) -> sqlx::SqliteConnection {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .busy_timeout(std::time::Duration::from_millis(500));
        sqlx::SqliteConnection::connect_with(&options)
            .await
            .expect("open manual transaction fixture")
    }

    async fn commit_delivery_fixture(
        path: &std::path::Path,
        owner: &str,
        max_connections: u32,
    ) -> (
        sqlx::SqlitePool,
        ManualTransaction<sqlx::pool::PoolConnection<sqlx::Sqlite>>,
    ) {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .busy_timeout(std::time::Duration::from_millis(500));
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_with(options)
            .await
            .expect("open COMMIT delivery pool");
        sqlx::raw_sql(
            "CREATE TABLE claw_writer_lock(
               singleton INTEGER PRIMARY KEY,
               owner TEXT NOT NULL,
               acquired_at_ms INTEGER NOT NULL
             );
             CREATE TABLE payload(value INTEGER NOT NULL);",
        )
        .execute(&pool)
        .await
        .expect("create COMMIT delivery fixture");
        sqlx::query(
            "INSERT INTO claw_writer_lock(singleton, owner, acquired_at_ms)
             VALUES (1, ?, 0)",
        )
        .bind(owner)
        .execute(&pool)
        .await
        .expect("seed COMMIT delivery owner");
        let connection = pool.acquire().await.expect("acquire COMMIT delivery owner");
        let mut transaction =
            begin_manual_pool_transaction(connection, std::time::Duration::from_secs(1))
                .await
                .expect("begin COMMIT delivery transaction");
        transaction
            .execute("INSERT INTO payload VALUES (1)")
            .await
            .expect("stage COMMIT delivery row");
        (pool, transaction)
    }

    struct CommitResultTestRegistration {
        owner: String,
        _executor_serial: tokio::sync::OwnedMutexGuard<()>,
    }

    impl Drop for CommitResultTestRegistration {
        fn drop(&mut self) {
            COMMIT_RESULT_TEST_GATES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.owner);
        }
    }

    async fn install_commit_result_gate(
        owner: &str,
    ) -> (
        CommitResultTestRegistration,
        Arc<tokio::sync::Notify>,
        Arc<AtomicBool>,
    ) {
        let executor_serial = Arc::clone(&EXECUTOR_TEST_SERIAL).lock_owned().await;
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(AtomicBool::new(false));
        let replaced = COMMIT_RESULT_TEST_GATES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                owner.to_owned(),
                CommitResultTestGate {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                },
            );
        assert!(replaced.is_none(), "COMMIT result gate must be unique");
        (
            CommitResultTestRegistration {
                owner: owner.to_owned(),
                _executor_serial: executor_serial,
            },
            entered,
            release,
        )
    }

    struct BeginTestRegistration {
        key: BeginTestKey,
        _serial: tokio::sync::OwnedMutexGuard<()>,
    }

    impl Drop for BeginTestRegistration {
        fn drop(&mut self) {
            BEGIN_TEST_GATE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.key);
            BEGIN_BUSY_OBSERVERS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.key);
            let mut pending = PENDING_BEGIN_TEST_KEYS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if pending.get(&self.key.connection_nonce) == Some(&self.key) {
                pending.remove(&self.key.connection_nonce);
            }
        }
    }

    fn normalize_begin_test_path(path: &std::path::Path) -> String {
        #[cfg(windows)]
        {
            path.to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase()
        }
        #[cfg(not(windows))]
        {
            path.to_string_lossy().into_owned()
        }
    }

    async fn register_begin_test<Connection: BeginOwnedConnection>(
        connection: &mut Connection,
        path: &std::path::Path,
        operation: BeginTestOperation,
    ) -> BeginTestRegistration {
        let serial = Arc::clone(&BEGIN_TEST_SERIAL).lock_owned().await;
        let connection_nonce = {
            let mut handle = connection
                .sqlite()
                .lock_handle()
                .await
                .expect("lock predispatch BEGIN test connection");
            connection_lifetime_nonce(LiveInterruptPointer(handle.as_raw_handle()))
                .expect("register predispatch BEGIN connection nonce")
        };
        let key = BeginTestKey {
            path: normalize_begin_test_path(path),
            connection_nonce,
            operation_generation: NEXT_BEGIN_TEST_GENERATION
                .fetch_add(1, Ordering::Relaxed)
                .max(1),
            operation,
        };
        let replaced = PENDING_BEGIN_TEST_KEYS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(connection_nonce, key.clone());
        assert!(
            replaced.is_none(),
            "BEGIN test registration must be unique per connection"
        );
        BeginTestRegistration {
            key,
            _serial: serial,
        }
    }

    async fn install_begin_gate<Connection: BeginOwnedConnection>(
        stage: BeginTestStage,
        connection: &mut Connection,
        path: &std::path::Path,
    ) -> (
        BeginTestRegistration,
        Arc<tokio::sync::Notify>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let registration =
            register_begin_test(connection, path, BeginTestOperation::Stage(stage)).await;
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        BEGIN_TEST_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                registration.key.clone(),
                BeginTestGate {
                    stage,
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                    hold_after_cancellation: true,
                },
            );
        (registration, entered, release)
    }

    async fn install_begin_busy_observer<Connection: BeginOwnedConnection>(
        connection: &mut Connection,
        path: &std::path::Path,
    ) -> (BeginTestRegistration, Arc<tokio::sync::Notify>) {
        let registration =
            register_begin_test(connection, path, BeginTestOperation::BusyObserver).await;
        let entered = Arc::new(tokio::sync::Notify::new());
        BEGIN_BUSY_OBSERVERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(registration.key.clone(), Arc::clone(&entered));
        (registration, entered)
    }

    struct BackupTestRegistration {
        database_address: usize,
    }

    impl Drop for BackupTestRegistration {
        fn drop(&mut self) {
            BACKUP_TEST_CONTROLS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.database_address);
        }
    }

    async fn install_backup_control(
        source: &mut sqlx::SqliteConnection,
        interrupt_at_step: Option<usize>,
    ) -> (BackupTestRegistration, Arc<AtomicUsize>) {
        let database_address = {
            let mut handle = source.lock_handle().await.expect("lock backup test source");
            handle.as_raw_handle().as_ptr() as usize
        };
        let observed_steps = Arc::new(AtomicUsize::new(0));
        let replaced = BACKUP_TEST_CONTROLS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                database_address,
                BackupTestControl {
                    interrupt_at_step,
                    observed_steps: Arc::clone(&observed_steps),
                },
            );
        assert!(replaced.is_none(), "backup test control must be unique");
        (BackupTestRegistration { database_address }, observed_steps)
    }

    #[tokio::test]
    async fn cancelled_owned_begin_before_dispatch_does_not_block_runtime() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("cancel-before-begin.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open pre-dispatch cancellation pool");
        let mut connection = pool.acquire().await.expect("acquire sole pool connection");
        let (_registration, entered, release) =
            install_begin_gate(BeginTestStage::BeforeDispatch, &mut connection, &path).await;
        let begin = tokio::spawn(async move {
            begin_manual_pool_transaction(connection, std::time::Duration::from_millis(500)).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("BEGIN worker reaches pre-dispatch gate");
        begin.abort();
        let cancellation = tokio::time::timeout(std::time::Duration::from_secs(1), begin)
            .await
            .expect("pre-dispatch cancellation leaves the runtime responsive");
        assert!(matches!(cancellation, Err(error) if error.is_cancelled()));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), pool.acquire())
                .await
                .is_err(),
            "cleanup owner must retain the sole pool permit before worker release"
        );
        release.store(true, Ordering::Release);

        let replacement = tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
            .await
            .expect("cleanup owner restores pool capacity")
            .expect("replacement pool connection");
        let (mut replacement, mut token) =
            begin_manual_pool_transaction(replacement, std::time::Duration::from_millis(500))
                .await
                .expect("pre-dispatch cancellation leaves no transaction")
                .into_test_parts();
        rollback_synchronously(&mut replacement, &mut token)
            .await
            .expect("replacement transaction rolls back");
    }

    #[tokio::test]
    async fn cancelled_owned_begin_after_sqlite_begin_does_not_block_runtime() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("cancel-after-begin.sqlite");
        for _ in 0..16 {
            let options = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(options)
                .await
                .expect("open post-BEGIN cancellation pool");
            let mut connection = pool.acquire().await.expect("acquire sole pool connection");
            let (_registration, entered, release) =
                install_begin_gate(BeginTestStage::AfterBegin, &mut connection, &path).await;
            let begin = tokio::spawn(async move {
                begin_manual_pool_transaction(connection, std::time::Duration::from_millis(500))
                    .await
            });
            tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
                .await
                .expect("BEGIN worker reaches post-BEGIN gate");
            begin.abort();
            let cancellation = tokio::time::timeout(std::time::Duration::from_secs(1), begin)
                .await
                .expect("post-BEGIN cancellation leaves the runtime responsive");
            assert!(matches!(cancellation, Err(error) if error.is_cancelled()));
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), pool.acquire())
                    .await
                    .is_err(),
                "cleanup owner must retain capacity while rollback is gated"
            );
            release.store(true, Ordering::Release);

            let replacement =
                tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
                    .await
                    .expect("post-BEGIN cleanup restores capacity")
                    .expect("replacement pool connection");
            let (mut replacement, mut token) =
                begin_manual_pool_transaction(replacement, std::time::Duration::from_millis(500))
                    .await
                    .expect("post-BEGIN cancellation rolled back before close")
                    .into_test_parts();
            rollback_synchronously(&mut replacement, &mut token)
                .await
                .expect("replacement transaction rolls back");
        }
    }

    #[tokio::test]
    async fn cancellation_during_begin_accept_removes_registry_after_cleanup() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("cancel-during-accept.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open accept-cancellation pool");
        let mut connection = pool.acquire().await.expect("acquire sole pool connection");
        let key = {
            let mut handle = connection
                .lock_handle()
                .await
                .expect("lock accept-cancellation SQLite handle");
            let pointer = LiveInterruptPointer(handle.as_raw_handle());
            (
                pointer.as_ptr() as usize,
                connection_lifetime_nonce(pointer).expect("register connection nonce"),
            )
        };

        let (_registration, entered, release) =
            install_begin_gate(BeginTestStage::AfterAccept, &mut connection, &path).await;
        let begin = tokio::spawn(async move {
            begin_manual_pool_transaction(connection, std::time::Duration::from_millis(500)).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("BEGIN reaches post-accept barrier");
        assert!(
            ACTIVE_MANUAL_TRANSACTIONS
                .lock()
                .expect("active transaction registry lock poisoned")
                .contains_key(&key),
            "accept path registers this exact physical connection"
        );
        begin.abort();
        let cancellation = tokio::time::timeout(std::time::Duration::from_secs(1), begin)
            .await
            .expect("post-accept cancellation leaves runtime responsive");
        assert!(matches!(cancellation, Err(error) if error.is_cancelled()));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), pool.acquire())
                .await
                .is_err(),
            "cleanup owner retains the accepted connection until rollback"
        );
        assert!(
            !ACTIVE_MANUAL_TRANSACTIONS
                .lock()
                .expect("active transaction registry lock poisoned")
                .contains_key(&key),
            "armed registration is removed when the accepting future is dropped"
        );
        release.store(true, Ordering::Release);
        tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
            .await
            .expect("terminal cleanup restores pool capacity")
            .expect("replacement acquisition succeeds");
    }

    #[tokio::test]
    async fn begin_panic_after_pointer_publication_quarantines_connection() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("panic-after-begin-pointer.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open BEGIN panic pool");
        let mut connection = pool.acquire().await.expect("acquire BEGIN panic owner");
        let (_registration, entered, release) = install_begin_gate(
            BeginTestStage::PanicAfterPointerPublication,
            &mut connection,
            &path,
        )
        .await;
        let begin = tokio::spawn(async move {
            begin_manual_pool_transaction(connection, std::time::Duration::from_millis(500)).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("BEGIN publishes its interrupt pointer");
        let heartbeat = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        });
        tokio::time::timeout(std::time::Duration::from_millis(100), heartbeat)
            .await
            .expect("BEGIN pointer barrier does not block the runtime")
            .expect("heartbeat joins");
        release.store(true, Ordering::Release);
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), begin)
            .await
            .expect("panicked BEGIN returns promptly")
            .expect("BEGIN task itself joins");
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("injected BEGIN worker panic must be reported"),
        };
        assert!(matches!(error, FileControlError::Handle(message) if message.contains("panicked")));
        let replacement = tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
            .await
            .expect("panicked worker releases quarantined capacity")
            .expect("replacement pool connection");
        let (mut replacement, mut token) =
            begin_manual_pool_transaction(replacement, std::time::Duration::from_millis(500))
                .await
                .expect("cleared pointer cannot affect the replacement connection")
                .into_test_parts();
        rollback_synchronously(&mut replacement, &mut token)
            .await
            .expect("replacement transaction rolls back");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn contended_manual_begin_keeps_tokio_executor_live() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("manual-begin.sqlite");
        let mut locker = manual_transaction_connection(&path).await;
        locker
            .execute("CREATE TABLE value(id INTEGER)")
            .await
            .expect("create manual transaction fixture");
        let (returned_locker, mut locker_token) =
            begin_manual_transaction(locker, std::time::Duration::from_millis(500), None)
                .await
                .expect("start locking transaction")
                .into_test_parts();
        locker = returned_locker;
        let waiter = manual_transaction_connection(&path).await;
        let ticks = Arc::new(AtomicUsize::new(0));
        let heartbeat_ticks = Arc::clone(&ticks);
        let heartbeat = tokio::spawn(async move {
            for _ in 0..20 {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                heartbeat_ticks.fetch_add(1, Ordering::AcqRel);
            }
        });
        let begin = tokio::spawn(async move {
            begin_manual_transaction(waiter, std::time::Duration::from_millis(500), None).await
        });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(
            ticks.load(Ordering::Acquire) > 0,
            "a contended raw BEGIN must not block Tokio workers"
        );
        rollback_synchronously(&mut locker, &mut locker_token)
            .await
            .expect("release locking transaction");
        let (mut waiter, mut waiter_token) = begin
            .await
            .expect("waiting BEGIN task joins")
            .expect("waiting BEGIN eventually starts")
            .into_test_parts();
        rollback_synchronously(&mut waiter, &mut waiter_token)
            .await
            .expect("rollback waiting transaction");
        heartbeat.await.expect("heartbeat joins");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_contended_manual_begin_interrupts_and_joins_worker() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("cancelled-begin.sqlite");
        let mut locker = manual_transaction_connection(&path).await;
        locker
            .execute("CREATE TABLE value(id INTEGER)")
            .await
            .expect("create cancellation fixture");
        let (returned_locker, mut locker_token) =
            begin_manual_transaction(locker, std::time::Duration::from_millis(500), None)
                .await
                .expect("start locking transaction")
                .into_test_parts();
        locker = returned_locker;
        let mut waiter = manual_transaction_connection(&path).await;
        let (_registration, busy_entered) = install_begin_busy_observer(&mut waiter, &path).await;
        let begin = tokio::spawn(async move {
            begin_manual_transaction(waiter, std::time::Duration::from_secs(5), None).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), busy_entered.notified())
            .await
            .expect("BEGIN reaches custom busy handler");
        let cancelled_at = std::time::Instant::now();
        begin.abort();
        let cancellation = tokio::time::timeout(std::time::Duration::from_secs(1), begin)
            .await
            .expect("cancelled BEGIN joins after interrupt");
        assert!(matches!(cancellation, Err(error) if error.is_cancelled()));
        assert!(
            cancelled_at.elapsed() < std::time::Duration::from_secs(1),
            "custom busy handler must observe cancellation without waiting for busy_timeout"
        );
        rollback_synchronously(&mut locker, &mut locker_token)
            .await
            .expect("release locking transaction");

        let replacement = manual_transaction_connection(&path).await;
        let (mut replacement, mut replacement_token) =
            begin_manual_transaction(replacement, std::time::Duration::from_millis(500), None)
                .await
                .expect("replacement connection starts a transaction")
                .into_test_parts();
        rollback_synchronously(&mut replacement, &mut replacement_token)
            .await
            .expect("replacement transaction rolls back");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn external_cancellation_interrupts_contended_begin_before_busy_timeout() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("external-cancel-begin.sqlite");
        let mut locker = manual_transaction_connection(&path).await;
        locker
            .execute("CREATE TABLE value(id INTEGER)")
            .await
            .expect("create external cancellation fixture");
        let (returned_locker, mut locker_token) =
            begin_manual_transaction(locker, std::time::Duration::from_secs(5), None)
                .await
                .expect("start locking transaction")
                .into_test_parts();
        locker = returned_locker;
        let mut waiter = manual_transaction_connection(&path).await;
        let (_registration, busy_entered) = install_begin_busy_observer(&mut waiter, &path).await;
        let cancelled = Arc::new(AtomicBool::new(false));
        let task_cancelled = Arc::clone(&cancelled);
        let begin = tokio::spawn(async move {
            begin_manual_transaction(
                waiter,
                std::time::Duration::from_secs(5),
                Some(task_cancelled),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), busy_entered.notified())
            .await
            .expect("BEGIN reaches cancellation-aware busy handler");
        let started = std::time::Instant::now();
        cancelled.store(true, Ordering::Release);
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), begin)
            .await
            .expect("external cancellation remains bounded")
            .expect("BEGIN cancellation task joins");
        assert!(result.is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        rollback_synchronously(&mut locker, &mut locker_token)
            .await
            .expect("release external cancellation locker");
    }

    #[tokio::test]
    async fn cancellation_wins_worker_error_before_terminal_cleanup() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("cancel-after-worker-error.sqlite");
        let mut locker = manual_transaction_connection(&path).await;
        locker
            .execute("CREATE TABLE value(id INTEGER)")
            .await
            .expect("create worker-error fixture");
        let (returned_locker, mut locker_token) =
            begin_manual_transaction(locker, std::time::Duration::from_secs(1), None)
                .await
                .expect("start worker-error locking transaction")
                .into_test_parts();
        locker = returned_locker;
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .busy_timeout(std::time::Duration::from_secs(1));
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open worker-error waiter pool");
        let mut waiter = pool.acquire().await.expect("acquire worker-error waiter");
        let (_registration, entered, release) =
            install_begin_gate(BeginTestStage::AfterFailureOutcome, &mut waiter, &path).await;
        let cancelled = Arc::new(AtomicBool::new(false));
        let task_cancelled = Arc::clone(&cancelled);
        let begin = tokio::spawn(async move {
            begin_manual_pool_transaction_with_restore(
                waiter,
                std::time::Duration::from_millis(30),
                std::time::Duration::from_secs(1),
                Some(task_cancelled),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("worker sends failure before terminal connection close");
        cancelled.store(true, Ordering::Release);
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), begin)
            .await
            .expect("external cancellation wins without runtime starvation")
            .expect("worker-error task joins");
        assert!(matches!(
            result,
            Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT))
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), pool.acquire())
                .await
                .is_err(),
            "cleanup owner retains capacity while terminal close is gated"
        );
        release.store(true, Ordering::Release);
        tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
            .await
            .expect("terminal cleanup restores worker-error pool capacity")
            .expect("replacement waiter acquisition succeeds");
        rollback_synchronously(&mut locker, &mut locker_token)
            .await
            .expect("release worker-error locker");
    }

    #[tokio::test]
    async fn failed_busy_commit_keeps_token_active_for_rollback() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("busy-commit.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete)
            .busy_timeout(std::time::Duration::from_millis(20));
        let mut writer = sqlx::SqliteConnection::connect_with(&options)
            .await
            .expect("open busy commit writer");
        writer
            .execute("CREATE TABLE IF NOT EXISTS value(id INTEGER)")
            .await
            .expect("create busy commit table");
        let (mut writer, mut token) =
            begin_manual_transaction(writer, std::time::Duration::from_millis(250), None)
                .await
                .expect("begin busy commit writer")
                .into_test_parts();
        writer
            .execute("INSERT INTO value VALUES (1)")
            .await
            .expect("stage busy commit row");
        let mut reader = sqlx::SqliteConnection::connect_with(&options)
            .await
            .expect("open busy commit reader");
        reader
            .execute("BEGIN")
            .await
            .expect("begin blocking reader");
        reader
            .fetch_one("SELECT COUNT(*) FROM value")
            .await
            .expect("hold rollback-journal read lock");

        assert_eq!(
            commit_synchronously(&mut writer, &mut token, None)
                .await
                .expect_err("reader makes COMMIT busy"),
            FileControlError::SQLite(libsqlite3_sys::SQLITE_BUSY)
        );
        rollback_synchronously(&mut writer, &mut token)
            .await
            .expect("failed COMMIT leaves token usable for rollback");
        reader
            .execute("ROLLBACK")
            .await
            .expect("release blocking reader");
    }

    #[tokio::test]
    async fn failed_authorizer_detach_is_freed_once_after_terminal_close() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open detach-failure pool");
        let connection = pool.acquire().await.expect("acquire detach-failure lease");
        let transaction =
            begin_manual_pool_transaction(connection, std::time::Duration::from_millis(500))
                .await
                .expect("begin detach-failure transaction");
        let token = transaction
            .token
            .as_ref()
            .expect("detach-failure token remains owned");
        let generation = token.generation;
        let key = (token.database_address, token.connection_nonce);
        assert!(
            FAIL_AUTHORIZER_DETACH_GENERATIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(generation)
        );

        let error = transaction
            .rollback()
            .await
            .expect_err("injected authorizer detach failure quarantines the connection");
        assert!(error.to_string().contains("code 1"));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if DROPPED_AUTHORIZER_GENERATIONS
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&generation)
                    == Some(&1)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("authorizer is released after terminal close completes");
        assert!(
            !ACTIVE_MANUAL_TRANSACTIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&key)
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
            .await
            .expect("terminal close restores detach-failure pool capacity")
            .expect("replacement detach-failure connection opens");
    }

    #[tokio::test]
    async fn durable_commit_detach_failure_is_never_reported_uncommitted() {
        let directory = tempfile::tempdir().expect("durable detach-failure directory");
        let path = directory.path().join("durable-detach-failure.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open durable detach-failure pool");
        let mut connection = pool
            .acquire()
            .await
            .expect("acquire durable detach-failure lease");
        connection
            .execute("CREATE TABLE committed_value(id INTEGER)")
            .await
            .expect("create durable detach-failure table");
        let mut transaction =
            begin_manual_pool_transaction(connection, std::time::Duration::from_millis(500))
                .await
                .expect("begin durable detach-failure transaction");
        transaction
            .execute("INSERT INTO committed_value VALUES (1)")
            .await
            .expect("stage durable detach-failure row");
        let generation = transaction
            .token
            .as_ref()
            .expect("durable detach-failure token remains owned")
            .generation;
        assert!(
            FAIL_AUTHORIZER_DETACH_GENERATIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(generation)
        );
        let error = transaction
            .commit()
            .await
            .expect_err("durable detach failure cannot return a reusable connection");
        assert!(matches!(
            error,
            FileControlError::CommittedWithCleanupFailure(_)
        ));
        let mut replacement = pool
            .acquire()
            .await
            .expect("open replacement after durable detach failure");
        assert_eq!(
            replacement
                .fetch_one("SELECT COUNT(*) FROM committed_value")
                .await
                .expect("read durably committed row")
                .get::<i64, _>(0),
            1
        );
    }

    #[tokio::test]
    async fn close_timeout_retains_authorizer_until_quarantined_close_finishes() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open authorizer quarantine pool");
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let entered = Arc::new(AtomicUsize::new(0));
        let connection = StallingPoolConnection {
            connection: pool
                .acquire()
                .await
                .expect("acquire authorizer quarantine lease"),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        };
        let transaction = begin_manual_transaction_inner(
            connection,
            std::time::Duration::from_millis(500),
            std::time::Duration::from_millis(500),
            None,
        )
        .await
        .expect("begin authorizer quarantine transaction");
        let token = transaction
            .token
            .as_ref()
            .expect("authorizer quarantine token remains owned");
        let generation = token.generation;
        let key = (token.database_address, token.connection_nonce);
        assert!(
            FAIL_AUTHORIZER_DETACH_GENERATIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(generation)
        );

        let error = transaction
            .rollback()
            .await
            .expect_err("stalled close quarantines failed authorizer detach");
        assert!(error.to_string().contains("Quarantined"));
        assert!(
            DROPPED_AUTHORIZER_GENERATIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&generation)
                .is_none(),
            "authorizer context remains live while SQLite close is stalled"
        );
        assert!(
            !ACTIVE_MANUAL_TRANSACTIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&key)
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), pool.acquire())
                .await
                .is_err(),
            "quarantined close retains the physical pool permit"
        );

        {
            let (released, changed) = &*release;
            *released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            changed.notify_all();
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if DROPPED_AUTHORIZER_GENERATIONS
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&generation)
                    == Some(&1)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("authorizer is freed after quarantined close completes");
        pool.acquire()
            .await
            .expect("quarantined close restores pool capacity");
    }

    #[tokio::test]
    async fn commit_rechecks_cancellation_immediately_before_native_dispatch() {
        let mut connection = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open commit-fence connection");
        connection
            .execute("CREATE TABLE value(id INTEGER)")
            .await
            .expect("create commit-fence table");
        let (mut connection, mut token) =
            begin_manual_transaction(connection, std::time::Duration::from_millis(250), None)
                .await
                .expect("begin commit-fence transaction")
                .into_test_parts();
        connection
            .execute("INSERT INTO value VALUES (1)")
            .await
            .expect("stage commit-fence row");
        let cancellation = BeginCancellation {
            local: AtomicBool::new(true),
            external: None,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
            busy_entered: std::sync::Mutex::new(None),
            test_key: std::sync::Mutex::new(None),
        };

        assert_eq!(
            commit_synchronously(&mut connection, &mut token, Some(&cancellation))
                .await
                .expect_err("cancelled precommit fence rejects native COMMIT"),
            FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT)
        );
        rollback_synchronously(&mut connection, &mut token)
            .await
            .expect("cancelled precommit fence leaves transaction rollbackable");
        assert_eq!(
            connection
                .fetch_one("SELECT COUNT(*) FROM value")
                .await
                .expect("query commit-fence row count")
                .get::<i64, _>(0),
            0
        );
    }

    #[tokio::test]
    async fn cancelled_commit_result_delivery_cleans_claim_and_closes_connection() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("cancelled-commit-delivery.sqlite");
        let owner = "cancelled-result-owner";
        let (pool, transaction) = commit_delivery_fixture(&path, owner, 1).await;
        let (_registration, entered, release) = install_commit_result_gate(owner).await;
        let cancelled = Arc::new(AtomicBool::new(false));
        let commit = tokio::spawn(transaction.commit_with_deadline(
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            std::time::Instant::now() + std::time::Duration::from_secs(2),
            cancelled,
            std::time::Duration::from_millis(500),
            Some(owner.to_owned()),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("COMMIT reaches result-delivery gate");
        commit.abort();
        assert!(
            commit
                .await
                .expect_err("COMMIT result receiver is cancelled")
                .is_cancelled()
        );
        release.store(true, Ordering::Release);
        let mut replacement =
            tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
                .await
                .expect("undelivered COMMIT closes its connection")
                .expect("replacement connection opens");
        let claims =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM claw_writer_lock WHERE owner = ?")
                .bind(owner)
                .fetch_one(&mut *replacement)
                .await
                .expect("verify cancelled result claim cleanup");
        assert_eq!(claims, 0);
    }

    #[tokio::test]
    async fn late_commit_cannot_deliver_connection() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("late-commit-delivery.sqlite");
        let owner = "late-result-owner";
        let (pool, transaction) = commit_delivery_fixture(&path, owner, 1).await;
        let (_registration, entered, release) = install_commit_result_gate(owner).await;
        let work_deadline = std::time::Instant::now() + std::time::Duration::from_millis(30);
        let commit = tokio::spawn(transaction.commit_with_deadline(
            work_deadline,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
            std::time::Duration::from_millis(500),
            Some(owner.to_owned()),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("late COMMIT reaches result gate");
        tokio::time::sleep_until(tokio::time::Instant::from_std(work_deadline)).await;
        release.store(true, Ordering::Release);
        assert!(commit.await.expect("late COMMIT task joins").is_err());
        let mut replacement =
            tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
                .await
                .expect("late COMMIT closes its connection")
                .expect("replacement connection opens");
        let claims =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM claw_writer_lock WHERE owner = ?")
                .bind(owner)
                .fetch_one(&mut *replacement)
                .await
                .expect("verify late COMMIT claim cleanup");
        assert_eq!(claims, 0);
    }

    #[tokio::test]
    async fn late_claim_delete_cutoff_quarantines_connection() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("late-delete-cutoff.sqlite");
        let owner = "delete-cutoff-owner";
        let (pool, transaction) = commit_delivery_fixture(&path, owner, 2).await;
        let (_registration, entered, release) = install_commit_result_gate(owner).await;
        let work_deadline = std::time::Instant::now() + std::time::Duration::from_millis(30);
        let cleanup_deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
        let commit = tokio::spawn(transaction.commit_with_deadline(
            work_deadline,
            cleanup_deadline,
            Arc::new(AtomicBool::new(false)),
            std::time::Duration::from_millis(500),
            Some(owner.to_owned()),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("cutoff COMMIT reaches result gate");
        tokio::time::sleep_until(tokio::time::Instant::from_std(cleanup_deadline)).await;
        release.store(true, Ordering::Release);
        let error = commit
            .await
            .expect("cutoff COMMIT task joins")
            .expect_err("expired DELETE cleanup cannot deliver a connection");
        assert!(
            error.to_string().contains("cutoff"),
            "unexpected cutoff error: {error}"
        );
        let mut replacement =
            tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
                .await
                .expect("cutoff path closes its connection")
                .expect("replacement connection opens");
        let claims =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM claw_writer_lock WHERE owner = ?")
                .bind(owner)
                .fetch_one(&mut *replacement)
                .await
                .expect("inspect quarantined claim");
        assert_eq!(claims, 1);
    }

    #[tokio::test]
    async fn pool_owned_begin_retains_actual_connection_capacity() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("pool-capacity.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open capacity pool");
        let connection = pool.acquire().await.expect("acquire capacity owner");
        let transaction =
            begin_manual_pool_transaction(connection, std::time::Duration::from_millis(100))
                .await
                .expect("begin pool-owned transaction");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), pool.acquire())
                .await
                .is_err(),
            "manual transaction must retain SQLx's sole pool permit"
        );
        let connection = transaction
            .rollback()
            .await
            .expect("rollback pool-owned transaction");
        drop(connection);
        tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
            .await
            .expect("pool permit returns after transaction terminal state")
            .expect("replacement pool acquisition succeeds");
    }

    #[tokio::test]
    async fn dropping_active_owner_rolls_back_before_pool_reuse() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("drop-owner.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open drop-owner pool");
        let mut connection = pool.acquire().await.expect("acquire drop-owner connection");
        connection
            .execute("CREATE TABLE value(id INTEGER)")
            .await
            .expect("create drop-owner fixture");
        let mut transaction =
            begin_manual_pool_transaction(connection, std::time::Duration::from_secs(1))
                .await
                .expect("begin drop-owner transaction");
        transaction
            .execute("INSERT INTO value VALUES (1)")
            .await
            .expect("stage drop-owner row");
        drop(transaction);
        let mut replacement =
            tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
                .await
                .expect("durable rollback restores pool capacity")
                .expect("replacement connection");
        assert!(
            is_autocommit(&mut replacement)
                .await
                .expect("read autocommit")
        );
        let count = replacement
            .fetch_one("SELECT COUNT(*) FROM value")
            .await
            .expect("count rolled-back rows")
            .get::<i64, _>(0);
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn transaction_control_sql_cannot_escape_owner() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("transaction-authorizer.sqlite");
        let mut connection = manual_transaction_connection(&path).await;
        connection
            .execute("CREATE TABLE value(id INTEGER)")
            .await
            .expect("create authorizer fixture");
        let mut transaction =
            begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                .await
                .expect("begin authorizer transaction");
        for statement in [
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "END",
            "SAVEPOINT nested",
            "RELEASE nested",
            "ROLLBACK TO nested",
        ] {
            let error = transaction
                .execute(statement)
                .await
                .expect_err("transaction control must be denied by the native authorizer");
            assert!(
                matches!(
                    error,
                    sqlx::Error::Database(ref database)
                        if database.code().as_deref() == Some("23")
                ),
                "{statement} returned {error:?} instead of SQLITE_AUTH"
            );
        }
        transaction
            .execute("INSERT INTO value VALUES (1)")
            .await
            .expect("transaction remains active after denied COMMIT");
        let mut connection = transaction
            .rollback()
            .await
            .expect("owned rollback remains authoritative");
        let count = connection
            .fetch_one("SELECT COUNT(*) FROM value")
            .await
            .expect("count authorizer rows")
            .get::<i64, _>(0);
        assert_eq!(count, 0);
    }

    #[test]
    fn source_contains_no_filesystem_sqlite_backup_output() {
        let helper = include_str!("lib.rs");
        let state = include_str!("../../claw-state/src/store.rs");
        let forbidden = [
            ["sqlite3_db_", "filename"].concat(),
            ["VACUUM", " INTO"].concat(),
            [".filename(", "destination)"].concat(),
            [".filename(&", "temporary)"].concat(),
            [".gta-claw-", "restore-"].concat(),
            ["backup-", "stage"].concat(),
        ];
        for needle in forbidden {
            assert!(
                !helper.contains(&needle) && !state.contains(&needle),
                "forbidden SQLite output-path source pattern remains"
            );
        }
    }

    #[tokio::test]
    async fn backup_interrupts_at_first_middle_and_final_batch() {
        let mut source = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open backup source");
        sqlx::raw_sql(
            "CREATE TABLE payload(value BLOB);
             WITH RECURSIVE n(value) AS (
               VALUES(1) UNION ALL SELECT value + 1 FROM n WHERE value < 400
             )
             INSERT INTO payload SELECT randomblob(4096) FROM n;",
        )
        .execute(&mut source)
        .await
        .expect("seed multi-batch backup source");

        let mut baseline_destination = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open baseline backup destination");
        let (_baseline_registration, baseline_steps) =
            install_backup_control(&mut source, None).await;
        backup_main_database(
            &mut source,
            &mut baseline_destination,
            &BackupExecutionContext {
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(2),
                cancelled: Arc::new(AtomicBool::new(false)),
                max_pages: 10_000,
                source_busy_timeout: std::time::Duration::ZERO,
                destination_busy_timeout: std::time::Duration::ZERO,
            },
        )
        .await
        .expect("complete baseline incremental backup");
        let total_steps = baseline_steps.load(Ordering::Acquire);
        assert!(
            total_steps >= 3,
            "fixture must span first, middle, and final batches"
        );
        drop(_baseline_registration);

        for target in [0, total_steps / 2, total_steps - 1] {
            let mut destination = sqlx::SqliteConnection::connect("sqlite::memory:")
                .await
                .expect("open interrupted backup destination");
            let (_registration, observed) = install_backup_control(&mut source, Some(target)).await;
            assert!(matches!(
                backup_main_database(
                    &mut source,
                    &mut destination,
                    &BackupExecutionContext {
                        deadline: std::time::Instant::now() + std::time::Duration::from_secs(2),
                        cancelled: Arc::new(AtomicBool::new(false)),
                        max_pages: 10_000,
                        source_busy_timeout: std::time::Duration::ZERO,
                        destination_busy_timeout: std::time::Duration::ZERO,
                    },
                )
                .await,
                Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT))
            ));
            assert_eq!(observed.load(Ordering::Acquire), target + 1);
            let rows = source
                .fetch_one("SELECT COUNT(*) FROM payload")
                .await
                .expect("interrupted backup leaves source usable")
                .get::<i64, _>(0);
            assert_eq!(rows, 400);
        }
    }

    #[tokio::test]
    async fn deserialize_transfer_keeps_ffi_ownership_one_way() {
        let mut source = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open deserialize source");
        source
            .execute("CREATE TABLE payload(value INTEGER)")
            .await
            .expect("create deserialize source schema");
        let bytes = serialize_main_database(&mut source, 1024 * 1024)
            .await
            .expect("serialize deserialize source");

        let mut destination = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open deserialize destination");
        deserialize_readonly(&mut destination, &bytes)
            .await
            .expect("transfer authenticated bytes to SQLite");
        drop(bytes);
        assert_eq!(
            destination
                .fetch_one("SELECT COUNT(*) FROM payload")
                .await
                .expect("query deserialized image")
                .get::<i64, _>(0),
            0
        );
        destination
            .close()
            .await
            .expect("SQLite releases deserialized ownership on close");
    }

    #[tokio::test]
    async fn serialization_and_backup_enforce_batch_size_caps() {
        let mut source = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open size-cap source");
        sqlx::raw_sql(
            "CREATE TABLE payload(value BLOB);
             INSERT INTO payload VALUES (randomblob(8192));",
        )
        .execute(&mut source)
        .await
        .expect("seed size-cap source");
        assert!(matches!(
            serialize_main_database(&mut source, 1).await,
            Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_TOOBIG))
        ));
        let mut destination = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open size-cap destination");
        assert!(matches!(
            backup_main_database(
                &mut source,
                &mut destination,
                &BackupExecutionContext {
                    deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
                    cancelled: Arc::new(AtomicBool::new(false)),
                    max_pages: 1,
                    source_busy_timeout: std::time::Duration::ZERO,
                    destination_busy_timeout: std::time::Duration::ZERO,
                },
            )
            .await,
            Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_TOOBIG))
        ));
    }

    #[tokio::test]
    async fn stale_manual_token_cannot_control_later_same_handle_transaction() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("token-generation.sqlite");
        let connection = manual_transaction_connection(&path).await;
        let (mut connection, mut first) =
            begin_manual_transaction(connection, std::time::Duration::from_millis(100), None)
                .await
                .expect("begin first generation")
                .into_test_parts();
        rollback_synchronously(&mut connection, &mut first)
            .await
            .expect("finish first generation");
        let (mut connection, mut current) =
            begin_manual_transaction(connection, std::time::Duration::from_millis(100), None)
                .await
                .expect("begin current generation")
                .into_test_parts();
        let mut stale = ManualTransactionToken {
            database_address: current.database_address,
            connection_nonce: current.connection_nonce,
            generation: current.generation.wrapping_sub(1),
            authorizer_address: current.authorizer_address,
            active: true,
        };
        assert!(matches!(
            commit_synchronously(&mut connection, &mut stale, None).await,
            Err(FileControlError::Handle(message)) if message.contains("generation is stale")
        ));
        let mut wrong_lifetime = ManualTransactionToken {
            database_address: current.database_address,
            connection_nonce: current.connection_nonce.wrapping_add(1),
            generation: current.generation,
            authorizer_address: current.authorizer_address,
            active: true,
        };
        assert!(matches!(
            commit_synchronously(&mut connection, &mut wrong_lifetime, None).await,
            Err(FileControlError::Handle(message)) if message.contains("connection lifetime")
        ));
        rollback_synchronously(&mut connection, &mut current)
            .await
            .expect("stale token did not affect current transaction");
    }

    #[tokio::test]
    async fn stalled_terminal_closes_release_normal_cleanup_workers() {
        let _executor_serial = Arc::clone(&EXECUTOR_TEST_SERIAL).lock_owned().await;
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let entered = Arc::new(AtomicUsize::new(0));
        let mut owners = BlockingCleanupOwner::acquire_set(
            "stalled-terminal-close-workers",
            CLEANUP_THREADS,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
        .expect("reserve former cleanup worker count");
        let (outcome_tx, outcome_rx) = std::sync::mpsc::sync_channel(CLEANUP_THREADS);
        let mut pools = Vec::new();
        for mut owner in owners.drain(..) {
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect("sqlite::memory:")
                .await
                .expect("open stalled-close pool");
            let connection = pool.acquire().await.expect("acquire stalled-close lease");
            let connection = StallingPoolConnection {
                connection,
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            };
            let outcome_tx = outcome_tx.clone();
            owner.handoff(move |_, mut terminal_closes| {
                let _ = outcome_tx.send(terminal_closes.close(connection));
            });
            pools.push(pool);
        }
        drop(outcome_tx);
        let cutoff = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut outcomes = Vec::new();
        while outcomes.len() < CLEANUP_THREADS && std::time::Instant::now() < cutoff {
            match outcome_rx.try_recv() {
                Ok(outcome) => outcomes.push(outcome),
                Err(std::sync::mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }
        assert_eq!(outcomes.len(), CLEANUP_THREADS);
        assert!(
            outcomes
                .iter()
                .all(|outcome| *outcome == TerminalCloseOutcome::Quarantined)
        );
        assert!(
            entered.load(Ordering::Acquire) <= TERMINAL_CLOSE_THREADS,
            "only the fixed terminal-close threads may block"
        );

        let mut heartbeat_owners = BlockingCleanupOwner::acquire_set(
            "cleanup-heartbeat-after-close-stalls",
            1,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await
        .expect("normal cleanup admission remains live");
        let mut heartbeat_owner = heartbeat_owners
            .pop()
            .expect("one heartbeat owner was reserved");
        let (heartbeat_tx, heartbeat_rx) = tokio::sync::oneshot::channel();
        heartbeat_owner.handoff(move |_, _| {
            let _ = heartbeat_tx.send(());
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), heartbeat_rx)
            .await
            .expect("normal cleanup heartbeat remains responsive")
            .expect("heartbeat owner reports completion");
        assert!(
            BlockingCleanupOwner::acquire_set(
                "terminal-quarantine-saturation",
                MAX_CLEANUP_JOBS,
                std::time::Instant::now() + std::time::Duration::from_millis(20),
            )
            .await
            .is_err(),
            "terminal quarantine capacity rejects an oversized atomic admission"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), pools[0].acquire())
                .await
                .is_err(),
            "stalled physical close retains the pool permit"
        );

        {
            let (released, changed) = &*release;
            *released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            changed.notify_all();
        }
        for pool in pools {
            tokio::time::timeout(std::time::Duration::from_secs(2), pool.acquire())
                .await
                .expect("released terminal close restores pool capacity")
                .expect("replacement pool connection opens");
        }
    }

    #[test]
    fn blocking_cleanup_handoff_is_guaranteed_without_a_tokio_runtime() {
        assert!(
            BlockingCleanupOwner::acquire_without_runtime("invalid\0cleanup-owner").is_err(),
            "invalid cleanup capability must fail before a SQLite worker starts"
        );

        let release = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let worker_release = Arc::clone(&release);
        let worker_entered = Arc::clone(&entered);
        let worker_done = Arc::clone(&done);
        let admission_started = std::time::Instant::now();
        let mut owner = loop {
            match BlockingCleanupOwner::acquire_without_runtime("handoff-outside-runtime") {
                Ok(owner) => break owner,
                Err(_) if admission_started.elapsed() < std::time::Duration::from_secs(1) => {
                    std::thread::yield_now();
                }
                Err(error) => panic!("acquire cleanup capability: {error}"),
            }
        };
        let started = std::time::Instant::now();
        owner.handoff(move |_, _terminal_closes| {
            worker_entered.store(true, Ordering::Release);
            while !worker_release.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            worker_done.store(true, Ordering::Release);
        });
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        while !entered.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        assert!(!done.load(Ordering::Acquire));
        release.store(true, Ordering::Release);
        while !done.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
    }

    #[test]
    fn concurrent_cleanup_saturation_reserves_atomically() {
        fn reserve(active: &AtomicUsize, count: usize) -> bool {
            loop {
                let observed = active.load(Ordering::Acquire);
                if observed > MAX_CLEANUP_JOBS - count {
                    return false;
                }
                if active
                    .compare_exchange_weak(
                        observed,
                        observed + count,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return true;
                }
            }
        }

        let active = AtomicUsize::new(0);
        assert!(reserve(&active, MAX_CLEANUP_JOBS));
        assert!(!reserve(&active, 2));
        assert_eq!(active.load(Ordering::Acquire), MAX_CLEANUP_JOBS);
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;

    #[test]
    fn unix_sidecar_generation_record_binds_path_and_store_generation() {
        let database = std::path::Path::new("/private/state.sqlite");
        let wal = std::path::Path::new("/private/state.sqlite-wal");
        let shm = std::path::Path::new("/private/state.sqlite-shm");
        let first = unix_sidecar_generation_record(database, wal, b"generation-one");
        assert_eq!(first.len(), 52);
        assert_eq!(&first[..20], b"GTA-CLAW-SIDECAR-U1\0");
        assert_ne!(
            first,
            unix_sidecar_generation_record(database, shm, b"generation-one")
        );
        assert_ne!(
            first,
            unix_sidecar_generation_record(database, wal, b"generation-two")
        );
        assert_ne!(
            first,
            unix_sidecar_generation_record(
                std::path::Path::new("/private/other.sqlite"),
                wal,
                b"generation-one",
            )
        );
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::io::Write as _;
    use std::os::windows::fs::{OpenOptionsExt as _, symlink_file};
    use std::process::{Command, Stdio};
    use std::sync::atomic::AtomicU64;

    #[test]
    fn windows_sidecar_generation_record_is_fixed_and_identity_bound() {
        let first = windows_sidecar_generation_record(b"short");
        let second = windows_sidecar_generation_record(b"a much longer generation identity");
        assert_eq!(first.len(), 52);
        assert_eq!(&first[..20], b"GTA-CLAW-SIDECAR-V1\0");
        assert_ne!(first, second);
    }

    #[test]
    fn newly_secured_windows_file_is_service_private() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{WRITE_DAC, WRITE_OWNER};

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("secured-file");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)
            .create_new(true)
            .open(&path)
            .expect("create security fixture");
        secure_new_windows_file(&file).expect("apply protected file security");
        assert!(windows_file_is_service_private(&file).expect("validate protected file security"));
        let status = Command::new("icacls.exe")
            .arg(directory.path())
            .arg("/grant")
            .arg("*S-1-1-0:(OI)(CI)F")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("mutate ancestor DACL");
        assert!(status.success());
        assert!(
            windows_file_is_service_private(&file)
                .expect("protected child remains independently service-private"),
            "an ancestor DACL change must not be inherited by a secured child"
        );
        let status = Command::new("icacls.exe")
            .arg(&path)
            .arg("/grant")
            .arg("*S-1-1-0:R")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("add read-only untrusted ACE");
        assert!(status.success());
        assert!(
            !windows_file_is_service_private(&file)
                .expect("validate file with untrusted read-only ACE"),
            "service-private files must reject untrusted read authority"
        );
    }

    #[test]
    fn windows_commit_callback_rejects_reparse_sidecar() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let identity = Command::new("whoami.exe")
            .output()
            .expect("read Windows test identity");
        assert!(identity.status.success());
        let identity = String::from_utf8(identity.stdout)
            .expect("Windows identity is UTF-8")
            .trim()
            .to_owned();
        let status = Command::new("icacls.exe")
            .arg(directory.path())
            .arg("/setowner")
            .arg(&identity)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("set Windows callback fixture owner");
        assert!(status.success());
        let status = Command::new("icacls.exe")
            .arg(directory.path())
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(format!("{identity}:(OI)(CI)F"))
            .arg("*S-1-5-18:(OI)(CI)F")
            .arg("*S-1-5-32-544:(OI)(CI)F")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("secure Windows callback fixture");
        assert!(status.success());
        let directory_security = std::fs::OpenOptions::new()
            .read(true)
            .access_mode(
                windows_sys::Win32::Foundation::GENERIC_READ
                    | windows_sys::Win32::Storage::FileSystem::WRITE_DAC
                    | windows_sys::Win32::Storage::FileSystem::WRITE_OWNER,
            )
            .custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS
                    | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            )
            .open(directory.path())
            .expect("open callback fixture directory for exact DACL");
        secure_new_windows_file(&directory_security)
            .expect("apply exact protected callback directory DACL");
        drop(directory_security);

        let database_path = directory.path().join("state.sqlite");
        let lock_path = directory.path().join("state.sqlite.writer.lock");
        let wal_path = directory.path().join("state.sqlite-wal");
        let shm_path = directory.path().join("state.sqlite-shm");
        let generation = b"callback-generation".to_vec();
        let generation_record = windows_sidecar_generation_record(&generation);
        std::fs::write(&database_path, b"database").expect("create database fixture");
        std::fs::write(&lock_path, &generation).expect("create lock fixture");
        std::fs::write(&wal_path, b"wal").expect("create WAL fixture");
        std::fs::write(&shm_path, b"shm").expect("create SHM fixture");
        for path in [&database_path, &lock_path, &wal_path, &shm_path] {
            use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
            use windows_sys::Win32::Storage::FileSystem::{WRITE_DAC, WRITE_OWNER};

            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)
                .open(path)
                .expect("open callback security fixture");
            secure_new_windows_file(&file).expect("protect callback security fixture");
        }
        for sidecar in [&wal_path, &shm_path] {
            let mut generation_path = sidecar.as_os_str().to_owned();
            generation_path.push(":gta-claw-generation");
            std::fs::File::create(std::path::PathBuf::from(generation_path))
                .and_then(|mut file| file.write_all(&generation_record))
                .expect("attach sidecar generation");
        }

        let database_parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS
                    | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            )
            .open(directory.path())
            .expect("open fixture parent");
        let database_file = std::fs::File::open(&database_path).expect("open database fixture");
        let lock_file = std::fs::File::open(&lock_path).expect("open lock fixture");
        let sidecars = [&wal_path, &shm_path]
            .into_iter()
            .map(|path| PinnedSidecar {
                path: path.clone(),
                file: std::fs::File::open(path).expect("open sidecar fixture"),
            })
            .collect::<Vec<_>>();
        assert!(
            windows_file_is_service_private(&database_parent)
                .expect("validate callback parent security")
        );
        assert!(
            windows_file_is_service_private(&database_file)
                .expect("validate callback database security")
        );
        assert!(
            windows_file_is_service_private(&lock_file).expect("validate callback lock security")
        );
        for sidecar in &sidecars {
            assert!(
                windows_file_is_service_private(&sidecar.file)
                    .expect("validate callback sidecar security")
            );
        }
        let context = WindowsIdentityCommitContext {
            database_parent_path: directory.path().to_owned(),
            database_parent,
            database_path: database_path.clone(),
            database_file,
            lock_path,
            lock_file,
            expected_identity: generation,
            sidecars,
            writer_generation: std::sync::Arc::new(AtomicU64::new(1)),
            expected_writer_generation: 1,
        };
        assert!(windows_identity_matches(&context));

        std::fs::remove_file(&wal_path).expect("remove live WAL fixture path");
        let replacement = directory.path().join("replacement-wal");
        std::fs::write(&replacement, b"replacement").expect("create reparse target");
        if let Err(error) = symlink_file(&replacement, &wal_path) {
            if error.kind() == std::io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("create WAL reparse point: {error}");
        }
        let mut context = context;
        // SAFETY: The callback receives the same live context layout registered
        // with SQLite and does not take ownership.
        let rejected =
            unsafe { reject_unbound_windows_commit((&raw mut context).cast::<std::ffi::c_void>()) };
        assert_eq!(rejected, 1);
    }
}

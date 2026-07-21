//! Minimal audited access to SQLite file-control operations.

use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::ptr::NonNull;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
};

/// Typed reason recorded by the installed identity commit hook for one COMMIT attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityCommitVeto {
    path: std::path::PathBuf,
    reason: &'static str,
}

impl IdentityCommitVeto {
    /// Returns the path whose identity check rejected the COMMIT.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Returns the stable identity-rejection reason.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

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
    /// The installed identity hook vetoed this exact COMMIT and SQLite rolled it back.
    IdentityCommitVetoed(IdentityCommitVeto, Option<String>),
    /// SQLite ended the exact manual transaction outside its owner.
    TransactionInvalidated(String),
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
            Self::IdentityCommitVetoed(_, _) => None,
            Self::TransactionInvalidated(_) => None,
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
            Self::IdentityCommitVetoed(veto, cleanup) => {
                write!(
                    formatter,
                    "SQLite identity hook vetoed COMMIT for {}: {}",
                    veto.path.display(),
                    veto.reason
                )?;
                if let Some(cleanup) = cleanup {
                    write!(formatter, "; terminal cleanup failed: {cleanup}")?;
                }
                Ok(())
            }
            Self::TransactionInvalidated(message) => {
                write!(
                    formatter,
                    "SQLite manual transaction was invalidated: {message}"
                )
            }
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
        FileControlError::IdentityCommitVetoed(veto, cleanup) => {
            let cleanup = cleanup.map_or_else(
                || additional.to_string(),
                |cleanup| format!("{cleanup}; {additional}"),
            );
            FileControlError::IdentityCommitVetoed(veto, Some(cleanup))
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
        let remaining = state
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        std::thread::sleep(remaining.min(std::time::Duration::from_millis(1)));
        i32::from(
            !state.cancelled.load(Ordering::Acquire) && std::time::Instant::now() < state.deadline,
        )
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
const TERMINAL_RESERVATIONS_PER_OWNER: usize = TERMINAL_CLOSE_SLOTS_PER_OWNER + 1;
const MAX_TERMINAL_CLOSE_JOBS: usize = MAX_CLEANUP_JOBS * TERMINAL_RESERVATIONS_PER_OWNER;
const TERMINAL_CLOSE_THREADS: usize = 4;
const TERMINAL_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(25);
static ACTIVE_CLEANUP_JOBS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_TERMINAL_CLOSE_JOBS: AtomicUsize = AtomicUsize::new(0);
static CLEANUP_ADMISSION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static LIVE_CLEANUP_WORKERS: AtomicUsize = AtomicUsize::new(0);
static LIVE_TERMINAL_CLOSE_WORKERS: AtomicUsize = AtomicUsize::new(0);
static CLEANUP_EXECUTOR_HEALTHY: AtomicBool = AtomicBool::new(true);
static TERMINAL_CLOSE_EXECUTOR_HEALTHY: AtomicBool = AtomicBool::new(true);
static EXECUTOR_HEALTH_GENERATION: AtomicU64 = AtomicU64::new(1);
static CLEANUP_JOB_PANICS: AtomicUsize = AtomicUsize::new(0);
static TERMINAL_CLOSE_JOB_PANICS: AtomicUsize = AtomicUsize::new(0);

struct CleanupReservation;

impl Drop for CleanupReservation {
    fn drop(&mut self) {
        ACTIVE_CLEANUP_JOBS.fetch_sub(1, Ordering::AcqRel);
    }
}

struct DropSlot<T>(Option<std::mem::ManuallyDrop<T>>);

impl<T> DropSlot<T> {
    fn new(value: T) -> Self {
        Self(Some(std::mem::ManuallyDrop::new(value)))
    }

    const fn empty() -> Self {
        Self(None)
    }

    fn take(&mut self) -> Option<T> {
        self.0.take().map(std::mem::ManuallyDrop::into_inner)
    }

    fn take_slot(&mut self) -> Self {
        Self(self.0.take())
    }
}

struct RetainedDropInner<T> {
    value: std::sync::Mutex<DropSlot<T>>,
    panicked: AtomicBool,
}

struct RetainedDrop<T>(Arc<RetainedDropInner<T>>);

impl<T> Clone for RetainedDrop<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> RetainedDrop<T> {
    fn new(value: T) -> Self {
        Self(Arc::new(RetainedDropInner {
            value: std::sync::Mutex::new(DropSlot::new(value)),
            panicked: AtomicBool::new(false),
        }))
    }

    fn with_mut<Result>(&self, operation: impl FnOnce(&mut T) -> Result) -> Option<Result> {
        if self.0.panicked.load(Ordering::Acquire) {
            return None;
        }
        self.0
            .value
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0
            .as_deref_mut()
            .map(operation)
    }

    fn destroy_once(&self) -> Result<(), ()> {
        if self.0.panicked.load(Ordering::Acquire) {
            return Err(());
        }
        let mut slot = self
            .0
            .value
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(value) = slot.0.as_mut() else {
            return Ok(());
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            std::mem::ManuallyDrop::drop(value);
        })) {
            Ok(()) => {
                // The value has been destroyed in place. Overwrite the wrapper
                // without moving a potentially drop-sensitive value.
                unsafe {
                    std::ptr::write(&raw mut slot.0, None);
                }
                Ok(())
            }
            Err(panic) => {
                self.0.panicked.store(true, Ordering::Release);
                // A partially destroyed value must remain at its stable address,
                // even if a future caller accidentally releases the quarantine.
                std::mem::forget(Arc::clone(&self.0));
                std::mem::forget(panic);
                Err(())
            }
        }
    }
}

trait RetainedDestructor: Send {
    fn destroy_once(&self) -> Result<(), ()>;
}

impl<T: Send + 'static> RetainedDestructor for RetainedDrop<T> {
    fn destroy_once(&self) -> Result<(), ()> {
        RetainedDrop::destroy_once(self)
    }
}

struct CleanupEnvelope {
    job: DropSlot<BlockingCleanupJob>,
    panic_retention: Option<RetainedDrop<Box<dyn Send>>>,
    callback_retention: Option<Box<dyn RetainedDestructor>>,
    reservation: DropSlot<CleanupReservation>,
    retirement_reservation: DropSlot<TerminalCloseReservation>,
}

struct CleanupExecutor {
    sender: std::sync::mpsc::SyncSender<CleanupEnvelope>,
    _receiver: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<CleanupEnvelope>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalJobDisposition {
    Completed,
    Quarantined,
}

type TerminalCloseJob =
    Box<dyn FnOnce(&tokio::runtime::Runtime) -> TerminalJobDisposition + Send + 'static>;

struct TerminalCloseReservation {
    completion_signal: Option<(Arc<AtomicU8>, u8)>,
}

impl TerminalCloseReservation {
    fn new() -> Self {
        Self {
            completion_signal: None,
        }
    }
}

impl Drop for TerminalCloseReservation {
    fn drop(&mut self) {
        ACTIVE_TERMINAL_CLOSE_JOBS.fetch_sub(1, Ordering::AcqRel);
        if let Some((signal, completed_state)) = self.completion_signal.take() {
            signal.store(completed_state, Ordering::Release);
        }
    }
}

struct TerminalCloseEnvelope {
    job: DropSlot<TerminalCloseJob>,
    panic_retention: Option<RetainedDrop<Box<dyn Send>>>,
    callback_retention: Option<Box<dyn RetainedDestructor>>,
    cleanup_reservation: DropSlot<CleanupReservation>,
    reservation: DropSlot<TerminalCloseReservation>,
}

struct TerminalCloseExecutor {
    sender: std::sync::mpsc::SyncSender<TerminalCloseEnvelope>,
    _receiver: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<TerminalCloseEnvelope>>>,
}

type CleanupQuarantine = [Option<CleanupEnvelope>; MAX_CLEANUP_JOBS];
type TerminalQuarantine = [Option<TerminalCloseEnvelope>; MAX_TERMINAL_CLOSE_JOBS];

static FAILED_CLEANUP_HANDOFFS: std::sync::LazyLock<std::sync::Mutex<CleanupQuarantine>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::array::from_fn(|_| None)));
static FAILED_TERMINAL_HANDOFFS: std::sync::LazyLock<std::sync::Mutex<TerminalQuarantine>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::array::from_fn(|_| None)));
static CLEANUP_PANIC_QUARANTINE: std::sync::LazyLock<std::sync::Mutex<CleanupQuarantine>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::array::from_fn(|_| None)));
static TERMINAL_PANIC_QUARANTINE: std::sync::LazyLock<std::sync::Mutex<TerminalQuarantine>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::array::from_fn(|_| None)));

struct WorkerLiveness {
    live: &'static AtomicUsize,
    healthy: &'static AtomicBool,
}

impl WorkerLiveness {
    fn new(live: &'static AtomicUsize, healthy: &'static AtomicBool) -> Self {
        live.fetch_add(1, Ordering::AcqRel);
        Self { live, healthy }
    }
}

impl Drop for WorkerLiveness {
    fn drop(&mut self) {
        mark_executor_unhealthy(self.healthy);
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}

fn mark_executor_unhealthy(healthy: &AtomicBool) {
    healthy.store(false, Ordering::Release);
    EXECUTOR_HEALTH_GENERATION.fetch_add(1, Ordering::AcqRel);
}

fn retain_cleanup_handoff(envelope: CleanupEnvelope) {
    let mut quarantine = FAILED_CLEANUP_HANDOFFS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(slot) = quarantine.iter_mut().find(|slot| slot.is_none()) {
        *slot = Some(envelope);
    } else {
        mark_executor_unhealthy(&CLEANUP_EXECUTOR_HEALTHY);
        std::mem::forget(envelope);
    }
}

fn retain_terminal_handoff(envelope: TerminalCloseEnvelope) {
    let mut quarantine = FAILED_TERMINAL_HANDOFFS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(slot) = quarantine.iter_mut().find(|slot| slot.is_none()) {
        *slot = Some(envelope);
    } else {
        mark_executor_unhealthy(&TERMINAL_CLOSE_EXECUTOR_HEALTHY);
        std::mem::forget(envelope);
    }
}

fn retain_cleanup_panic(quarantine: CleanupEnvelope) {
    let mut retained = CLEANUP_PANIC_QUARANTINE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(slot) = retained.iter_mut().find(|slot| slot.is_none()) {
        *slot = Some(quarantine);
    } else {
        mark_executor_unhealthy(&CLEANUP_EXECUTOR_HEALTHY);
        std::mem::forget(quarantine);
    }
}

fn retain_terminal_panic(quarantine: TerminalCloseEnvelope) {
    let mut retained = TERMINAL_PANIC_QUARANTINE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(slot) = retained.iter_mut().find(|slot| slot.is_none()) {
        *slot = Some(quarantine);
    } else {
        mark_executor_unhealthy(&TERMINAL_CLOSE_EXECUTOR_HEALTHY);
        std::mem::forget(quarantine);
    }
}

fn try_send_cleanup_envelope(
    sender: &std::sync::mpsc::SyncSender<CleanupEnvelope>,
    envelope: CleanupEnvelope,
    healthy: &AtomicBool,
) -> Result<(), String> {
    match sender.try_send(envelope) {
        Ok(()) => Ok(()),
        Err(
            std::sync::mpsc::TrySendError::Full(envelope)
            | std::sync::mpsc::TrySendError::Disconnected(envelope),
        ) => {
            healthy.store(false, Ordering::Release);
            retain_cleanup_handoff(envelope);
            Err("cleanup executor rejected a pre-reserved job".to_owned())
        }
    }
}

fn try_send_terminal_envelope(
    sender: &std::sync::mpsc::SyncSender<TerminalCloseEnvelope>,
    envelope: TerminalCloseEnvelope,
    healthy: &AtomicBool,
) -> Result<(), String> {
    match sender.try_send(envelope) {
        Ok(()) => Ok(()),
        Err(
            std::sync::mpsc::TrySendError::Full(envelope)
            | std::sync::mpsc::TrySendError::Disconnected(envelope),
        ) => {
            healthy.store(false, Ordering::Release);
            retain_terminal_handoff(envelope);
            Err("terminal executor rejected a pre-reserved job".to_owned())
        }
    }
}

fn validate_worker_health(
    healthy: &AtomicBool,
    live: &AtomicUsize,
    expected: usize,
    name: &str,
) -> Result<(), String> {
    if !healthy.load(Ordering::Acquire) || live.load(Ordering::Acquire) != expected {
        Err(format!("{name} executor is unhealthy"))
    } else {
        Ok(())
    }
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
                        Ok(runtime) => runtime,
                        Err(error) => {
                            mark_executor_unhealthy(&CLEANUP_EXECUTOR_HEALTHY);
                            let _ = ready_tx.send(Err(error.to_string()));
                            return;
                        }
                    };
                    let _liveness =
                        WorkerLiveness::new(&LIVE_CLEANUP_WORKERS, &CLEANUP_EXECUTOR_HEALTHY);
                    let _ = ready_tx.send(Ok(()));
                    loop {
                        let envelope = receiver
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv();
                        let Ok(envelope) = envelope else {
                            return;
                        };
                        let mut envelope = envelope;
                        let job = envelope
                            .job
                            .take()
                            .expect("cleanup envelope job is single-use");
                        let _runtime_context = runtime.enter();
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            job(&runtime);
                        })) {
                            Ok(()) => {
                                let retire = TerminalCloseEnvelope {
                                    job: DropSlot::new(Box::new(|_| {
                                        TerminalJobDisposition::Completed
                                    })),
                                    panic_retention: envelope.panic_retention.take(),
                                    callback_retention: envelope.callback_retention.take(),
                                    cleanup_reservation: envelope.reservation.take_slot(),
                                    reservation: envelope.retirement_reservation.take_slot(),
                                };
                                let executor = TERMINAL_CLOSE_EXECUTOR
                                    .as_ref()
                                    .expect("terminal executor was validated before admission");
                                let _ = try_send_terminal_envelope(
                                    &executor.sender,
                                    retire,
                                    &TERMINAL_CLOSE_EXECUTOR_HEALTHY,
                                );
                            }
                            Err(panic) => {
                                std::mem::forget(panic);
                                CLEANUP_JOB_PANICS.fetch_add(1, Ordering::AcqRel);
                                retain_cleanup_panic(envelope);
                            }
                        }
                    }
                })
                .map_err(|error| {
                    mark_executor_unhealthy(&CLEANUP_EXECUTOR_HEALTHY);
                    error.to_string()
                })?;
        }
        drop(ready_tx);
        for _ in 0..CLEANUP_THREADS {
            ready_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|error| {
                    format!("cleanup executor readiness acknowledgement: {error}")
                })??;
        }
        Ok(CleanupExecutor {
            sender,
            _receiver: receiver,
        })
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
                        Ok(runtime) => runtime,
                        Err(error) => {
                            mark_executor_unhealthy(&TERMINAL_CLOSE_EXECUTOR_HEALTHY);
                            let _ = ready_tx.send(Err(error.to_string()));
                            return;
                        }
                    };
                    let _liveness = WorkerLiveness::new(
                        &LIVE_TERMINAL_CLOSE_WORKERS,
                        &TERMINAL_CLOSE_EXECUTOR_HEALTHY,
                    );
                    let _ = ready_tx.send(Ok(()));
                    loop {
                        let envelope = receiver
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv();
                        let Ok(envelope) = envelope else {
                            return;
                        };
                        let mut envelope = envelope;
                        let job = envelope
                            .job
                            .take()
                            .expect("terminal envelope job is single-use");
                        let _runtime_context = runtime.enter();
                        let disposition =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                job(&runtime)
                            }));
                        match disposition {
                            Ok(TerminalJobDisposition::Completed) => {
                                let retention_destroyed = envelope
                                    .panic_retention
                                    .as_ref()
                                    .map(RetainedDrop::destroy_once)
                                    .unwrap_or(Ok(()));
                                if retention_destroyed.is_ok() {
                                    envelope.panic_retention.take();
                                    let callback_destroyed = envelope
                                        .callback_retention
                                        .as_ref()
                                        .map(|callback| callback.destroy_once())
                                        .unwrap_or(Ok(()));
                                    if callback_destroyed.is_ok() {
                                        envelope.callback_retention.take();
                                        envelope.cleanup_reservation.take();
                                        envelope.reservation.take();
                                    } else {
                                        retain_terminal_panic(envelope);
                                    }
                                } else {
                                    retain_terminal_panic(envelope);
                                }
                            }
                            Ok(TerminalJobDisposition::Quarantined) => {
                                retain_terminal_panic(envelope);
                            }
                            Err(panic) => {
                                std::mem::forget(panic);
                                TERMINAL_CLOSE_JOB_PANICS.fetch_add(1, Ordering::AcqRel);
                                retain_terminal_panic(envelope);
                            }
                        }
                    }
                })
                .map_err(|error| {
                    mark_executor_unhealthy(&TERMINAL_CLOSE_EXECUTOR_HEALTHY);
                    error.to_string()
                })?;
        }
        drop(ready_tx);
        for _ in 0..TERMINAL_CLOSE_THREADS {
            ready_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|error| {
                    format!("terminal close executor readiness acknowledgement: {error}")
                })??;
        }
        Ok(TerminalCloseExecutor {
            sender,
            _receiver: receiver,
        })
    });

/// Result of transferring a physical SQLite close to the bounded close executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalCloseOutcome {
    /// SQLx and the SQLite VFS completed the close.
    Closed,
    /// The close completed with an observable error.
    Failed(String),
    /// The terminal callback panicked and its remaining ownership was quarantined.
    Panicked,
    /// The fixed cutoff elapsed; the bounded quarantine still owns the close.
    Quarantined,
}

struct TerminalCloseReceipt {
    result: std::sync::mpsc::Receiver<TerminalCloseOutcome>,
}

impl TerminalCloseReceipt {
    fn wait(self, cutoff: std::time::Instant) -> TerminalCloseOutcome {
        match self.result.try_recv() {
            Ok(outcome) => return outcome,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return TerminalCloseOutcome::Quarantined;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        let remaining = cutoff.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return TerminalCloseOutcome::Quarantined;
        }
        match self.result.recv_timeout(remaining) {
            Ok(outcome) => outcome,
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

/// Linear pre-reserved permission to submit exactly one terminal job.
pub struct TerminalClosePermit {
    reservation: Option<TerminalCloseReservation>,
}

struct TerminalClosePayload<Connection: BeginOwnedConnection> {
    close: RetainedTerminalClose<Connection>,
    authorizer_address: usize,
    retention: Option<RetainedDrop<Arc<dyn Send + Sync>>>,
    result: Option<std::sync::mpsc::SyncSender<TerminalCloseOutcome>>,
}

impl TerminalCloseBatch {
    /// Takes capacity before a caller transfers any connection or retention ownership.
    pub fn take_permit(&mut self) -> Result<TerminalClosePermit, String> {
        self.reservations
            .pop()
            .map(|reservation| TerminalClosePermit {
                reservation: Some(reservation),
            })
            .ok_or_else(|| "terminal batch capacity is exhausted".to_owned())
    }
}

impl TerminalClosePermit {
    fn submit_job(
        self,
        job: TerminalCloseJob,
        panic_retention: Option<Box<dyn Send>>,
    ) -> Result<(), String> {
        self.submit_job_with_cleanup(job, panic_retention, None)
    }

    fn submit_job_with_cleanup(
        mut self,
        job: TerminalCloseJob,
        panic_retention: Option<Box<dyn Send>>,
        cleanup_reservation: Option<CleanupReservation>,
    ) -> Result<(), String> {
        let reservation = self
            .reservation
            .take()
            .expect("terminal permit submission is single-use");
        let envelope = TerminalCloseEnvelope {
            job: DropSlot::new(job),
            panic_retention: panic_retention.map(RetainedDrop::new),
            callback_retention: None,
            cleanup_reservation: cleanup_reservation
                .map(DropSlot::new)
                .unwrap_or_else(DropSlot::empty),
            reservation: DropSlot::new(reservation),
        };
        let executor = match TERMINAL_CLOSE_EXECUTOR.as_ref() {
            Ok(executor) => executor,
            Err(error) => {
                mark_executor_unhealthy(&TERMINAL_CLOSE_EXECUTOR_HEALTHY);
                retain_terminal_handoff(envelope);
                return Err(format!("terminal executor unavailable: {error}"));
            }
        };
        let result = try_send_terminal_envelope(
            &executor.sender,
            envelope,
            &TERMINAL_CLOSE_EXECUTOR_HEALTHY,
        );
        if result.is_err() {
            EXECUTOR_HEALTH_GENERATION.fetch_add(1, Ordering::AcqRel);
        }
        result
    }

    fn submit_full<Connection: BeginOwnedConnection>(
        self,
        connection: Connection,
        authorizer_address: usize,
        retention: Option<Arc<dyn Send + Sync>>,
    ) -> TerminalCloseReceipt {
        self.submit_retained_full(
            RetainedTerminalClose::new(connection),
            authorizer_address,
            retention,
        )
    }

    fn submit_retained_full<Connection: BeginOwnedConnection>(
        self,
        close: RetainedTerminalClose<Connection>,
        authorizer_address: usize,
        retention: Option<Arc<dyn Send + Sync>>,
    ) -> TerminalCloseReceipt {
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let payload = Arc::new(std::sync::Mutex::new(TerminalClosePayload {
            close,
            authorizer_address,
            retention: retention.map(RetainedDrop::new),
            result: Some(result_tx),
        }));
        let job_payload = Arc::clone(&payload);
        let job: TerminalCloseJob = Box::new(move |runtime| {
            let mut payload = job_payload
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match payload.close.run(runtime) {
                TerminalCloseOutcome::Closed => {
                    if !payload.close.finish_success() {
                        if let Some(result) = payload.result.take() {
                            let _ = result.send(TerminalCloseOutcome::Panicked);
                        }
                        return TerminalJobDisposition::Quarantined;
                    }
                    if payload
                        .retention
                        .as_ref()
                        .map(RetainedDrop::destroy_once)
                        .unwrap_or(Ok(()))
                        .is_err()
                    {
                        if let Some(result) = payload.result.take() {
                            let _ = result.send(TerminalCloseOutcome::Panicked);
                        }
                        return TerminalJobDisposition::Quarantined;
                    }
                    payload.retention.take();
                    if payload.authorizer_address != 0 {
                        // SAFETY: terminal connection ownership keeps SQLite's
                        // pApp live until the close future has completed.
                        unsafe {
                            drop(Box::from_raw(
                                payload.authorizer_address as *mut TransactionAuthorizerContext,
                            ));
                        }
                        payload.authorizer_address = 0;
                    }
                    if let Some(result) = payload.result.take() {
                        let _ = result.send(TerminalCloseOutcome::Closed);
                    }
                    TerminalJobDisposition::Completed
                }
                TerminalCloseOutcome::Failed(error) => {
                    if let Some(result) = payload.result.take() {
                        let _ = result.send(TerminalCloseOutcome::Failed(error));
                    }
                    TerminalJobDisposition::Quarantined
                }
                TerminalCloseOutcome::Panicked | TerminalCloseOutcome::Quarantined => {
                    if let Some(result) = payload.result.take() {
                        let _ = result.send(TerminalCloseOutcome::Panicked);
                    }
                    TerminalJobDisposition::Quarantined
                }
            }
        });
        let _ = self.submit_job(job, Some(Box::new(payload)));
        TerminalCloseReceipt { result: result_rx }
    }

    fn submit_with_authorizer<Connection: BeginOwnedConnection>(
        self,
        connection: Connection,
        authorizer_address: usize,
    ) -> TerminalCloseReceipt {
        self.submit_full(connection, authorizer_address, None)
    }

    fn submit<Connection: BeginOwnedConnection>(
        self,
        connection: Connection,
    ) -> TerminalCloseReceipt {
        self.submit_with_authorizer(connection, 0)
    }

    fn submit_retaining<Connection, Retention>(
        self,
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
        self,
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
        self,
        connection: Connection,
    ) -> TerminalCloseOutcome {
        self.submit(connection)
            .wait(std::time::Instant::now() + TERMINAL_CLOSE_TIMEOUT)
    }
}

/// Pre-acquired dedicated owner for cancellation-safe blocking cleanup.
pub struct BlockingCleanupOwner {
    reservation: Option<CleanupReservation>,
    terminal_closes: Option<TerminalCloseBatch>,
    retirement_reservation: Option<TerminalCloseReservation>,
}

/// Opaque pre-reserved capacity for a trusted external bounded worker.
pub struct ExternalCleanupPermit {
    reservation: Option<CleanupReservation>,
    terminal_closes: Option<TerminalCloseBatch>,
    retirement_reservation: Option<TerminalCloseReservation>,
}

impl ExternalCleanupPermit {
    /// Borrows the pre-reserved terminal close batch.
    pub fn terminal_closes(&mut self) -> &mut TerminalCloseBatch {
        self.terminal_closes
            .as_mut()
            .expect("external cleanup terminal capacity remains owned")
    }

    /// Transfers callback capture destruction to the terminal executor.
    pub fn retire(self, retention: Box<dyn Send>) -> Result<(), String> {
        self.retire_inner(retention, None)
    }

    /// Transfers capture destruction and signals after all reserved cleanup capacity is released.
    #[doc(hidden)]
    pub fn retire_with_completion_signal(
        self,
        retention: Box<dyn Send>,
        signal: Arc<AtomicU8>,
        completed_state: u8,
    ) -> Result<(), String> {
        self.retire_inner(retention, Some((signal, completed_state)))
    }

    fn retire_inner(
        mut self,
        retention: Box<dyn Send>,
        completion_signal: Option<(Arc<AtomicU8>, u8)>,
    ) -> Result<(), String> {
        let reservation = self
            .reservation
            .take()
            .expect("external cleanup reservation remains owned");
        let mut retirement_reservation = self
            .retirement_reservation
            .take()
            .expect("external cleanup retirement capacity remains owned");
        retirement_reservation.completion_signal = completion_signal;
        self.terminal_closes.take();
        let envelope = TerminalCloseEnvelope {
            job: DropSlot::new(Box::new(|_| TerminalJobDisposition::Completed)),
            panic_retention: Some(RetainedDrop::new(retention)),
            callback_retention: None,
            cleanup_reservation: DropSlot::new(reservation),
            reservation: DropSlot::new(retirement_reservation),
        };
        let executor = match TERMINAL_CLOSE_EXECUTOR.as_ref() {
            Ok(executor) => executor,
            Err(error) => {
                mark_executor_unhealthy(&TERMINAL_CLOSE_EXECUTOR_HEALTHY);
                retain_terminal_handoff(envelope);
                return Err(format!("terminal executor unavailable: {error}"));
            }
        };
        try_send_terminal_envelope(&executor.sender, envelope, &TERMINAL_CLOSE_EXECUTOR_HEALTHY)
    }
}

impl std::fmt::Debug for BlockingCleanupOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BlockingCleanupOwner")
            .finish_non_exhaustive()
    }
}

impl BlockingCleanupOwner {
    fn validate_executor(thread_name: &str) -> Result<&'static CleanupExecutor, String> {
        if thread_name.contains('\0') {
            return Err("blocking cleanup owner name contains a NUL byte".to_owned());
        }
        let executor = CLEANUP_EXECUTOR.as_ref().map_err(Clone::clone)?;
        let _ = TERMINAL_CLOSE_EXECUTOR.as_ref().map_err(Clone::clone)?;
        validate_worker_health(
            &CLEANUP_EXECUTOR_HEALTHY,
            &LIVE_CLEANUP_WORKERS,
            CLEANUP_THREADS,
            "blocking cleanup",
        )?;
        validate_worker_health(
            &TERMINAL_CLOSE_EXECUTOR_HEALTHY,
            &LIVE_TERMINAL_CLOSE_WORKERS,
            TERMINAL_CLOSE_THREADS,
            "terminal cleanup",
        )?;
        Ok(executor)
    }

    /// Acquires and readies a dedicated cleanup runtime without blocking Tokio.
    pub async fn acquire(thread_name: &str) -> Result<Self, String> {
        let mut owners = Self::acquire_many_until(thread_name, 1, None, false).await?;
        Ok(owners.pop().expect("one cleanup owner was reserved"))
    }

    /// Atomically reserves a complete owner set before an operation acquires resources.
    pub async fn acquire_set(
        thread_name: &str,
        count: usize,
        deadline: std::time::Instant,
    ) -> Result<Vec<Self>, String> {
        Self::acquire_many_until(thread_name, count, Some(deadline), false).await
    }

    async fn acquire_many_until(
        thread_name: &str,
        count: usize,
        deadline: Option<std::time::Instant>,
        allow_expired_first_attempt: bool,
    ) -> Result<Vec<Self>, String> {
        if count == 0 || count > MAX_CLEANUP_JOBS {
            return Err("blocking cleanup owner count is out of range".to_owned());
        }
        let deadline_expired =
            deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline);
        if deadline_expired && !allow_expired_first_attempt {
            return Err("blocking cleanup owner admission timed out".to_owned());
        }
        if let Some(deadline) = deadline {
            if deadline_expired {
                let _ = Self::validate_executor(thread_name)?;
            } else {
                let thread_name = thread_name.to_owned();
                tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    tokio::task::spawn_blocking(move || {
                        Self::validate_executor(&thread_name).map(|_| ())
                    }),
                )
                .await
                .map_err(|_| "blocking cleanup executor readiness timed out".to_owned())?
                .map_err(|error| format!("blocking cleanup executor readiness task: {error}"))??;
            }
        } else {
            let _ = Self::validate_executor(thread_name)?;
        }
        let health_generation = EXECUTOR_HEALTH_GENERATION.load(Ordering::Acquire);
        loop {
            let expired = deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline);
            if expired && !allow_expired_first_attempt {
                return Err("blocking cleanup owner admission timed out".to_owned());
            }
            let _ = Self::validate_executor(thread_name)?;
            if EXECUTOR_HEALTH_GENERATION.load(Ordering::Acquire) != health_generation {
                return Err("cleanup executor health changed during admission".to_owned());
            }
            let terminal_count = count
                .checked_mul(TERMINAL_RESERVATIONS_PER_OWNER)
                .ok_or_else(|| "terminal close owner count overflowed".to_owned())?;
            let admission = CLEANUP_ADMISSION_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let active = ACTIVE_CLEANUP_JOBS.load(Ordering::Acquire);
            let active_terminal = ACTIVE_TERMINAL_CLOSE_JOBS.load(Ordering::Acquire);
            if active > MAX_CLEANUP_JOBS - count
                || active_terminal > MAX_TERMINAL_CLOSE_JOBS - terminal_count
            {
                drop(admission);
                if allow_expired_first_attempt {
                    return Err("blocking cleanup owner capacity is exhausted".to_owned());
                }
                tokio::task::yield_now().await;
                continue;
            }
            ACTIVE_CLEANUP_JOBS.fetch_add(count, Ordering::AcqRel);
            ACTIVE_TERMINAL_CLOSE_JOBS.fetch_add(terminal_count, Ordering::AcqRel);
            drop(admission);
            if EXECUTOR_HEALTH_GENERATION.load(Ordering::Acquire) != health_generation
                || Self::validate_executor(thread_name).is_err()
            {
                ACTIVE_CLEANUP_JOBS.fetch_sub(count, Ordering::AcqRel);
                ACTIVE_TERMINAL_CLOSE_JOBS.fetch_sub(terminal_count, Ordering::AcqRel);
                return Err("cleanup executor became unhealthy during admission".to_owned());
            }
            if !allow_expired_first_attempt
                && deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                ACTIVE_CLEANUP_JOBS.fetch_sub(count, Ordering::AcqRel);
                ACTIVE_TERMINAL_CLOSE_JOBS.fetch_sub(terminal_count, Ordering::AcqRel);
                return Err("blocking cleanup owner admission timed out".to_owned());
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
                            .map(|_| TerminalCloseReservation::new())
                            .collect(),
                    }),
                    retirement_reservation: Some(TerminalCloseReservation::new()),
                });
            }
            return Ok(owners);
        }
    }

    #[cfg(test)]
    fn acquire_without_runtime(thread_name: &str) -> Result<Self, String> {
        let _ = Self::validate_executor(thread_name)?;
        let health_generation = EXECUTOR_HEALTH_GENERATION.load(Ordering::Acquire);
        let admission = CLEANUP_ADMISSION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let active = ACTIVE_CLEANUP_JOBS.load(Ordering::Acquire);
        if active >= MAX_CLEANUP_JOBS {
            return Err("blocking cleanup owner capacity is exhausted".to_owned());
        }
        let terminal_active = ACTIVE_TERMINAL_CLOSE_JOBS.load(Ordering::Acquire);
        if terminal_active > MAX_TERMINAL_CLOSE_JOBS - TERMINAL_RESERVATIONS_PER_OWNER {
            return Err("terminal close owner capacity is exhausted".to_owned());
        }
        ACTIVE_CLEANUP_JOBS.fetch_add(1, Ordering::AcqRel);
        ACTIVE_TERMINAL_CLOSE_JOBS.fetch_add(TERMINAL_RESERVATIONS_PER_OWNER, Ordering::AcqRel);
        drop(admission);
        if EXECUTOR_HEALTH_GENERATION.load(Ordering::Acquire) != health_generation
            || Self::validate_executor(thread_name).is_err()
        {
            ACTIVE_TERMINAL_CLOSE_JOBS.fetch_sub(TERMINAL_RESERVATIONS_PER_OWNER, Ordering::AcqRel);
            ACTIVE_CLEANUP_JOBS.fetch_sub(1, Ordering::AcqRel);
            return Err("cleanup executor became unhealthy during admission".to_owned());
        }
        Ok(Self {
            reservation: Some(CleanupReservation),
            terminal_closes: Some(TerminalCloseBatch {
                reservations: (0..TERMINAL_CLOSE_SLOTS_PER_OWNER)
                    .map(|_| TerminalCloseReservation::new())
                    .collect(),
            }),
            retirement_reservation: Some(TerminalCloseReservation::new()),
        })
    }

    /// Transfers terminal cleanup to the dedicated runtime.
    #[cfg(test)]
    fn handoff<Cleanup>(&mut self, cleanup: Cleanup) -> Result<(), String>
    where
        Cleanup: FnOnce(&tokio::runtime::Runtime, TerminalCloseBatch) + Send + 'static,
    {
        self.handoff_with_panic_retention(cleanup, None)
    }

    /// Converts this owner into opaque capacity for another bounded executor.
    pub fn into_external_cleanup(mut self) -> Result<ExternalCleanupPermit, String> {
        Ok(ExternalCleanupPermit {
            reservation: Some(
                self.reservation
                    .take()
                    .ok_or_else(|| "blocking cleanup owner is missing".to_owned())?,
            ),
            terminal_closes: Some(
                self.terminal_closes
                    .take()
                    .ok_or_else(|| "terminal close owner is missing".to_owned())?,
            ),
            retirement_reservation: Some(
                self.retirement_reservation
                    .take()
                    .ok_or_else(|| "cleanup retirement owner is missing".to_owned())?,
            ),
        })
    }

    fn handoff_payload_internal<Payload, Cleanup>(
        &mut self,
        payload: Payload,
        cleanup: Cleanup,
    ) -> Result<(), String>
    where
        Payload: Send + 'static,
        Cleanup:
            FnMut(&tokio::runtime::Runtime, &mut TerminalCloseBatch, &Payload) + Send + 'static,
    {
        let reservation = self
            .reservation
            .take()
            .expect("blocking cleanup payload handoff is single-use");
        let terminal_closes = self
            .terminal_closes
            .take()
            .expect("terminal close payload handoff is single-use");
        let retirement_reservation = self
            .retirement_reservation
            .take()
            .expect("cleanup retirement capacity was pre-reserved");
        let payload = Arc::new(std::sync::Mutex::new(payload));
        let job_payload = Arc::clone(&payload);
        let terminal_closes = Arc::new(std::sync::Mutex::new(terminal_closes));
        let job_terminal_closes = Arc::clone(&terminal_closes);
        let cleanup = RetainedDrop::new(cleanup);
        let job_cleanup = cleanup.clone();
        let envelope = CleanupEnvelope {
            job: DropSlot::new(Box::new(move |runtime| {
                let payload = job_payload
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut terminal_closes = job_terminal_closes
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                job_cleanup
                    .with_mut(|cleanup| cleanup(runtime, &mut terminal_closes, &payload))
                    .expect("cleanup callback remains owned");
            })),
            panic_retention: Some(RetainedDrop::new(Box::new((payload, terminal_closes)))),
            callback_retention: Some(Box::new(cleanup)),
            reservation: DropSlot::new(reservation),
            retirement_reservation: DropSlot::new(retirement_reservation),
        };
        let executor = match CLEANUP_EXECUTOR.as_ref() {
            Ok(executor) => executor,
            Err(error) => {
                mark_executor_unhealthy(&CLEANUP_EXECUTOR_HEALTHY);
                retain_cleanup_handoff(envelope);
                return Err(format!("cleanup executor unavailable: {error}"));
            }
        };
        let result =
            try_send_cleanup_envelope(&executor.sender, envelope, &CLEANUP_EXECUTOR_HEALTHY);
        if result.is_err() {
            EXECUTOR_HEALTH_GENERATION.fetch_add(1, Ordering::AcqRel);
        }
        result
    }

    /// Takes one terminal permit before a caller moves any resource into cleanup.
    pub fn take_terminal_permit(&mut self) -> Result<TerminalClosePermit, String> {
        self.terminal_closes
            .as_mut()
            .ok_or_else(|| "terminal close owner is missing".to_owned())?
            .take_permit()
    }

    #[cfg(test)]
    fn handoff_with_panic_retention<Cleanup>(
        &mut self,
        cleanup: Cleanup,
        panic_retention: Option<Box<dyn Send>>,
    ) -> Result<(), String>
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
        let retirement_reservation = self
            .retirement_reservation
            .take()
            .expect("cleanup retirement capacity was pre-reserved");
        let envelope = CleanupEnvelope {
            job: DropSlot::new(Box::new(move |runtime| cleanup(runtime, terminal_closes))),
            panic_retention: panic_retention.map(RetainedDrop::new),
            callback_retention: None,
            reservation: DropSlot::new(reservation),
            retirement_reservation: DropSlot::new(retirement_reservation),
        };
        let executor = match CLEANUP_EXECUTOR.as_ref() {
            Ok(executor) => executor,
            Err(error) => {
                mark_executor_unhealthy(&CLEANUP_EXECUTOR_HEALTHY);
                retain_cleanup_handoff(envelope);
                return Err(format!("cleanup executor unavailable: {error}"));
            }
        };
        let result =
            try_send_cleanup_envelope(&executor.sender, envelope, &CLEANUP_EXECUTOR_HEALTHY);
        if result.is_err() {
            EXECUTOR_HEALTH_GENERATION.fetch_add(1, Ordering::AcqRel);
        }
        result
    }

    /// Shuts down an unused cleanup owner without waiting on a runtime thread.
    pub fn shutdown(mut self) -> Result<(), String> {
        self.reservation
            .take()
            .ok_or_else(|| "blocking cleanup owner is missing".to_owned())?;
        self.terminal_closes
            .take()
            .ok_or_else(|| "terminal close owner is missing".to_owned())?;
        self.retirement_reservation
            .take()
            .ok_or_else(|| "cleanup retirement owner is missing".to_owned())?;
        Ok(())
    }
}

impl Drop for BlockingCleanupOwner {
    fn drop(&mut self) {
        self.reservation.take();
        self.terminal_closes.take();
        self.retirement_reservation.take();
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

#[cfg(unix)]
unsafe extern "C" fn drop_unix_identity_invalidation(value: *mut std::ffi::c_void) {
    if !value.is_null() {
        // SAFETY: this key is exclusively registered with a Box<AtomicBool>.
        drop(unsafe { Box::from_raw(value.cast::<AtomicBool>()) });
    }
}

#[cfg(unix)]
fn unix_identity_invalidation(
    database: LiveInterruptPointer,
) -> Result<NonNull<AtomicBool>, FileControlError> {
    // SAFETY: the caller holds SQLx's locked live SQLite handle.
    let existing = unsafe {
        libsqlite3_sys::sqlite3_get_clientdata(
            database.as_ptr(),
            c"gta-claw-unix-identity-invalidated".as_ptr(),
        )
    };
    if let Some(existing) = NonNull::new(existing.cast::<AtomicBool>()) {
        return Ok(existing);
    }
    let state = Box::into_raw(Box::new(AtomicBool::new(false)));
    // SAFETY: SQLite owns `state` after registration.
    let result = unsafe {
        libsqlite3_sys::sqlite3_set_clientdata(
            database.as_ptr(),
            c"gta-claw-unix-identity-invalidated".as_ptr(),
            state.cast(),
            Some(drop_unix_identity_invalidation),
        )
    };
    if result != libsqlite3_sys::SQLITE_OK {
        return Err(FileControlError::SQLite(result));
    }
    NonNull::new(state).ok_or_else(|| {
        FileControlError::Handle("Unix identity invalidation state is null".to_owned())
    })
}

/// Returns whether SQLite reports that its open main database was moved or replaced.
///
/// Once observed, invalidation remains latched for the connection lifetime.
#[cfg(unix)]
pub async fn main_database_has_moved(
    connection: &mut sqlx::SqliteConnection,
) -> Result<bool, FileControlError> {
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let database_pointer = LiveInterruptPointer(database.as_raw_handle());
    let invalidated = unix_identity_invalidation(database_pointer)?;
    // SAFETY: SQLite client data retains this AtomicBool for the connection lifetime.
    if unsafe { invalidated.as_ref() }.load(Ordering::Acquire) {
        return Ok(true);
    }
    let mut moved = 0_i32;
    // SAFETY: SQLx's locked handle guarantees a live SQLite connection for this
    // call. The schema name is NUL-terminated and `moved` remains valid.
    let result = unsafe {
        libsqlite3_sys::sqlite3_file_control(
            database_pointer.as_ptr(),
            c"main".as_ptr(),
            libsqlite3_sys::SQLITE_FCNTL_HAS_MOVED,
            (&raw mut moved).cast(),
        )
    };
    if result == libsqlite3_sys::SQLITE_OK {
        if moved != 0 {
            // SAFETY: SQLite client data retains this AtomicBool for the connection lifetime.
            unsafe { invalidated.as_ref() }.store(true, Ordering::Release);
        }
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
            | libsqlite3_sys::SQLITE_LOCKED => {
                let remaining = context
                    .deadline
                    .saturating_duration_since(std::time::Instant::now());
                tokio::time::sleep(remaining.min(std::time::Duration::from_millis(1))).await;
            }
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
    source: Source,
    destination: Destination,
    reservation: Reservation,
    context: BackupExecutionContext,
) -> Result<(Source, Destination, Reservation), FileControlError>
where
    Source: BeginOwnedConnection,
    Destination: BeginOwnedConnection,
    Reservation: Send + 'static,
{
    type BackupWorkerResult<Source, Destination, Reservation> = Result<
        (
            Source,
            Destination,
            Reservation,
            TerminalClosePermit,
            TerminalClosePermit,
        ),
        FileControlError,
    >;

    struct BackupWorkerPayload<Source, Destination, Reservation> {
        source: Option<Source>,
        destination: Option<Destination>,
        reservation: Option<Reservation>,
        close_retention: Option<Arc<std::sync::Mutex<Option<Reservation>>>>,
        result: Option<
            std::sync::mpsc::SyncSender<BackupWorkerResult<Source, Destination, Reservation>>,
        >,
    }

    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(0);
    let deadline = context.deadline;
    let delivery_cancelled = Arc::clone(&context.cancelled);
    worker_owner
        .handoff_payload_internal(
        std::sync::Mutex::new(BackupWorkerPayload {
            source: Some(source),
            destination: Some(destination),
            reservation: Some(reservation),
            close_retention: None,
            result: Some(result_tx),
        }),
        move |runtime, terminal_closes, payload| {
        let mut payload = payload
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut source_close_permit = Some(
            terminal_closes
                .take_permit()
                .expect("backup source close capacity was pre-reserved"),
        );
        let mut destination_close_permit = Some(
            terminal_closes
                .take_permit()
                .expect("backup destination close capacity was pre-reserved"),
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let BackupWorkerPayload {
                source,
                destination,
                ..
            } = &mut *payload;
            runtime.block_on(backup_main_database(
                source
                    .as_mut()
                    .expect("backup source remains owned")
                    .sqlite(),
                destination
                    .as_mut()
                    .expect("backup destination remains owned")
                    .sqlite(),
                &context,
            ))
        }))
        .unwrap_or_else(|_| {
            Err(FileControlError::Handle(
                "logical backup worker panicked".to_owned(),
            ))
        });
        match result {
            Ok(()) => {
                let source = payload.source.take().expect("backup source remains owned");
                let destination = payload
                    .destination
                    .take()
                    .expect("backup destination remains owned");
                let reservation = payload
                    .reservation
                    .take()
                    .expect("backup reservation remains owned");
                let result_tx = payload.result.take().expect("backup result remains owned");
                let source_close_permit = source_close_permit
                    .take()
                    .expect("backup source close permit remains owned");
                let destination_close_permit = destination_close_permit
                    .take()
                    .expect("backup destination close permit remains owned");
                if let Err(error) = result_tx.send(Ok((
                    source,
                    destination,
                    reservation,
                    source_close_permit,
                    destination_close_permit,
                ))) && let Ok((
                    source,
                    destination,
                    reservation,
                    source_close_permit,
                    destination_close_permit,
                )) = error.0
                {
                    let retention = Arc::new(std::sync::Mutex::new(Some(reservation)));
                    let source_close =
                        source_close_permit.submit_retaining(source, Arc::clone(&retention));
                    let destination_close = destination_close_permit
                        .submit_retaining(destination, Arc::clone(&retention));
                    payload.close_retention = Some(retention);
                    let cutoff = std::time::Instant::now() + TERMINAL_CLOSE_TIMEOUT;
                    let _ = source_close.wait(cutoff);
                    let _ = destination_close.wait(cutoff);
                }
            }
            Err(error) => {
                let source = payload.source.take().expect("backup source remains owned");
                let destination = payload
                    .destination
                    .take()
                    .expect("backup destination remains owned");
                let reservation = payload
                    .reservation
                    .take()
                    .expect("backup reservation remains owned");
                let result_tx = payload.result.take().expect("backup result remains owned");
                let retention = Arc::new(std::sync::Mutex::new(Some(reservation)));
                let source_close = source_close_permit
                    .take()
                    .expect("backup source close permit remains owned")
                    .submit_retaining(source, Arc::clone(&retention));
                let destination_close = destination_close_permit
                    .take()
                    .expect("backup destination close permit remains owned")
                    .submit_retaining(destination, Arc::clone(&retention));
                payload.close_retention = Some(retention);
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
        },
        )
        .map_err(FileControlError::Handle)?;
    let cleanup_cutoff = deadline + std::time::Duration::from_secs(5);
    loop {
        match result_rx.try_recv() {
            Ok(Ok((
                source,
                destination,
                reservation,
                source_close_permit,
                destination_close_permit,
            ))) => {
                if delivery_cancelled.load(Ordering::Acquire)
                    || std::time::Instant::now() >= deadline
                {
                    let retention = Arc::new(std::sync::Mutex::new(Some(reservation)));
                    let source_close =
                        source_close_permit.submit_retaining(source, Arc::clone(&retention));
                    let destination_close = destination_close_permit
                        .submit_retaining(destination, Arc::clone(&retention));
                    let cutoff = std::time::Instant::now() + TERMINAL_CLOSE_TIMEOUT;
                    let _ = source_close.wait(cutoff);
                    let _ = destination_close.wait(cutoff);
                    return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
                }
                drop((source_close_permit, destination_close_permit));
                return Ok((source, destination, reservation));
            }
            Ok(Err(error)) => return Err(error),
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
    connection: sqlx::SqliteConnection,
    output: std::fs::File,
    mut cleanup: Cleanup,
    context: SnapshotFinalizeContext,
) -> Result<(SnapshotWriteReceipt, Cleanup), FileControlError>
where
    Cleanup: SnapshotCleanupLease,
{
    type FinalizeWorkerResult<Cleanup> =
        Result<(SnapshotWriteReceipt, Cleanup), (FileControlError, Cleanup)>;

    struct FinalizeWorkerPayload<Cleanup> {
        connection: Option<sqlx::SqliteConnection>,
        output: Option<std::fs::File>,
        cleanup: Option<Cleanup>,
        close_retention: Arc<std::sync::Mutex<Option<Box<dyn Send>>>>,
        result: Option<std::sync::mpsc::SyncSender<FinalizeWorkerResult<Cleanup>>>,
    }

    let SnapshotFinalizeContext {
        output_path,
        deadline,
        cancelled,
        maximum_bytes,
    } = context;
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(0);
    let delivery_cancelled = Arc::clone(&cancelled);
    let close_retention = Arc::new(std::sync::Mutex::new(cleanup.take_terminal_retention()));
    worker_owner
        .handoff_payload_internal(
            std::sync::Mutex::new(FinalizeWorkerPayload {
                connection: Some(connection),
                output: Some(output),
                cleanup: Some(cleanup),
                close_retention,
                result: Some(result_tx),
            }),
            move |runtime, terminal_closes, payload| {
                let mut payload = payload
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut close_permit = Some(
                    terminal_closes
                        .take_permit()
                        .expect("snapshot close capacity was pre-reserved"),
                );
                let operation = (|| {
                    if cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
                        return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
                    }
                    let serialization =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            runtime.block_on(async {
                                sqlx::query("PRAGMA journal_mode = DELETE")
                                    .execute(
                                        payload
                                            .connection
                                            .as_mut()
                                            .expect("snapshot connection remains owned"),
                                    )
                                    .await
                                    .map_err(|error| FileControlError::Handle(error.to_string()))?;
                                serialize_main_database(
                                    payload
                                        .connection
                                        .as_mut()
                                        .expect("snapshot connection remains owned"),
                                    maximum_bytes,
                                )
                                .await
                            })
                        }))
                        .unwrap_or_else(|_| {
                            Err(FileControlError::Handle(
                                "snapshot serialization worker panicked".to_owned(),
                            ))
                        });
                    let mut bytes = match serialization {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            let connection = payload
                                .connection
                                .take()
                                .expect("snapshot connection remains owned");
                            let close = close_permit
                                .take()
                                .expect("snapshot close permit remains owned")
                                .close_with_shared_retention(
                                    connection,
                                    Arc::clone(&payload.close_retention),
                                );
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
                    let connection = payload
                        .connection
                        .take()
                        .expect("snapshot connection remains owned");
                    match close_permit
                        .take()
                        .expect("snapshot close permit remains owned")
                        .close_with_shared_retention(
                            connection,
                            Arc::clone(&payload.close_retention),
                        ) {
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
                    let output = payload
                        .output
                        .as_mut()
                        .expect("snapshot output remains owned");
                    output
                        .seek(SeekFrom::Start(0))
                        .and_then(|_| output.set_len(0))
                        .map_err(|error| {
                            FileControlError::Handle(format!(
                                "prepare held snapshot output {output_path}: {error}"
                            ))
                        })?;
                    for chunk in bytes.chunks(64 * 1024) {
                        if cancelled.load(Ordering::Acquire)
                            || std::time::Instant::now() >= deadline
                        {
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
                        if cancelled.load(Ordering::Acquire)
                            || std::time::Instant::now() >= deadline
                        {
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
                        FileControlError::Handle(
                            "serialized snapshot size does not fit u64".to_owned(),
                        )
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
                let operation = if let Some(connection) = payload.connection.take() {
                    let close = close_permit
                        .take()
                        .expect("residual snapshot close permit remains owned")
                        .close_with_shared_retention(
                            connection,
                            Arc::clone(&payload.close_retention),
                        );
                    match (operation, close) {
                        (result, TerminalCloseOutcome::Closed) => result,
                        (Ok(_), close) => Err(FileControlError::Handle(format!(
                            "residual snapshot terminal close did not complete: {close:?}"
                        ))),
                        (Err(primary), close) => Err(FileControlError::Handle(format!(
                            "{primary}; residual snapshot terminal close: {close:?}"
                        ))),
                    }
                } else {
                    operation
                };
                payload.output.take();
                let cleanup = payload
                    .cleanup
                    .take()
                    .expect("snapshot cleanup remains owned");
                let result_tx = payload
                    .result
                    .take()
                    .expect("snapshot result remains owned");
                let delivered = match operation {
                    Ok(receipt) => result_tx.send(Ok((receipt, cleanup))),
                    Err(primary) => result_tx.send(Err((primary, cleanup))),
                };
                if let Err(error) = delivered {
                    match error.0 {
                        Ok((_, mut cleanup)) | Err((_, mut cleanup)) => {
                            cleanup.detach_cleanup();
                            payload.cleanup = Some(cleanup);
                        }
                    }
                }
            },
        )
        .map_err(FileControlError::Handle)?;
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
    state: Arc<ManualTransactionState>,
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

fn take_nonzero_generation(counter: &AtomicU64, name: &str) -> Result<u64, FileControlError> {
    loop {
        let current = counter.load(Ordering::Acquire);
        if current == 0 || current == u64::MAX {
            return Err(FileControlError::Handle(format!("{name} exhausted")));
        }
        if counter
            .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Ok(current);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ManualTransactionPhase {
    Healthy,
    Poisoned(String),
    Terminal,
}

struct ManualTransactionStateInner {
    phase: ManualTransactionPhase,
    next_operation: u64,
    in_flight: Option<u64>,
}

struct ManualTransactionState {
    key: (usize, u64),
    generation: u64,
    inner: std::sync::Mutex<ManualTransactionStateInner>,
    preflight_pragmas: AtomicBool,
}

type ManualTransactionRegistry =
    std::collections::HashMap<(usize, u64), Arc<ManualTransactionState>>;
static ACTIVE_MANUAL_TRANSACTIONS: std::sync::LazyLock<
    std::sync::Mutex<ManualTransactionRegistry>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

struct ActiveTransactionRegistration {
    state: Arc<ManualTransactionState>,
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
        let state = Arc::new(ManualTransactionState {
            key,
            generation,
            inner: std::sync::Mutex::new(ManualTransactionStateInner {
                phase: ManualTransactionPhase::Healthy,
                next_operation: 1,
                in_flight: None,
            }),
            preflight_pragmas: AtomicBool::new(false),
        });
        active.insert(key, Arc::clone(&state));
        Ok(Self { state, armed: true })
    }

    fn into_token(mut self, authorizer_address: usize) -> ManualTransactionToken {
        self.armed = false;
        ManualTransactionToken {
            database_address: self.state.key.0,
            connection_nonce: self.state.key.1,
            generation: self.state.generation,
            authorizer_address,
            active: true,
            state: Arc::clone(&self.state),
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
        if active
            .get(&self.state.key)
            .is_some_and(|state| Arc::ptr_eq(state, &self.state))
        {
            active.remove(&self.state.key);
        }
    }
}

fn remove_transaction_state(state: &Arc<ManualTransactionState>) {
    let mut active = ACTIVE_MANUAL_TRANSACTIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if active
        .get(&state.key)
        .is_some_and(|registered| Arc::ptr_eq(registered, state))
    {
        active.remove(&state.key);
    }
}

fn poison_transaction_state(state: &Arc<ManualTransactionState>, reason: impl Into<String>) {
    {
        let mut inner = state
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(inner.phase, ManualTransactionPhase::Healthy) {
            inner.phase = ManualTransactionPhase::Poisoned(reason.into());
        }
        inner.in_flight = None;
    }
    remove_transaction_state(state);
}

struct TransactionOperationGuard {
    state: Arc<ManualTransactionState>,
    operation: u64,
    armed: bool,
}

impl TransactionOperationGuard {
    fn begin(state: &Arc<ManualTransactionState>) -> Result<Self, sqlx::Error> {
        let mut inner = state
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &inner.phase {
            ManualTransactionPhase::Healthy => {}
            ManualTransactionPhase::Poisoned(reason) => {
                return Err(sqlx::Error::Protocol(format!(
                    "manual transaction is poisoned: {reason}"
                )));
            }
            ManualTransactionPhase::Terminal => {
                return Err(sqlx::Error::Protocol(
                    "manual transaction is terminal".to_owned(),
                ));
            }
        }
        if inner.in_flight.is_some() {
            return Err(sqlx::Error::Protocol(
                "manual transaction already has a statement in flight".to_owned(),
            ));
        }
        let operation = inner.next_operation;
        inner.next_operation = inner.next_operation.checked_add(1).ok_or_else(|| {
            sqlx::Error::Protocol("manual transaction operation generation exhausted".to_owned())
        })?;
        inner.in_flight = Some(operation);
        Ok(Self {
            state: Arc::clone(state),
            operation,
            armed: true,
        })
    }

    fn complete(mut self) -> Result<(), sqlx::Error> {
        let mut inner = self
            .state
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.in_flight != Some(self.operation) {
            return Err(sqlx::Error::Protocol(
                "manual transaction operation generation changed".to_owned(),
            ));
        }
        match &inner.phase {
            ManualTransactionPhase::Healthy => {
                inner.in_flight = None;
                self.armed = false;
                Ok(())
            }
            ManualTransactionPhase::Poisoned(reason) => Err(sqlx::Error::Protocol(format!(
                "manual transaction is poisoned: {reason}"
            ))),
            ManualTransactionPhase::Terminal => Err(sqlx::Error::Protocol(
                "manual transaction is terminal".to_owned(),
            )),
        }
    }
}

impl Drop for TransactionOperationGuard {
    fn drop(&mut self) {
        if self.armed {
            poison_transaction_state(
                &self.state,
                "statement result was not verified to completion",
            );
        }
    }
}

struct PreflightPragmaGuard<'state>(&'state AtomicBool);

impl<'state> PreflightPragmaGuard<'state> {
    fn new(state: &'state ManualTransactionState) -> Result<Self, sqlx::Error> {
        if state.preflight_pragmas.swap(true, Ordering::AcqRel) {
            return Err(sqlx::Error::Protocol(
                "manual transaction preflight is already active".to_owned(),
            ));
        }
        Ok(Self(&state.preflight_pragmas))
    }
}

impl Drop for PreflightPragmaGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct StatementPreflight {
    denied_during_parse: bool,
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
    let nonce = take_nonzero_generation(&NEXT_CONNECTION_NONCE, "connection nonce")?;
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
        remove_transaction_state(&token.state);
        {
            let mut inner = token
                .state
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.phase = ManualTransactionPhase::Terminal;
            inner.in_flight = None;
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
    post_commit_owner: Option<BlockingCleanupOwner>,
}

struct TransactionConnection<Connection: BeginOwnedConnection> {
    inner: Connection,
    state: Arc<ManualTransactionState>,
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

struct CommitDeliveryTerminalPayload<Connection: BeginOwnedConnection> {
    shared: Arc<CommitDeliveryShared<Connection>>,
    close: Option<RetainedTerminalClose<Connection>>,
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

enum TerminalRollbackCompletion<Connection: BeginOwnedConnection> {
    Return(tokio::sync::oneshot::Sender<Result<Connection, FileControlError>>),
    ReportCommit {
        result: std::sync::mpsc::SyncSender<Result<CommitDelivery<Connection>, FileControlError>>,
        primary: FileControlError,
    },
    ReportPlain {
        result: tokio::sync::oneshot::Sender<Result<(), FileControlError>>,
        primary: FileControlError,
    },
    Drop,
}

struct TerminalRollbackPayload<Connection: BeginOwnedConnection> {
    connection: Option<TransactionConnection<Connection>>,
    close: Option<RetainedTerminalClose<Connection>>,
    token: Option<ManualTransactionToken>,
    completion: Option<TerminalRollbackCompletion<Connection>>,
}

fn terminal_close_transaction<Connection: BeginOwnedConnection>(
    payload: &mut TerminalRollbackPayload<Connection>,
    runtime: &tokio::runtime::Runtime,
) -> (TerminalCloseOutcome, TerminalJobDisposition) {
    if payload.close.is_none() {
        let connection = payload
            .connection
            .take()
            .expect("terminal transaction close is single-use")
            .inner;
        payload.close = Some(RetainedTerminalClose::new(connection));
    }
    let close = payload
        .close
        .as_mut()
        .expect("terminal transaction close remains owned")
        .run(runtime);
    match close {
        TerminalCloseOutcome::Closed => {
            if !payload
                .close
                .as_mut()
                .expect("terminal transaction close remains owned")
                .finish_success()
            {
                return (
                    TerminalCloseOutcome::Panicked,
                    TerminalJobDisposition::Quarantined,
                );
            }
            if let Some(token) = payload.token.as_mut() {
                if token.authorizer_address != 0 {
                    let authorizer_address = token.take_authorizer_for_terminal_close();
                    unregister_manual_transaction(token);
                    // SAFETY: the database close completed, so SQLite no longer retains pApp.
                    unsafe {
                        drop(Box::from_raw(
                            authorizer_address as *mut TransactionAuthorizerContext,
                        ));
                    }
                } else if token.active {
                    unregister_manual_transaction(token);
                }
            }
            payload.token.take();
            (
                TerminalCloseOutcome::Closed,
                TerminalJobDisposition::Completed,
            )
        }
        TerminalCloseOutcome::Failed(error) => (
            TerminalCloseOutcome::Failed(error),
            TerminalJobDisposition::Quarantined,
        ),
        TerminalCloseOutcome::Panicked | TerminalCloseOutcome::Quarantined => (
            TerminalCloseOutcome::Panicked,
            TerminalJobDisposition::Quarantined,
        ),
    }
}

fn send_terminal_rollback_error<Connection: BeginOwnedConnection>(
    completion: TerminalRollbackCompletion<Connection>,
    rollback: Option<&FileControlError>,
    close: Option<&TerminalCloseOutcome>,
) {
    match completion {
        TerminalRollbackCompletion::Return(result) => {
            let error = match (rollback, close) {
                (Some(rollback), Some(close)) => {
                    FileControlError::Handle(format!("{rollback}; terminal close: {close:?}"))
                }
                (Some(rollback), None) => FileControlError::Handle(rollback.to_string()),
                (None, Some(close)) => {
                    FileControlError::Handle(format!("terminal rollback panicked: {close:?}"))
                }
                (None, None) => FileControlError::Handle("terminal rollback panicked".to_owned()),
            };
            let _ = result.send(Err(error));
        }
        TerminalRollbackCompletion::ReportCommit { result, primary } => {
            let error = match (rollback, close) {
                (Some(rollback), Some(close)) => FileControlError::Handle(format!(
                    "COMMIT failed: {primary}; terminal rollback failed: {rollback}; terminal close: {close:?}"
                )),
                (Some(rollback), None) => FileControlError::Handle(format!(
                    "COMMIT failed: {primary}; terminal rollback failed: {rollback}"
                )),
                (None, Some(TerminalCloseOutcome::Closed)) => primary,
                (None, Some(close)) => FileControlError::Handle(format!(
                    "COMMIT failed: {primary}; terminal close: {close:?}"
                )),
                (None, None) => FileControlError::Handle(format!(
                    "COMMIT failed: {primary}; terminal rollback panicked"
                )),
            };
            let _ = result.send(Err(error));
        }
        TerminalRollbackCompletion::ReportPlain { result, primary } => {
            let error = match (rollback, close) {
                (Some(rollback), Some(close)) => FileControlError::Handle(format!(
                    "COMMIT failed: {primary}; terminal rollback failed: {rollback}; terminal close: {close:?}"
                )),
                (Some(rollback), None) => FileControlError::Handle(format!(
                    "COMMIT failed: {primary}; terminal rollback failed: {rollback}"
                )),
                (None, Some(TerminalCloseOutcome::Closed)) => primary,
                (None, Some(close)) => FileControlError::Handle(format!(
                    "COMMIT failed: {primary}; terminal close: {close:?}"
                )),
                (None, None) => FileControlError::Handle(format!(
                    "COMMIT failed: {primary}; terminal rollback panicked"
                )),
            };
            let _ = result.send(Err(error));
        }
        TerminalRollbackCompletion::Drop => {}
    }
}

fn run_terminal_rollback<Connection: BeginOwnedConnection>(
    payload: &Arc<std::sync::Mutex<TerminalRollbackPayload<Connection>>>,
    runtime: &tokio::runtime::Runtime,
) -> TerminalJobDisposition {
    let mut payload = payload
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let rollback = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let TerminalRollbackPayload {
            connection, token, ..
        } = &mut *payload;
        runtime.block_on(rollback_synchronously(
            connection
                .as_mut()
                .expect("terminal rollback connection remains owned")
                .inner
                .sqlite(),
            token
                .as_mut()
                .expect("terminal rollback token remains owned"),
        ))
    }));
    let rollback = match rollback {
        Ok(rollback) => rollback,
        Err(_) => {
            if let Some(completion) = payload.completion.take() {
                send_terminal_rollback_error(completion, None, None);
            }
            return TerminalJobDisposition::Quarantined;
        }
    };
    if let Err(rollback_error) = rollback {
        let (close, disposition) = terminal_close_transaction(&mut payload, runtime);
        if let Some(completion) = payload.completion.take() {
            send_terminal_rollback_error(completion, Some(&rollback_error), Some(&close));
        }
        return disposition;
    }
    match payload
        .completion
        .take()
        .expect("terminal rollback completion is single-use")
    {
        TerminalRollbackCompletion::Return(result) => {
            let state = Arc::clone(
                &payload
                    .connection
                    .as_ref()
                    .expect("successful rollback retains its connection")
                    .state,
            );
            payload.token.take();
            let connection = payload
                .connection
                .take()
                .expect("successful rollback retains its connection")
                .inner;
            match result.send(Ok(connection)) {
                Ok(()) => TerminalJobDisposition::Completed,
                Err(Ok(connection)) => {
                    payload.connection = Some(TransactionConnection {
                        inner: connection,
                        state,
                    });
                    let (_, disposition) = terminal_close_transaction(&mut payload, runtime);
                    disposition
                }
                Err(Err(_)) => TerminalJobDisposition::Completed,
            }
        }
        completion @ (TerminalRollbackCompletion::ReportCommit { .. }
        | TerminalRollbackCompletion::ReportPlain { .. }) => {
            let (close, disposition) = terminal_close_transaction(&mut payload, runtime);
            send_terminal_rollback_error(completion, None, Some(&close));
            disposition
        }
        TerminalRollbackCompletion::Drop => {
            let (_, disposition) = terminal_close_transaction(&mut payload, runtime);
            disposition
        }
    }
}

fn submit_terminal_rollback<Connection: BeginOwnedConnection>(
    permit: TerminalClosePermit,
    connection: TransactionConnection<Connection>,
    token: ManualTransactionToken,
    completion: TerminalRollbackCompletion<Connection>,
) -> Result<(), String> {
    let payload = Arc::new(std::sync::Mutex::new(TerminalRollbackPayload {
        connection: Some(connection),
        close: None,
        token: Some(token),
        completion: Some(completion),
    }));
    let job_payload = Arc::clone(&payload);
    permit.submit_job(
        Box::new(move |runtime| run_terminal_rollback(&job_payload, runtime)),
        Some(Box::new(payload)),
    )
}

fn handoff_terminal_rollback<Connection: BeginOwnedConnection>(
    owner: &mut BlockingCleanupOwner,
    permit: TerminalClosePermit,
    connection: TransactionConnection<Connection>,
    token: ManualTransactionToken,
    completion: TerminalRollbackCompletion<Connection>,
) -> Result<(), String> {
    let reservation = owner
        .reservation
        .take()
        .ok_or_else(|| "blocking cleanup owner is missing".to_owned())?;
    let terminal_closes = owner
        .terminal_closes
        .take()
        .ok_or_else(|| "terminal close owner is missing".to_owned())?;
    let result = submit_terminal_rollback(permit, connection, token, completion);
    drop(terminal_closes);
    drop(reservation);
    result
}

enum TerminalCommittedResult<Connection: BeginOwnedConnection> {
    Commit(std::sync::mpsc::SyncSender<Result<CommitDelivery<Connection>, FileControlError>>),
    Plain(tokio::sync::oneshot::Sender<Result<(), FileControlError>>),
}

impl<Connection: BeginOwnedConnection> TerminalCommittedResult<Connection> {
    fn send_error(self, error: FileControlError) {
        match self {
            Self::Commit(result) => {
                let _ = result.send(Err(error));
            }
            Self::Plain(result) => {
                let _ = result.send(Err(error));
            }
        }
    }
}

struct TerminalIdentityVetoPayload<Connection: BeginOwnedConnection> {
    transaction: TerminalRollbackPayload<Connection>,
    result: Option<TerminalCommittedResult<Connection>>,
    primary: Option<FileControlError>,
}

fn run_terminal_identity_veto_close<Connection: BeginOwnedConnection>(
    payload: &Arc<std::sync::Mutex<TerminalIdentityVetoPayload<Connection>>>,
    runtime: &tokio::runtime::Runtime,
) -> TerminalJobDisposition {
    let mut payload = payload
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (close, disposition) = terminal_close_transaction(&mut payload.transaction, runtime);
    let primary = payload
        .primary
        .take()
        .expect("identity veto primary error remains owned");
    let error = if close == TerminalCloseOutcome::Closed {
        primary
    } else {
        append_committed_cleanup(primary, format!("terminal close: {close:?}"))
    };
    if let Some(result) = payload.result.take() {
        result.send_error(error);
    }
    disposition
}

fn submit_terminal_identity_veto_close<Connection: BeginOwnedConnection>(
    permit: TerminalClosePermit,
    connection: TransactionConnection<Connection>,
    token: ManualTransactionToken,
    result: TerminalCommittedResult<Connection>,
    primary: FileControlError,
) -> Result<(), String> {
    let payload = Arc::new(std::sync::Mutex::new(TerminalIdentityVetoPayload {
        transaction: TerminalRollbackPayload {
            connection: Some(connection),
            close: None,
            token: Some(token),
            completion: Some(TerminalRollbackCompletion::Drop),
        },
        result: Some(result),
        primary: Some(primary),
    }));
    let job_payload = Arc::clone(&payload);
    permit.submit_job(
        Box::new(move |runtime| run_terminal_identity_veto_close(&job_payload, runtime)),
        Some(Box::new(payload)),
    )
}

fn handoff_terminal_identity_veto_close<Connection: BeginOwnedConnection>(
    owner: &mut BlockingCleanupOwner,
    permit: TerminalClosePermit,
    connection: TransactionConnection<Connection>,
    token: ManualTransactionToken,
    result: TerminalCommittedResult<Connection>,
    primary: FileControlError,
) -> Result<(), String> {
    let reservation = owner
        .reservation
        .take()
        .ok_or_else(|| "blocking cleanup owner is missing".to_owned())?;
    let terminal_closes = owner
        .terminal_closes
        .take()
        .ok_or_else(|| "terminal close owner is missing".to_owned())?;
    let result = submit_terminal_identity_veto_close(permit, connection, token, result, primary);
    drop(terminal_closes);
    drop(reservation);
    result
}

struct TerminalCommittedPayload<Connection: BeginOwnedConnection> {
    transaction: TerminalRollbackPayload<Connection>,
    owner: Option<String>,
    cleanup_deadline: std::time::Instant,
    result: Option<TerminalCommittedResult<Connection>>,
    primary: Option<FileControlError>,
    after_deadline: bool,
}

fn run_terminal_committed_cleanup<Connection: BeginOwnedConnection>(
    payload: &Arc<std::sync::Mutex<TerminalCommittedPayload<Connection>>>,
    runtime: &tokio::runtime::Runtime,
) -> TerminalJobDisposition {
    let mut payload = payload
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let owner = payload.owner.clone();
    let cleanup_deadline = payload.cleanup_deadline;
    let late_cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(cleanup_late_writer_claim(
            &mut payload
                .transaction
                .connection
                .as_mut()
                .expect("committed cleanup connection remains owned")
                .inner,
            owner.as_deref(),
            cleanup_deadline,
        ))
    }));
    let late_cleanup = match late_cleanup {
        Ok(result) => result.err().map(|error| error.to_string()),
        Err(_) => {
            let error = if payload.after_deadline {
                FileControlError::CommittedAfterDeadline(Some(
                    "late writer claim cleanup panicked".to_owned(),
                ))
            } else {
                append_committed_cleanup(
                    payload
                        .primary
                        .take()
                        .expect("committed cleanup primary error remains owned"),
                    "late writer claim cleanup panicked".to_owned(),
                )
            };
            if let Some(result) = payload.result.take() {
                result.send_error(error);
            }
            return TerminalJobDisposition::Quarantined;
        }
    };
    let (close, disposition) = terminal_close_transaction(&mut payload.transaction, runtime);
    let cleanup = late_cleanup
        .map(|error| format!("late claim cleanup: {error}; terminal close: {close:?}"))
        .or_else(|| {
            (close != TerminalCloseOutcome::Closed).then(|| format!("terminal close: {close:?}"))
        });
    let error = if payload.after_deadline {
        FileControlError::CommittedAfterDeadline(cleanup)
    } else {
        match cleanup {
            Some(cleanup) => append_committed_cleanup(
                payload
                    .primary
                    .take()
                    .expect("committed cleanup primary error remains owned"),
                cleanup,
            ),
            None => payload
                .primary
                .take()
                .expect("committed cleanup primary error remains owned"),
        }
    };
    if let Some(result) = payload.result.take() {
        result.send_error(error);
    }
    disposition
}

struct TerminalCommittedRequest<Connection: BeginOwnedConnection> {
    connection: TransactionConnection<Connection>,
    token: ManualTransactionToken,
    owner: Option<String>,
    cleanup_deadline: std::time::Instant,
    result: TerminalCommittedResult<Connection>,
    primary: Option<FileControlError>,
    after_deadline: bool,
}

fn submit_terminal_committed_cleanup<Connection: BeginOwnedConnection>(
    permit: TerminalClosePermit,
    request: TerminalCommittedRequest<Connection>,
) -> Result<(), String> {
    let TerminalCommittedRequest {
        connection,
        token,
        owner,
        cleanup_deadline,
        result,
        primary,
        after_deadline,
    } = request;
    let payload = Arc::new(std::sync::Mutex::new(TerminalCommittedPayload {
        transaction: TerminalRollbackPayload {
            connection: Some(connection),
            close: None,
            token: Some(token),
            completion: Some(TerminalRollbackCompletion::Drop),
        },
        owner,
        cleanup_deadline,
        result: Some(result),
        primary,
        after_deadline,
    }));
    let job_payload = Arc::clone(&payload);
    permit.submit_job(
        Box::new(move |runtime| run_terminal_committed_cleanup(&job_payload, runtime)),
        Some(Box::new(payload)),
    )
}

fn handoff_terminal_committed_cleanup<Connection: BeginOwnedConnection>(
    owner: &mut BlockingCleanupOwner,
    permit: TerminalClosePermit,
    connection: TransactionConnection<Connection>,
    token: ManualTransactionToken,
    completion: TerminalCommittedResult<Connection>,
    primary: FileControlError,
) -> Result<(), String> {
    let reservation = owner
        .reservation
        .take()
        .ok_or_else(|| "blocking cleanup owner is missing".to_owned())?;
    let terminal_closes = owner
        .terminal_closes
        .take()
        .ok_or_else(|| "terminal close owner is missing".to_owned())?;
    let result = submit_terminal_committed_cleanup(
        permit,
        TerminalCommittedRequest {
            connection,
            token,
            owner: None,
            cleanup_deadline: std::time::Instant::now() + TERMINAL_CLOSE_TIMEOUT,
            result: completion,
            primary: Some(primary),
            after_deadline: false,
        },
    );
    drop(terminal_closes);
    drop(reservation);
    result
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
    let deadline = tokio::time::Instant::from_std(cleanup_deadline);
    tokio::time::timeout_at(deadline, set_busy_timeout(connection.sqlite(), remaining))
        .await
        .map_err(|_| {
            FileControlError::Handle(
                "late writer claim busy-timeout setup exceeded its cutoff".to_owned(),
            )
        })??;
    if std::time::Instant::now() >= cleanup_deadline {
        return Err(FileControlError::Handle(
            "late writer claim cleanup cutoff elapsed after busy-timeout setup".to_owned(),
        ));
    }
    tokio::time::timeout_at(deadline, async {
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
    .map_err(|_| {
        FileControlError::Handle(
            "late writer claim cleanup timed out; connection requires terminal close".to_owned(),
        )
    })?
    .map_err(|error| FileControlError::Handle(error.to_string()))
}

fn drive_commit_delivery<Connection: BeginOwnedConnection>(
    payload: Arc<std::sync::Mutex<CommitDeliveryTerminalPayload<Connection>>>,
    runtime: &tokio::runtime::Runtime,
    owner: Option<&str>,
    cleanup_deadline: std::time::Instant,
) -> TerminalJobDisposition {
    let shared = {
        let payload = payload
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(&payload.shared)
    };
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        match state.disposition {
            CommitDeliveryDisposition::Accepted | CommitDeliveryDisposition::Closed => {
                return TerminalJobDisposition::Completed;
            }
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
    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(cleanup_late_writer_claim(
            &mut connection,
            owner,
            cleanup_deadline,
        ))
    }));
    let cleanup = match cleanup {
        Ok(cleanup) => cleanup,
        Err(_) => {
            let mut state = shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.connection = Some(connection);
            state.cleanup_error = Some("late writer claim cleanup panicked".to_owned());
            state.disposition = CommitDeliveryDisposition::Closed;
            shared.changed.notify_all();
            return TerminalJobDisposition::Quarantined;
        }
    };
    let mut terminal = payload
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    terminal.close = Some(RetainedTerminalClose::new(connection));
    let close = terminal
        .close
        .as_mut()
        .expect("COMMIT delivery close remains owned")
        .run(runtime);
    let close = if close == TerminalCloseOutcome::Closed
        && !terminal
            .close
            .as_mut()
            .expect("COMMIT delivery close remains owned")
            .finish_success()
    {
        TerminalCloseOutcome::Panicked
    } else {
        close
    };
    drop(terminal);
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.cleanup_error = cleanup.err().map(|error| error.to_string()).or_else(|| {
        (close != TerminalCloseOutcome::Closed).then(|| format!("terminal close: {close:?}"))
    });
    state.disposition = CommitDeliveryDisposition::Closed;
    shared.changed.notify_all();
    if close == TerminalCloseOutcome::Closed {
        TerminalJobDisposition::Completed
    } else {
        TerminalJobDisposition::Quarantined
    }
}

fn submit_commit_delivery<Connection: BeginOwnedConnection>(
    permit: TerminalClosePermit,
    shared: Arc<CommitDeliveryShared<Connection>>,
    owner: Option<String>,
    cleanup_deadline: std::time::Instant,
) -> Result<(), String> {
    let payload = Arc::new(std::sync::Mutex::new(CommitDeliveryTerminalPayload {
        shared,
        close: None,
    }));
    let job_payload = Arc::clone(&payload);
    permit.submit_job(
        Box::new(move |runtime| {
            drive_commit_delivery(job_payload, runtime, owner.as_deref(), cleanup_deadline)
        }),
        Some(Box::new(payload)),
    )
}

impl<Connection: BeginOwnedConnection> ManualTransaction<Connection> {
    #[cfg(test)]
    fn into_test_parts(mut self) -> (Connection, ManualTransactionToken) {
        self.cleanup_owner.take();
        self.post_commit_owner.take();
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

    /// Deletes one exact writer claim under an absolute progress deadline.
    pub async fn delete_writer_claim_with_deadline(
        &mut self,
        owner: &str,
        deadline: std::time::Instant,
        cancelled: Arc<AtomicBool>,
    ) -> Result<u64, FileControlError> {
        let connection = self.connection.as_mut().ok_or_else(|| {
            FileControlError::Handle("transaction connection is missing".to_owned())
        })?;
        let token = self
            .token
            .as_ref()
            .ok_or_else(|| FileControlError::Handle("transaction token is missing".to_owned()))?;
        validate_terminal_transaction_state(token)?;
        let mut database = connection
            .inner
            .sqlite()
            .lock_handle()
            .await
            .map_err(|error| FileControlError::Handle(error.to_string()))?;
        if cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
            return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
        }
        let database = LiveInterruptPointer(database.as_raw_handle());
        let mut progress = RawDeadlineContext {
            deadline,
            cancelled,
        };
        // SAFETY: the locked handle and stack context remain live through statement finalization.
        unsafe {
            libsqlite3_sys::sqlite3_progress_handler(
                database.as_ptr(),
                1,
                Some(raw_deadline_progress),
                (&raw mut progress).cast(),
            );
        }
        let _progress = RawProgressRegistration(database);
        let mut statement = std::ptr::null_mut();
        // SAFETY: no await occurs between the cutoff check and statement dispatch.
        let prepared = unsafe {
            libsqlite3_sys::sqlite3_prepare_v2(
                database.as_ptr(),
                c"DELETE FROM claw_writer_lock WHERE singleton = 1 AND owner = ?".as_ptr(),
                -1,
                &raw mut statement,
                std::ptr::null_mut(),
            )
        };
        if prepared != libsqlite3_sys::SQLITE_OK {
            return Err(FileControlError::SQLite(prepared));
        }
        let statement = RawStatement(statement);
        let owner = std::ffi::CString::new(owner)
            .map_err(|_| FileControlError::Handle("writer owner contains NUL".to_owned()))?;
        // SAFETY: SQLITE_TRANSIENT copies the owner bytes before this call returns.
        let bound = unsafe {
            libsqlite3_sys::sqlite3_bind_text(
                statement.0,
                1,
                owner.as_ptr(),
                -1,
                libsqlite3_sys::SQLITE_TRANSIENT(),
            )
        };
        if bound != libsqlite3_sys::SQLITE_OK {
            return Err(FileControlError::SQLite(bound));
        }
        // SAFETY: the prepared statement and deadline context remain live.
        let stepped = unsafe { libsqlite3_sys::sqlite3_step(statement.0) };
        if stepped != libsqlite3_sys::SQLITE_DONE {
            return Err(FileControlError::SQLite(stepped));
        }
        // SAFETY: this worker exclusively owns the connection.
        let changed = unsafe { libsqlite3_sys::sqlite3_changes64(database.as_ptr()) };
        u64::try_from(changed)
            .map_err(|_| FileControlError::Handle("negative SQLite change count".to_owned()))
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
                self.post_commit_owner.take();
                Ok(self
                    .connection
                    .take()
                    .expect("committed connection remains owned")
                    .inner)
            }
            Err(commit_error) => {
                let identity_veto =
                    matches!(commit_error, FileControlError::IdentityCommitVetoed(_, _));
                let committed = matches!(
                    commit_error,
                    FileControlError::CommittedWithCleanupFailure(_)
                        | FileControlError::CommitOutcomeUncertain(_, _)
                );
                let permit = self
                    .cleanup_owner
                    .as_mut()
                    .expect("failed commit cleanup owner remains owned")
                    .take_terminal_permit()
                    .expect("failed commit terminal capacity was pre-reserved");
                let connection = self
                    .connection
                    .take()
                    .expect("failed commit connection remains owned");
                let token = self
                    .token
                    .take()
                    .expect("failed commit token remains owned");
                let mut owner = self
                    .cleanup_owner
                    .take()
                    .expect("failed commit cleanup owner remains owned");
                let fallback = commit_error.clone();
                let (result_tx, result_rx) = tokio::sync::oneshot::channel();
                let handoff = if identity_veto {
                    handoff_terminal_identity_veto_close(
                        &mut owner,
                        permit,
                        connection,
                        token,
                        TerminalCommittedResult::Plain(result_tx),
                        commit_error,
                    )
                } else if committed {
                    handoff_terminal_committed_cleanup(
                        &mut owner,
                        permit,
                        connection,
                        token,
                        TerminalCommittedResult::Plain(result_tx),
                        commit_error,
                    )
                } else {
                    handoff_terminal_rollback(
                        &mut owner,
                        permit,
                        connection,
                        token,
                        TerminalRollbackCompletion::ReportPlain {
                            result: result_tx,
                            primary: commit_error,
                        },
                    )
                };
                if let Err(error) = handoff {
                    return Err(if identity_veto || committed {
                        append_committed_cleanup(
                            fallback,
                            format!("terminal cleanup handoff: {error}"),
                        )
                    } else {
                        FileControlError::Handle(format!(
                            "COMMIT failed: {fallback}; terminal cleanup handoff: {error}"
                        ))
                    });
                }
                match tokio::time::timeout(std::time::Duration::from_secs(1), result_rx).await {
                    Ok(Ok(Err(error))) => Err(error),
                    Ok(Ok(Ok(()))) => Err(fallback),
                    Ok(Err(_)) => Err(FileControlError::Handle(format!(
                        "COMMIT failed: {fallback}; terminal cleanup owner stopped without result"
                    ))),
                    Err(_) if identity_veto || committed => Err(append_committed_cleanup(
                        fallback,
                        "terminal cleanup exceeded its fixed cutoff".to_owned(),
                    )),
                    Err(_) => Err(FileControlError::Handle(format!(
                        "COMMIT failed: {fallback}; terminal cleanup exceeded its fixed cutoff"
                    ))),
                }
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
    ) -> Result<(Connection, BlockingCleanupOwner), FileControlError> {
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
        let connection = self
            .connection
            .take()
            .expect("bounded commit connection remains owned");
        let token = self
            .token
            .take()
            .expect("bounded commit token remains owned");
        let mut cleanup_owner = self
            .cleanup_owner
            .take()
            .expect("bounded commit cleanup owner remains owned");
        let mut post_commit_owner = Some(
            self.post_commit_owner
                .take()
                .expect("bounded post-COMMIT owner remains owned"),
        );
        struct CommitWorkerPayload<Connection: BeginOwnedConnection> {
            connection: Option<TransactionConnection<Connection>>,
            token: Option<ManualTransactionToken>,
            result: Option<
                std::sync::mpsc::SyncSender<Result<CommitDelivery<Connection>, FileControlError>>,
            >,
        }
        let delivery_cancelled = Arc::clone(&cancelled);
        let identity_veto_fallback = Arc::new(std::sync::Mutex::new(None));
        let worker_identity_veto_fallback = Arc::clone(&identity_veto_fallback);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        cleanup_owner
            .handoff_payload_internal(
                std::sync::Mutex::new(CommitWorkerPayload {
                    connection: Some(connection),
                    token: Some(token),
                    result: Some(result_tx),
                }),
                move |runtime, terminal_closes, payload| {
                    let mut payload = payload
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let mut terminal_permit = Some(
                        terminal_closes
                            .take_permit()
                            .expect("COMMIT terminal capacity was pre-reserved"),
                    );
                    let cancellation = Arc::new(BeginCancellation {
                        local: std::sync::atomic::AtomicBool::new(false),
                        external: Some(Arc::clone(&cancelled)),
                        work_deadline: Some(deadline),
                        busy_deadline: Some(deadline),
                        cleanup_deadline: deadline
                            .checked_add(std::time::Duration::from_secs(1))
                            .unwrap_or(deadline),
                        stop_cause: AtomicU8::new(BEGIN_STOP_NONE),
                        #[cfg(test)]
                        busy_entered: std::sync::Mutex::new(None),
                        #[cfg(test)]
                        busy_sleep_gate: std::sync::Mutex::new(None),
                        #[cfg(test)]
                        test_key: std::sync::Mutex::new(None),
                    });
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        runtime.block_on(async {
                            let CommitWorkerPayload {
                                connection, token, ..
                            } = &mut *payload;
                            let connection = connection
                                .as_mut()
                                .expect("COMMIT worker connection remains owned");
                            let token = token.as_mut().expect("COMMIT worker token remains owned");
                            let pointer = {
                                let mut handle =
                                    connection.inner.sqlite().lock_handle().await.map_err(
                                        |error| FileControlError::Handle(error.to_string()),
                                    )?;
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
                                commit_synchronously(
                                    connection.inner.sqlite(),
                                    token,
                                    Some(&cancellation),
                                )
                                .await
                            };
                            if let Err(error @ FileControlError::IdentityCommitVetoed(_, _)) =
                                &commit
                            {
                                *worker_identity_veto_fallback
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                    Some(error.clone());
                            }
                            #[cfg(test)]
                            wait_at_commit_restore_test_gate(token.generation);
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
                                        libsqlite3_sys::sqlite3_busy_timeout(
                                            pointer.as_ptr(),
                                            restore_ms,
                                        );
                                    }
                                });
                            match (commit, restored) {
                                (Ok(()), Ok(())) => Ok(()),
                                (Ok(()), Err(error)) => {
                                    Err(FileControlError::CommittedWithCleanupFailure(
                                        error.to_string(),
                                    ))
                                }
                                (
                                    Err(FileControlError::CommittedWithCleanupFailure(commit)),
                                    Err(error),
                                ) => Err(FileControlError::CommittedWithCleanupFailure(format!(
                                    "{commit}; restore busy handler: {error}"
                                ))),
                                (
                                    Err(FileControlError::CommitOutcomeUncertain(code, commit)),
                                    Err(error),
                                ) => Err(FileControlError::CommitOutcomeUncertain(
                                    code,
                                    format!("{commit}; restore busy handler: {error}"),
                                )),
                                (
                                    Err(FileControlError::IdentityCommitVetoed(veto, cleanup)),
                                    Err(error),
                                ) => Err(append_committed_cleanup(
                                    FileControlError::IdentityCommitVetoed(veto, cleanup),
                                    format!("restore busy handler: {error}"),
                                )),
                                (Err(error), Ok(())) => Err(error),
                                (Err(error), Err(restore)) => Err(FileControlError::Handle(
                                    format!("{error}; restore busy handler failed: {restore}"),
                                )),
                            }
                        })
                    }));
                    let result = match result {
                        Ok(result) => result,
                        Err(_) => {
                            let connection = payload
                                .connection
                                .take()
                                .expect("COMMIT worker connection remains owned");
                            let token = payload
                                .token
                                .take()
                                .expect("COMMIT worker token remains owned");
                            let result_tx = payload
                                .result
                                .take()
                                .expect("COMMIT worker result remains owned");
                            let _ = submit_terminal_committed_cleanup(
                                terminal_permit
                                    .take()
                                    .expect("COMMIT terminal permit remains owned"),
                                TerminalCommittedRequest {
                                    connection,
                                    token,
                                    owner: late_writer_owner.clone(),
                                    cleanup_deadline,
                                    result: TerminalCommittedResult::Commit(result_tx),
                                    primary: Some(FileControlError::CommitOutcomeUncertain(
                                        libsqlite3_sys::SQLITE_ABORT,
                                        "COMMIT worker panicked".to_owned(),
                                    )),
                                    after_deadline: false,
                                },
                            );
                            return;
                        }
                    };
                    let connection = payload
                        .connection
                        .take()
                        .expect("COMMIT worker connection remains owned");
                    let token = payload
                        .token
                        .take()
                        .expect("COMMIT worker token remains owned");
                    let result_tx = payload
                        .result
                        .take()
                        .expect("COMMIT worker result remains owned");
                    match result {
                        Ok(()) => {
                            #[cfg(test)]
                            wait_at_commit_result_test_gate(late_writer_owner.as_deref());
                            if cancellation.is_expired() {
                                let _ = submit_terminal_committed_cleanup(
                                    terminal_permit
                                        .take()
                                        .expect("COMMIT terminal permit remains owned"),
                                    TerminalCommittedRequest {
                                        connection,
                                        token,
                                        owner: late_writer_owner.clone(),
                                        cleanup_deadline,
                                        result: TerminalCommittedResult::Commit(result_tx),
                                        primary: None,
                                        after_deadline: true,
                                    },
                                );
                            } else {
                                drop(token);
                                let connection = connection.inner;
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
                                let _ = submit_commit_delivery(
                                    terminal_permit
                                        .take()
                                        .expect("COMMIT terminal permit remains owned"),
                                    shared,
                                    late_writer_owner.clone(),
                                    cleanup_deadline,
                                );
                            }
                        }
                        Err(error) => {
                            let identity_veto =
                                matches!(error, FileControlError::IdentityCommitVetoed(_, _));
                            let committed = matches!(
                                error,
                                FileControlError::CommittedWithCleanupFailure(_)
                                    | FileControlError::CommitOutcomeUncertain(_, _)
                            );
                            if identity_veto {
                                let _ = submit_terminal_identity_veto_close(
                                    terminal_permit
                                        .take()
                                        .expect("COMMIT terminal permit remains owned"),
                                    connection,
                                    token,
                                    TerminalCommittedResult::Commit(result_tx),
                                    error,
                                );
                            } else if committed {
                                let _ = submit_terminal_committed_cleanup(
                                    terminal_permit
                                        .take()
                                        .expect("COMMIT terminal permit remains owned"),
                                    TerminalCommittedRequest {
                                        connection,
                                        token,
                                        owner: late_writer_owner.clone(),
                                        cleanup_deadline,
                                        result: TerminalCommittedResult::Commit(result_tx),
                                        primary: Some(error),
                                        after_deadline: false,
                                    },
                                );
                            } else {
                                let _ = submit_terminal_rollback(
                                    terminal_permit
                                        .take()
                                        .expect("COMMIT terminal permit remains owned"),
                                    connection,
                                    token,
                                    TerminalRollbackCompletion::ReportCommit {
                                        result: result_tx,
                                        primary: error,
                                    },
                                );
                            }
                        }
                    }
                },
            )
            .map_err(FileControlError::Handle)?;
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
                                return Err(FileControlError::CommittedAfterDeadline(Some(
                                    "late COMMIT result cleanup exceeded its cutoff".to_owned(),
                                )));
                            }
                        }
                    }
                }
                Ok(Ok(delivery)) => {
                    return delivery.accept().map(|connection| {
                        (
                            connection,
                            post_commit_owner
                                .take()
                                .expect("post-COMMIT owner is delivered once"),
                        )
                    });
                }
                Ok(Err(error)) => return Err(error),
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    if std::time::Instant::now() >= cleanup_deadline {
                        if let Some(veto) = identity_veto_fallback
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                        {
                            return Err(append_committed_cleanup(
                                veto,
                                "terminal close exceeded the bounded COMMIT cleanup cutoff",
                            ));
                        }
                        return Err(FileControlError::CommitOutcomeUncertain(
                            libsqlite3_sys::SQLITE_INTERRUPT,
                            "bounded COMMIT exceeded its cleanup cutoff".to_owned(),
                        ));
                    }
                    tokio::task::yield_now().await;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    if let Some(veto) = identity_veto_fallback
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                    {
                        return Err(append_committed_cleanup(
                            veto,
                            "terminal close owner stopped without a result",
                        ));
                    }
                    return Err(FileControlError::CommitOutcomeUncertain(
                        libsqlite3_sys::SQLITE_ABORT,
                        "bounded COMMIT cleanup owner stopped without a result".to_owned(),
                    ));
                }
            }
        }
    }

    /// Rolls back and returns the owned connection only after SQLite reaches autocommit.
    pub async fn rollback(mut self) -> Result<Connection, FileControlError> {
        let permit = self
            .cleanup_owner
            .as_mut()
            .expect("rollback cleanup owner remains owned")
            .take_terminal_permit()
            .expect("rollback terminal capacity was pre-reserved");
        let connection = self
            .connection
            .take()
            .expect("rollback connection remains owned");
        let token = self.token.take().expect("rollback token remains owned");
        let mut owner = self
            .cleanup_owner
            .take()
            .expect("rollback cleanup owner remains owned");
        self.post_commit_owner.take();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        handoff_terminal_rollback(
            &mut owner,
            permit,
            connection,
            token,
            TerminalRollbackCompletion::Return(result_tx),
        )
        .map_err(FileControlError::Handle)?;
        tokio::time::timeout(std::time::Duration::from_secs(1), result_rx)
            .await
            .map_err(|_| {
                FileControlError::Handle(
                    "terminal rollback was Quarantined after its fixed cleanup cutoff".to_owned(),
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

type ManualTransactionItem =
    Result<sqlx::Either<sqlx::sqlite::SqliteQueryResult, sqlx::sqlite::SqliteRow>, sqlx::Error>;

struct GuardedSqliteExecute {
    sql: sqlx::SqlStr,
    arguments: Result<Option<sqlx::sqlite::SqliteArguments>, sqlx::error::BoxDynError>,
    persistent: bool,
}

impl<'query> sqlx::Execute<'query, sqlx::Sqlite> for GuardedSqliteExecute {
    fn sql(self) -> sqlx::SqlStr {
        self.sql
    }

    fn statement(&self) -> Option<&sqlx::sqlite::SqliteStatement> {
        None
    }

    fn take_arguments(
        &mut self,
    ) -> Result<Option<sqlx::sqlite::SqliteArguments>, sqlx::error::BoxDynError> {
        std::mem::replace(&mut self.arguments, Ok(None))
    }

    fn persistent(&self) -> bool {
        self.persistent
    }
}

struct GuardedTransactionStream<'executor> {
    receiver: tokio::sync::mpsc::Receiver<ManualTransactionItem>,
    producer: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'executor>>,
    producer_done: bool,
}

impl futures_core::Stream for GuardedTransactionStream<'_> {
    type Item = ManualTransactionItem;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if !this.producer_done && this.producer.as_mut().poll(context).is_ready() {
            this.producer_done = true;
        }
        this.receiver.poll_recv(context)
    }
}

impl<Connection: BeginOwnedConnection> ManualTransaction<Connection> {
    fn begin_statement_operation(&self) -> Result<TransactionOperationGuard, sqlx::Error> {
        TransactionOperationGuard::begin(&self.state()?)
    }

    fn state(&self) -> Result<Arc<ManualTransactionState>, sqlx::Error> {
        let token = self.token.as_ref().ok_or_else(|| {
            sqlx::Error::Protocol("manual transaction token is missing".to_owned())
        })?;
        let connection = self.connection.as_ref().ok_or_else(|| {
            sqlx::Error::Protocol("manual transaction connection is missing".to_owned())
        })?;
        if !Arc::ptr_eq(&token.state, &connection.state)
            || token.generation != connection.state.generation
        {
            poison_transaction_state(
                &token.state,
                "manual transaction connection generation is stale",
            );
            return Err(sqlx::Error::Protocol(
                "manual transaction connection generation is stale".to_owned(),
            ));
        }
        Ok(Arc::clone(&token.state))
    }

    async fn preflight_one_statement(
        &mut self,
        sql: &str,
    ) -> Result<StatementPreflight, sqlx::Error> {
        if sql.as_bytes().contains(&0) {
            return Err(sqlx::Error::Protocol(
                "SQLite statement contains an embedded NUL".to_owned(),
            ));
        }
        let length = i32::try_from(sql.len())
            .map_err(|_| sqlx::Error::Protocol("SQLite statement is too large".to_owned()))?;
        let state = self.state()?;
        {
            let inner = state
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !matches!(inner.phase, ManualTransactionPhase::Healthy) {
                return Err(sqlx::Error::Protocol(
                    "manual transaction is not healthy".to_owned(),
                ));
            }
        }
        let _pragma_guard = PreflightPragmaGuard::new(&state)?;
        let mut handle = self
            .connection
            .as_mut()
            .ok_or_else(|| {
                sqlx::Error::Protocol("manual transaction connection is missing".to_owned())
            })?
            .inner
            .sqlite()
            .lock_handle()
            .await?;
        let database = LiveInterruptPointer(handle.as_raw_handle());
        if unsafe { libsqlite3_sys::sqlite3_get_autocommit(database.as_ptr()) } != 0 {
            poison_transaction_state(
                &state,
                "SQLite entered autocommit before statement dispatch",
            );
            return Err(sqlx::Error::Protocol(
                "manual transaction ended before statement dispatch".to_owned(),
            ));
        }
        let base = sql.as_ptr();
        let mut offset = 0_usize;
        let mut statements = 0_usize;
        let mut denied_during_parse = false;
        while offset < sql.len() {
            let mut statement = std::ptr::null_mut();
            let mut tail = std::ptr::null();
            let remaining = length
                .checked_sub(i32::try_from(offset).expect("validated SQL offset fits i32"))
                .ok_or_else(|| sqlx::Error::Protocol("SQLite SQL tail underflowed".to_owned()))?;
            let result = unsafe {
                libsqlite3_sys::sqlite3_prepare_v3(
                    database.as_ptr(),
                    base.add(offset).cast(),
                    remaining,
                    0,
                    &raw mut statement,
                    &raw mut tail,
                )
            };
            if result != libsqlite3_sys::SQLITE_OK {
                if !statement.is_null() {
                    unsafe {
                        libsqlite3_sys::sqlite3_finalize(statement);
                    }
                }
                if result == libsqlite3_sys::SQLITE_AUTH {
                    denied_during_parse = true;
                    if tail.is_null() {
                        return Err(sqlx::Error::Protocol(
                            "SQLite denied statement preflight returned no tail".to_owned(),
                        ));
                    }
                    let tail_offset = unsafe { tail.cast::<u8>().offset_from(base) };
                    let tail_offset = usize::try_from(tail_offset).map_err(|_| {
                        sqlx::Error::Protocol(
                            "SQLite denied statement tail preceded its input".to_owned(),
                        )
                    })?;
                    if tail_offset <= offset || tail_offset > sql.len() {
                        return Err(sqlx::Error::Protocol(
                            "SQLite denied statement tail did not advance within its input"
                                .to_owned(),
                        ));
                    }
                    statements += 1;
                    if statements > 1 {
                        return Err(sqlx::Error::Protocol(
                            "manual transactions accept exactly one SQLite statement".to_owned(),
                        ));
                    }
                    offset = tail_offset;
                    continue;
                }
                return Err(sqlx::Error::Protocol(format!(
                    "SQLite statement preflight failed with code {result}"
                )));
            }
            if !statement.is_null() {
                statements += 1;
                unsafe {
                    libsqlite3_sys::sqlite3_finalize(statement);
                }
                if statements > 1 {
                    return Err(sqlx::Error::Protocol(
                        "manual transactions accept exactly one SQLite statement".to_owned(),
                    ));
                }
            }
            if tail.is_null() {
                return Err(sqlx::Error::Protocol(
                    "SQLite statement preflight returned no tail".to_owned(),
                ));
            }
            let tail_offset = unsafe { tail.cast::<u8>().offset_from(base) };
            let tail_offset = usize::try_from(tail_offset).map_err(|_| {
                sqlx::Error::Protocol("SQLite statement tail preceded its input".to_owned())
            })?;
            if tail_offset <= offset || tail_offset > sql.len() {
                return Err(sqlx::Error::Protocol(
                    "SQLite statement tail did not advance within its input".to_owned(),
                ));
            }
            offset = tail_offset;
        }
        if statements == 1 {
            Ok(StatementPreflight {
                denied_during_parse,
            })
        } else {
            Err(sqlx::Error::Protocol(
                "manual transactions accept exactly one SQLite statement".to_owned(),
            ))
        }
    }

    async fn next_script_statement(
        &mut self,
        sql: &str,
    ) -> Result<Option<(usize, bool)>, sqlx::Error> {
        if sql.is_empty() {
            return Ok(None);
        }
        if sql.as_bytes().contains(&0) {
            return Err(sqlx::Error::Protocol(
                "SQLite script contains an embedded NUL".to_owned(),
            ));
        }
        let length = i32::try_from(sql.len())
            .map_err(|_| sqlx::Error::Protocol("SQLite script is too large".to_owned()))?;
        let state = self.state()?;
        let _pragma_guard = PreflightPragmaGuard::new(&state)?;
        let mut handle = self
            .connection
            .as_mut()
            .ok_or_else(|| {
                sqlx::Error::Protocol("manual transaction connection is missing".to_owned())
            })?
            .inner
            .sqlite()
            .lock_handle()
            .await?;
        let database = LiveInterruptPointer(handle.as_raw_handle());
        let mut statement = std::ptr::null_mut();
        let mut tail = std::ptr::null();
        let result = unsafe {
            libsqlite3_sys::sqlite3_prepare_v3(
                database.as_ptr(),
                sql.as_ptr().cast(),
                length,
                0,
                &raw mut statement,
                &raw mut tail,
            )
        };
        if result != libsqlite3_sys::SQLITE_OK && result != libsqlite3_sys::SQLITE_AUTH {
            if !statement.is_null() {
                unsafe {
                    libsqlite3_sys::sqlite3_finalize(statement);
                }
            }
            return Err(sqlx::Error::Protocol(format!(
                "SQLite script statement preflight failed with code {result}"
            )));
        }
        let executable = !statement.is_null() || result == libsqlite3_sys::SQLITE_AUTH;
        if !statement.is_null() {
            unsafe {
                libsqlite3_sys::sqlite3_finalize(statement);
            }
        }
        if tail.is_null() {
            return Err(sqlx::Error::Protocol(
                "SQLite script preflight returned no tail".to_owned(),
            ));
        }
        let consumed = unsafe { tail.cast::<u8>().offset_from(sql.as_ptr()) };
        let consumed = usize::try_from(consumed)
            .map_err(|_| sqlx::Error::Protocol("SQLite script tail is invalid".to_owned()))?;
        if consumed == 0 || consumed > sql.len() {
            return Err(sqlx::Error::Protocol(
                "SQLite script tail did not advance".to_owned(),
            ));
        }
        Ok(Some((consumed, executable)))
    }

    /// Executes a migration script one SQLite-prepared statement at a time.
    pub async fn execute_script(&mut self, script: &str) -> Result<(), sqlx::Error> {
        let mut offset = 0_usize;
        while offset < script.len() {
            let Some((consumed, executable)) =
                self.next_script_statement(&script[offset..]).await?
            else {
                break;
            };
            if executable {
                let statement = script[offset..offset + consumed].to_owned();
                sqlx::Executor::execute(&mut *self, sqlx::query(sqlx::AssertSqlSafe(statement)))
                    .await?;
            }
            offset += consumed;
        }
        Ok(())
    }

    async fn verify_statement_operation(
        &mut self,
        guard: TransactionOperationGuard,
    ) -> Result<(), sqlx::Error> {
        let state = Arc::clone(&guard.state);
        let ManualTransaction {
            connection, token, ..
        } = self;
        #[cfg(not(test))]
        let _ = token;
        let mut handle = connection
            .as_mut()
            .ok_or_else(|| {
                sqlx::Error::Protocol("manual transaction connection is missing".to_owned())
            })?
            .inner
            .sqlite()
            .lock_handle()
            .await?;
        #[cfg(test)]
        if FORCE_IMPLICIT_ROLLBACK_GENERATIONS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&state.generation)
        {
            let token = token.as_ref().ok_or_else(|| {
                sqlx::Error::Protocol("manual transaction token is missing".to_owned())
            })?;
            let permit = InternalTransactionPermit::activate(token)
                .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
            let mut message = std::ptr::null_mut();
            unsafe {
                libsqlite3_sys::sqlite3_exec(
                    handle.as_raw_handle().as_ptr(),
                    c"ROLLBACK".as_ptr(),
                    None,
                    std::ptr::null_mut(),
                    &raw mut message,
                );
                if !message.is_null() {
                    libsqlite3_sys::sqlite3_free(message.cast());
                }
            }
            drop(permit);
        }
        let autocommit =
            unsafe { libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) } != 0;
        if autocommit {
            poison_transaction_state(
                &state,
                "SQLite implicitly rolled back the manual transaction",
            );
            return Err(sqlx::Error::Protocol(
                "SQLite implicitly rolled back the manual transaction".to_owned(),
            ));
        }
        guard.complete()
    }
}

impl<'connection, Connection: BeginOwnedConnection> sqlx::Executor<'connection>
    for &'connection mut ManualTransaction<Connection>
{
    type Database = sqlx::Sqlite;

    fn fetch_many<'executor, 'query: 'executor, Execute>(
        self,
        mut query: Execute,
    ) -> futures_core::stream::BoxStream<
        'executor,
        Result<sqlx::Either<sqlx::sqlite::SqliteQueryResult, sqlx::sqlite::SqliteRow>, sqlx::Error>,
    >
    where
        'connection: 'executor,
        Execute: 'query + sqlx::Execute<'query, sqlx::Sqlite>,
    {
        let persistent = query.persistent();
        let arguments = query.take_arguments();
        let sql = query.sql();
        let sql_text = sql.as_str().to_owned();
        let query = GuardedSqliteExecute {
            sql,
            arguments,
            persistent,
        };
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let guard = self.begin_statement_operation();
        let producer = Box::pin(async move {
            let guard = match guard {
                Ok(guard) => guard,
                Err(error) => {
                    let _ = sender.send(Err(error)).await;
                    return;
                }
            };
            if let Err(error) = self.preflight_one_statement(&sql_text).await {
                let error = match self.verify_statement_operation(guard).await {
                    Ok(()) => error,
                    Err(verification) => verification,
                };
                let _ = sender.send(Err(error)).await;
                return;
            }
            let mut stream = sqlx::Executor::fetch_many(
                self.connection
                    .as_mut()
                    .expect("manual transaction connection remains owned")
                    .inner
                    .sqlite(),
                query,
            );
            let mut guard = Some(guard);
            loop {
                let next = std::future::poll_fn(|context| {
                    futures_core::Stream::poll_next(stream.as_mut(), context)
                })
                .await;
                match next {
                    Some(Ok(sqlx::Either::Right(row))) => {
                        if sender.send(Ok(sqlx::Either::Right(row))).await.is_err() {
                            return;
                        }
                    }
                    Some(item) => {
                        drop(stream);
                        let verification = self
                            .verify_statement_operation(
                                guard.take().expect("statement guard remains owned"),
                            )
                            .await;
                        let item = match verification {
                            Ok(()) => item,
                            Err(error) => Err(error),
                        };
                        let _ = sender.send(item).await;
                        return;
                    }
                    None => {
                        drop(stream);
                        if let Err(error) = self
                            .verify_statement_operation(
                                guard.take().expect("statement guard remains owned"),
                            )
                            .await
                        {
                            let _ = sender.send(Err(error)).await;
                        }
                        return;
                    }
                }
            }
        });
        Box::pin(GuardedTransactionStream {
            receiver,
            producer,
            producer_done: false,
        })
    }

    fn fetch_optional<'executor, 'query: 'executor, Execute>(
        self,
        mut query: Execute,
    ) -> futures_core::future::BoxFuture<
        'executor,
        Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error>,
    >
    where
        'connection: 'executor,
        Execute: 'query + sqlx::Execute<'query, sqlx::Sqlite>,
    {
        let persistent = query.persistent();
        let arguments = query.take_arguments();
        let sql = query.sql();
        let sql_text = sql.as_str().to_owned();
        let query = GuardedSqliteExecute {
            sql,
            arguments,
            persistent,
        };
        let guard = self.begin_statement_operation();
        Box::pin(async move {
            let guard = guard?;
            if let Err(error) = self.preflight_one_statement(&sql_text).await {
                return match self.verify_statement_operation(guard).await {
                    Ok(()) => Err(error),
                    Err(verification) => Err(verification),
                };
            }
            let result = sqlx::Executor::fetch_optional(
                self.connection
                    .as_mut()
                    .expect("manual transaction connection remains owned")
                    .inner
                    .sqlite(),
                query,
            )
            .await;
            match self.verify_statement_operation(guard).await {
                Ok(()) => result,
                Err(error) => Err(error),
            }
        })
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
        let sql_text = sql.as_str().to_owned();
        let guard = self.begin_statement_operation();
        Box::pin(async move {
            let guard = guard?;
            let preflight = match self.preflight_one_statement(&sql_text).await {
                Ok(preflight) => preflight,
                Err(error) => {
                    return match self.verify_statement_operation(guard).await {
                        Ok(()) => Err(error),
                        Err(verification) => Err(verification),
                    };
                }
            };
            if preflight.denied_during_parse {
                let error = sqlx::Error::Protocol(
                    "explicit prepare rejects statements with prepare-time effects".to_owned(),
                );
                return match self.verify_statement_operation(guard).await {
                    Ok(()) => Err(error),
                    Err(verification) => Err(verification),
                };
            }
            let result = sqlx::Executor::prepare_with(
                self.connection
                    .as_mut()
                    .expect("manual transaction connection remains owned")
                    .inner
                    .sqlite(),
                sql,
                parameters,
            )
            .await;
            #[cfg(test)]
            wait_at_prepare_delivery_test_gate(guard.state.generation).await;
            match self.verify_statement_operation(guard).await {
                Ok(()) => result,
                Err(error) => Err(error),
            }
        })
    }
}

impl<Connection: BeginOwnedConnection> Drop for ManualTransaction<Connection> {
    fn drop(&mut self) {
        if self.connection.is_none() || self.token.is_none() || self.cleanup_owner.is_none() {
            return;
        }
        let permit = self
            .cleanup_owner
            .as_mut()
            .expect("dropped transaction cleanup owner remains owned")
            .take_terminal_permit()
            .expect("dropped transaction terminal capacity was pre-reserved");
        let (Some(connection), Some(token), Some(mut cleanup_owner)) = (
            self.connection.take(),
            self.token.take(),
            self.cleanup_owner.take(),
        ) else {
            return;
        };
        self.post_commit_owner.take();
        let _ = handoff_terminal_rollback(
            &mut cleanup_owner,
            permit,
            connection,
            token,
            TerminalRollbackCompletion::Drop,
        );
    }
}
enum BeginWorkerCommand {
    Accept(Arc<ManualTransactionState>),
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RollbackTestStage {
    BeforeLockHandle,
    BeforeSqliteExec,
}

#[cfg(test)]
struct RollbackTestGate {
    stage: RollbackTestStage,
    panic: bool,
    entered: Arc<AtomicBool>,
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

#[cfg(test)]
static ROLLBACK_TEST_GATES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u64, RollbackTestGate>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static FAIL_COMMIT_GENERATIONS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<u64>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static ROLLBACK_SYNCHRONOUS_CALLS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u64, usize>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
#[cfg(all(test, unix))]
struct CommitRestoreTestGate {
    entered: Arc<AtomicBool>,
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}
#[cfg(all(test, unix))]
static COMMIT_RESTORE_TEST_GATES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u64, CommitRestoreTestGate>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static FORCE_IMPLICIT_ROLLBACK_GENERATIONS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<u64>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

#[cfg(all(test, unix))]
fn wait_at_commit_restore_test_gate(generation: u64) {
    let gate = COMMIT_RESTORE_TEST_GATES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&generation)
        .map(|gate| (Arc::clone(&gate.entered), Arc::clone(&gate.release)));
    if let Some((entered, release)) = gate {
        entered.store(true, Ordering::Release);
        let (released, changed) = &*release;
        let mut released = released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*released {
            released = changed
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

#[cfg(all(test, not(unix)))]
fn wait_at_commit_restore_test_gate(_generation: u64) {}

#[cfg(test)]
struct PrepareDeliveryTestGate {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<AtomicBool>,
}

#[cfg(test)]
static PREPARE_DELIVERY_TEST_GATES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u64, PrepareDeliveryTestGate>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
async fn wait_at_prepare_delivery_test_gate(generation: u64) {
    let gate = PREPARE_DELIVERY_TEST_GATES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&generation)
        .map(|gate| (Arc::clone(&gate.entered), Arc::clone(&gate.release)));
    if let Some((entered, release)) = gate {
        entered.notify_one();
        while !release.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(test)]
fn run_rollback_test_gate(token: &ManualTransactionToken, stage: RollbackTestStage) {
    let gate = ROLLBACK_TEST_GATES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&token.generation)
        .filter(|gate| gate.stage == stage)
        .map(|gate| {
            (
                gate.panic,
                Arc::clone(&gate.entered),
                Arc::clone(&gate.release),
            )
        });
    let Some((panic, entered, release)) = gate else {
        return;
    };
    entered.store(true, Ordering::Release);
    if panic {
        panic!("injected terminal rollback panic at {stage:?}");
    }
    let (released, changed) = &*release;
    let mut released = released
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while !*released {
        released = changed
            .wait(released)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
}

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
pub type TerminalCloseFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'static>>;

struct RetainedConsumingCloseFuture<Future> {
    future: std::mem::ManuallyDrop<Future>,
    completed: bool,
}

impl<Future, Error> std::future::Future for RetainedConsumingCloseFuture<Future>
where
    Future: std::future::Future<Output = Result<(), Error>>,
    Error: ToString,
{
    type Output = Result<(), String>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // SAFETY: `future` is never moved after this wrapper is pinned.
        let this = unsafe { self.get_unchecked_mut() };
        if this.completed {
            return std::task::Poll::Ready(Err(
                "completed close future was polled again".to_owned()
            ));
        }
        // SAFETY: the ManuallyDrop storage remains live until Ready or quarantine.
        let future =
            unsafe { std::pin::Pin::new_unchecked(&mut *(&raw mut this.future).cast::<Future>()) };
        match future.poll(context) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(result) => {
                this.completed = true;
                // SAFETY: Ready transfers the result and ends the consuming future.
                unsafe {
                    std::mem::ManuallyDrop::drop(&mut this.future);
                }
                std::task::Poll::Ready(result.map_err(|error| error.to_string()))
            }
        }
    }
}

fn retain_consuming_close_future<Future, Error>(future: Future) -> TerminalCloseFuture
where
    Future: std::future::Future<Output = Result<(), Error>> + Send + 'static,
    Error: ToString,
{
    Box::pin(RetainedConsumingCloseFuture {
        future: std::mem::ManuallyDrop::new(future),
        completed: false,
    })
}

#[doc(hidden)]
pub struct CloseTransfer<Connection>(Arc<std::sync::Mutex<DropSlot<Connection>>>);

impl<Connection> CloseTransfer<Connection> {
    fn new(connection: Connection) -> Self {
        Self(Arc::new(std::sync::Mutex::new(DropSlot::new(connection))))
    }

    fn with_mut<Result>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result,
    ) -> Option<Result> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0
            .as_deref_mut()
            .map(operation)
    }

    fn into_future<Factory, Future, Error>(self, factory: Factory) -> TerminalCloseFuture
    where
        Factory: FnOnce(std::mem::ManuallyDrop<Connection>) -> Future + Send + 'static,
        Future: std::future::Future<Output = Result<(), Error>> + Send + 'static,
        Error: ToString,
        Connection: Send + 'static,
    {
        let connection = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("terminal close transfer is single-use");
        retain_consuming_close_future(factory(std::mem::ManuallyDrop::new(connection)))
    }
}

impl<Connection> Clone for CloseTransfer<Connection> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

mod private {
    use super::{CloseTransfer, TerminalCloseFuture};

    pub trait SealedConnection: Send + 'static {
        fn prepare_terminal_close(connection: &mut Self);
        fn make_close_future(transfer: CloseTransfer<Self>) -> TerminalCloseFuture
        where
            Self: Sized;
    }
}

/// Retained, panic-safe ownership of one physical terminal close.
pub struct RetainedTerminalClose<Connection: BeginOwnedConnection> {
    transfer: CloseTransfer<Connection>,
    future: Option<RetainedDrop<TerminalCloseFuture>>,
    prepared: bool,
    outcome: Option<TerminalCloseOutcome>,
}

impl<Connection: BeginOwnedConnection> RetainedTerminalClose<Connection> {
    /// Retains connection ownership before any close hook is invoked.
    pub fn new(connection: Connection) -> Self {
        Self {
            transfer: CloseTransfer::new(connection),
            future: None,
            prepared: false,
            outcome: None,
        }
    }

    fn remember_outcome(&mut self, outcome: TerminalCloseOutcome) -> TerminalCloseOutcome {
        self.outcome = Some(outcome.clone());
        outcome
    }

    /// Drives preparation, conversion, and physical close without losing panic ownership.
    pub fn run(&mut self, runtime: &tokio::runtime::Runtime) -> TerminalCloseOutcome {
        if let Some(outcome) = &self.outcome {
            return outcome.clone();
        }
        if !self.prepared {
            let Some(prepared) = self.transfer.with_mut(|connection| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    <Connection as private::SealedConnection>::prepare_terminal_close(connection);
                }))
            }) else {
                return self.remember_outcome(TerminalCloseOutcome::Panicked);
            };
            if let Err(panic) = prepared {
                std::mem::forget(panic);
                return self.remember_outcome(TerminalCloseOutcome::Panicked);
            }
            self.prepared = true;
        }
        if self.future.is_none() {
            let future = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                <Connection as private::SealedConnection>::make_close_future(self.transfer.clone())
            }));
            let Ok(future) = future else {
                if let Err(panic) = future {
                    std::mem::forget(panic);
                }
                return self.remember_outcome(TerminalCloseOutcome::Panicked);
            };
            self.future = Some(RetainedDrop::new(future));
        }
        let Some(outcome) = self
            .future
            .as_ref()
            .expect("terminal close future remains owned")
            .with_mut(|future| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    runtime.block_on(future.as_mut())
                }))
            })
        else {
            return self.remember_outcome(TerminalCloseOutcome::Panicked);
        };
        let outcome = match outcome {
            Ok(Ok(())) => TerminalCloseOutcome::Closed,
            Ok(Err(error)) => TerminalCloseOutcome::Failed(error),
            Err(panic) => {
                std::mem::forget(panic);
                TerminalCloseOutcome::Panicked
            }
        };
        self.remember_outcome(outcome)
    }

    /// Explicitly destroys a completed close future exactly once.
    pub fn finish_success(&mut self) -> bool {
        if self.outcome != Some(TerminalCloseOutcome::Closed) {
            return false;
        }
        let destroyed = self
            .future
            .as_ref()
            .map(RetainedDrop::destroy_once)
            .unwrap_or(Ok(()));
        if destroyed.is_ok() {
            self.future.take();
            true
        } else {
            false
        }
    }
}

/// Connection ownership supported by [`ManualTransaction`].
pub trait BeginOwnedConnection: private::SealedConnection + Send + 'static {
    /// Borrows the underlying SQLite connection.
    fn sqlite_ref(&self) -> &sqlx::SqliteConnection;

    /// Mutably borrows the underlying SQLite connection.
    fn sqlite(&mut self) -> &mut sqlx::SqliteConnection;
}

impl private::SealedConnection for sqlx::SqliteConnection {
    fn prepare_terminal_close(_connection: &mut Self) {}

    fn make_close_future(transfer: CloseTransfer<Self>) -> TerminalCloseFuture {
        transfer.into_future(|mut connection| {
            // SAFETY: the installed future is the unique terminal owner.
            let connection = unsafe { std::mem::ManuallyDrop::take(&mut connection) };
            sqlx::Connection::close(connection)
        })
    }
}

impl BeginOwnedConnection for sqlx::SqliteConnection {
    fn sqlite_ref(&self) -> &sqlx::SqliteConnection {
        self
    }

    fn sqlite(&mut self) -> &mut sqlx::SqliteConnection {
        self
    }
}

impl private::SealedConnection for sqlx::pool::PoolConnection<sqlx::Sqlite> {
    fn prepare_terminal_close(connection: &mut Self) {
        connection.close_on_drop();
    }

    fn make_close_future(transfer: CloseTransfer<Self>) -> TerminalCloseFuture {
        transfer.into_future(|mut connection| {
            // SAFETY: the installed future is the unique terminal owner.
            let connection = unsafe { std::mem::ManuallyDrop::take(&mut connection) };
            connection.close()
        })
    }
}

impl BeginOwnedConnection for sqlx::pool::PoolConnection<sqlx::Sqlite> {
    fn sqlite_ref(&self) -> &sqlx::SqliteConnection {
        self
    }

    fn sqlite(&mut self) -> &mut sqlx::SqliteConnection {
        self
    }
}

enum BeginWorkerOutput<Connection> {
    Accepted(Connection, ManualTransactionIdentity, usize),
    Terminal(TerminalCloseOutcome, Option<FileControlError>),
}

struct BeginCancellation {
    local: std::sync::atomic::AtomicBool,
    external: Option<Arc<std::sync::atomic::AtomicBool>>,
    work_deadline: Option<std::time::Instant>,
    busy_deadline: Option<std::time::Instant>,
    cleanup_deadline: std::time::Instant,
    stop_cause: AtomicU8,
    #[cfg(test)]
    busy_entered: std::sync::Mutex<Option<Arc<tokio::sync::Notify>>>,
    #[cfg(test)]
    busy_sleep_gate: std::sync::Mutex<Option<BeginBusySleepTestGate>>,
    #[cfg(test)]
    test_key: std::sync::Mutex<Option<BeginTestKey>>,
}

#[cfg(test)]
struct BeginBusySleepTestGate {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<std::sync::atomic::AtomicBool>,
}

struct BeginBusyRegistration {
    database: LiveInterruptPointer,
    active: bool,
}

impl BeginBusyRegistration {
    fn clear(&mut self) -> Result<(), FileControlError> {
        if !self.active {
            return Ok(());
        }
        // SAFETY: the worker exclusively owns SQLx's locked live handle.
        let result = unsafe {
            libsqlite3_sys::sqlite3_busy_handler(self.database.as_ptr(), None, std::ptr::null_mut())
        };
        if result == libsqlite3_sys::SQLITE_OK {
            self.active = false;
            Ok(())
        } else {
            Err(FileControlError::SQLite(result))
        }
    }
}

impl Drop for BeginBusyRegistration {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: the registration guard cannot outlive the locked live handle.
            unsafe {
                libsqlite3_sys::sqlite3_busy_handler(
                    self.database.as_ptr(),
                    None,
                    std::ptr::null_mut(),
                );
            }
        }
    }
}

const BEGIN_STOP_NONE: u8 = 0;
const BEGIN_STOP_CANCELLED: u8 = 1;
const BEGIN_STOP_WORK_DEADLINE: u8 = 2;
const BEGIN_STOP_BUSY_DEADLINE: u8 = 3;

impl BeginCancellation {
    fn is_cancelled(&self) -> bool {
        self.local.load(std::sync::atomic::Ordering::Acquire)
            || self
                .external
                .as_ref()
                .is_some_and(|state| state.load(std::sync::atomic::Ordering::Acquire))
    }

    fn is_expired(&self) -> bool {
        self.is_cancelled()
            || self
                .work_deadline
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    }

    fn cleanup_deadline(&self) -> std::time::Instant {
        self.cleanup_deadline
    }

    fn latch_stop_cause(&self, now: std::time::Instant) -> u8 {
        let observed = if self.is_cancelled() {
            BEGIN_STOP_CANCELLED
        } else if self.work_deadline.is_some_and(|deadline| now >= deadline) {
            BEGIN_STOP_WORK_DEADLINE
        // No configured busy deadline is the zero-timeout mode: SQLite gets
        // exactly one non-waiting attempt and the callback always denies retry.
        } else if self.busy_deadline.is_none_or(|deadline| now >= deadline) {
            BEGIN_STOP_BUSY_DEADLINE
        } else {
            BEGIN_STOP_NONE
        };
        if observed != BEGIN_STOP_NONE {
            let _ = self.stop_cause.compare_exchange(
                BEGIN_STOP_NONE,
                observed,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            );
        }
        self.stop_cause.load(std::sync::atomic::Ordering::Acquire)
    }

    fn stopped_by_work_or_cancellation(&self) -> bool {
        matches!(
            self.latch_stop_cause(std::time::Instant::now()),
            BEGIN_STOP_CANCELLED | BEGIN_STOP_WORK_DEADLINE
        )
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
    let permits_retry =
        || cancellation.latch_stop_cause(std::time::Instant::now()) == BEGIN_STOP_NONE;
    if !permits_retry() {
        0
    } else {
        std::thread::sleep(std::time::Duration::from_millis(1));
        #[cfg(test)]
        if let Some((entered, release)) = cancellation
            .busy_sleep_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|gate| (Arc::clone(&gate.entered), Arc::clone(&gate.release)))
        {
            entered.notify_one();
            while !release.load(std::sync::atomic::Ordering::Acquire) {
                std::thread::yield_now();
            }
        }
        i32::from(permits_retry())
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
        .is_some_and(|state| Arc::ptr_eq(state, &context.state));
    let healthy = matches!(
        context
            .state
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .phase,
        ManualTransactionPhase::Healthy
    );
    if !active || !healthy {
        return libsqlite3_sys::SQLITE_DENY;
    }
    if context.state.preflight_pragmas.load(Ordering::Acquire)
        && action == libsqlite3_sys::SQLITE_PRAGMA
    {
        return libsqlite3_sys::SQLITE_DENY;
    }
    if action != libsqlite3_sys::SQLITE_TRANSACTION && action != libsqlite3_sys::SQLITE_SAVEPOINT {
        return libsqlite3_sys::SQLITE_OK;
    }
    if context.internal_permit.load(Ordering::Acquire) {
        libsqlite3_sys::SQLITE_OK
    } else {
        libsqlite3_sys::SQLITE_DENY
    }
}

struct TransactionAuthorizerContext {
    database_address: usize,
    connection_nonce: u64,
    generation: u64,
    state: Arc<ManualTransactionState>,
    internal_permit: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
static FAIL_AUTHORIZER_DETACH_GENERATIONS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<u64>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static FAIL_BEGIN_BUSY_RESTORE_NONCES: std::sync::LazyLock<
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
    state: Arc<ManualTransactionState>,
) -> Result<usize, FileControlError> {
    let context = Box::new(TransactionAuthorizerContext {
        database_address: identity.database_address,
        connection_nonce: identity.connection_nonce,
        generation: state.generation,
        state,
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
        if !Arc::ptr_eq(&context.state, &token.state) {
            return Err(FileControlError::TransactionInvalidated(
                "manual transaction authorizer state is stale".to_owned(),
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
        let cutoff = self.cancellation.cleanup_deadline();
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
        state: Arc<ManualTransactionState>,
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
            .send(BeginWorkerCommand::Accept(state))
            .map_err(|_| {
                FileControlError::Handle("BEGIN worker stopped before accept".to_owned())
            })?;
        let result = match self.receive_worker_result().await? {
            BeginWorkerOutput::Accepted(connection, identity, authorizer_address) => {
                (connection, identity, authorizer_address)
            }
            BeginWorkerOutput::Terminal(close, primary) => {
                return Err(primary.unwrap_or_else(|| {
                    FileControlError::Handle(format!(
                        "BEGIN worker discarded the connection; terminal close: {close:?}"
                    ))
                }));
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
        if let BeginWorkerOutput::Terminal(close, primary) = self.receive_worker_result().await?
            && close != TerminalCloseOutcome::Closed
        {
            return Err(FileControlError::Handle(primary.map_or_else(
                || format!("BEGIN terminal cleanup degraded: {close:?}"),
                |primary| format!("{primary}; terminal cleanup degraded: {close:?}"),
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
    permit: TerminalClosePermit,
    connection: Connection,
) -> TerminalCloseOutcome {
    permit.close(connection)
}

enum LockedBeginOutcome {
    Accepted(ManualTransactionIdentity, usize),
    Failed(FileControlError),
    Cancelled,
}

fn begin_result_error(result: i32, cancellation: &BeginCancellation) -> FileControlError {
    let primary = result & 0xff;
    if matches!(
        primary,
        libsqlite3_sys::SQLITE_BUSY | libsqlite3_sys::SQLITE_INTERRUPT
    ) {
        if cancellation.stopped_by_work_or_cancellation() {
            FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT)
        } else {
            FileControlError::SQLite(primary)
        }
    } else {
        FileControlError::SQLite(result)
    }
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
    let mut busy_registration = BeginBusyRegistration {
        database: pointer,
        active: true,
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
    if let Err(error) = busy_registration.clear() {
        return LockedBeginOutcome::Failed(error);
    }
    if result != libsqlite3_sys::SQLITE_OK {
        return LockedBeginOutcome::Failed(begin_result_error(result, cancellation));
    }
    #[cfg(test)]
    if !wait_at_begin_test_gate(BeginTestStage::AfterBegin, cancellation, command) {
        return LockedBeginOutcome::Cancelled;
    }
    let identity = ManualTransactionIdentity {
        database_address: pointer.as_ptr() as usize,
        connection_nonce,
    };
    let accepted_generation = if outcome.send(Ok(identity)).is_ok() {
        match command.recv() {
            Ok(BeginWorkerCommand::Accept(state)) => Some(state),
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
    if let Some(state) = accepted_generation
        && accept_gate_open
        && !cancellation.is_expired()
    {
        // SAFETY: the callback was cleared above and the worker still exclusively
        // owns the locked live handle. Only a reusable accepted connection is restored.
        #[cfg(test)]
        let restore = if FAIL_BEGIN_BUSY_RESTORE_NONCES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&connection_nonce)
        {
            libsqlite3_sys::SQLITE_ERROR
        } else {
            // SAFETY: the callback is cleared and the locked live handle remains owned.
            unsafe {
                libsqlite3_sys::sqlite3_busy_timeout(pointer.as_ptr(), restore_busy_timeout_ms)
            }
        };
        #[cfg(not(test))]
        let restore = unsafe {
            libsqlite3_sys::sqlite3_busy_timeout(pointer.as_ptr(), restore_busy_timeout_ms)
        };
        if restore != libsqlite3_sys::SQLITE_OK {
            return LockedBeginOutcome::Failed(FileControlError::SQLite(restore));
        }
        return match install_transaction_authorizer(pointer, identity, state) {
            Ok(authorizer_address) => LockedBeginOutcome::Accepted(identity, authorizer_address),
            Err(error) => LockedBeginOutcome::Failed(error),
        };
    }

    LockedBeginOutcome::Cancelled
}

struct BeginWorkerExecutors<'worker> {
    runtime: &'worker tokio::runtime::Runtime,
    terminal_closes: &'worker mut TerminalCloseBatch,
}

enum BeginWorkerDecision {
    Accepted(ManualTransactionIdentity, usize),
    Terminal(TerminalCloseOutcome, Option<FileControlError>),
}

fn run_owned_begin_worker<Connection: BeginOwnedConnection>(
    connection: &mut Option<Connection>,
    outcome: &std::sync::mpsc::SyncSender<Result<ManualTransactionIdentity, FileControlError>>,
    command: &std::sync::mpsc::Receiver<BeginWorkerCommand>,
    database_slot: &Arc<std::sync::Mutex<Option<LiveInterruptPointer>>>,
    restore_busy_timeout: std::time::Duration,
    cancellation: &Arc<BeginCancellation>,
    executors: BeginWorkerExecutors<'_>,
) -> BeginWorkerDecision {
    let begin = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_locked_begin(
            executors.runtime,
            connection
                .as_mut()
                .expect("BEGIN worker connection remains owned"),
            outcome,
            command,
            database_slot,
            restore_busy_timeout,
            cancellation,
        )
    }));
    let begin = match begin {
        Ok(begin) => begin,
        Err(_) => {
            let _ = outcome.try_send(Err(FileControlError::Handle(
                "BEGIN worker panicked after taking connection ownership".to_owned(),
            )));
            let permit = executors
                .terminal_closes
                .take_permit()
                .expect("panicked BEGIN close capacity was pre-reserved");
            let close = close_owned_begin_connection(
                permit,
                connection
                    .take()
                    .expect("panicked BEGIN retains its connection"),
            );
            return BeginWorkerDecision::Terminal(
                close,
                Some(FileControlError::Handle(
                    "BEGIN worker panicked after taking connection ownership".to_owned(),
                )),
            );
        }
    };
    match begin {
        LockedBeginOutcome::Accepted(identity, authorizer_address) => {
            BeginWorkerDecision::Accepted(identity, authorizer_address)
        }
        LockedBeginOutcome::Failed(error) => {
            let _ = outcome.try_send(Err(error.clone()));
            #[cfg(test)]
            wait_at_begin_failure_cleanup_gate(cancellation);
            let permit = executors
                .terminal_closes
                .take_permit()
                .expect("failed BEGIN close capacity was pre-reserved");
            let close = close_owned_begin_connection(
                permit,
                connection
                    .take()
                    .expect("failed BEGIN retains its connection"),
            );
            BeginWorkerDecision::Terminal(close, Some(error))
        }
        LockedBeginOutcome::Cancelled => {
            let _ = outcome.try_send(Err(FileControlError::SQLite(
                libsqlite3_sys::SQLITE_INTERRUPT,
            )));
            let permit = executors
                .terminal_closes
                .take_permit()
                .expect("cancelled BEGIN close capacity was pre-reserved");
            let close = close_owned_begin_connection(
                permit,
                connection
                    .take()
                    .expect("cancelled BEGIN retains its connection"),
            );
            BeginWorkerDecision::Terminal(
                close,
                Some(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT)),
            )
        }
    }
}

async fn begin_manual_transaction_inner<Connection: BeginOwnedConnection>(
    connection: Connection,
    busy_timeout: std::time::Duration,
    work_deadline: Option<std::time::Instant>,
    cleanup_deadline: std::time::Instant,
    allow_expired_first_attempt: bool,
    restore_busy_timeout: std::time::Duration,
    ownership: (
        Option<Arc<std::sync::atomic::AtomicBool>>,
        Option<Vec<BlockingCleanupOwner>>,
    ),
) -> Result<ManualTransaction<Connection>, FileControlError> {
    let (external_cancellation, reserved_owners) = ownership;
    let now = std::time::Instant::now();
    if work_deadline.is_some_and(|deadline| cleanup_deadline <= deadline) {
        return Err(FileControlError::Handle(
            "BEGIN cleanup deadline must be later than its work deadline".to_owned(),
        ));
    }
    let busy_deadline = if busy_timeout.is_zero() {
        None
    } else {
        let relative = now.checked_add(busy_timeout).unwrap_or(now);
        Some(work_deadline.map_or(relative, |deadline| deadline.min(relative)))
    };
    let admission_deadline = work_deadline.unwrap_or(now);
    let mut owners = if let Some(owners) = reserved_owners {
        if owners.len() != 3 {
            return Err(FileControlError::Handle(
                "BEGIN requires exactly three transferred cleanup owners".to_owned(),
            ));
        }
        owners
    } else {
        BlockingCleanupOwner::acquire_many_until(
            "claw-sqlite-begin-owner",
            3,
            Some(admission_deadline),
            allow_expired_first_attempt,
        )
        .await
        .map_err(|error| {
            FileControlError::Handle(format!("acquire BEGIN worker and cleanup owners: {error}"))
        })?
    };
    let post_commit_owner = owners.pop().expect("post-COMMIT cleanup owner");
    let cleanup_owner = owners.pop().expect("terminal BEGIN cleanup owner");
    let mut worker_owner = owners.pop().expect("BEGIN worker owner");
    let database = Arc::new(std::sync::Mutex::new(None));
    let worker_database = Arc::clone(&database);
    let cancellation = Arc::new(BeginCancellation {
        local: std::sync::atomic::AtomicBool::new(false),
        external: external_cancellation,
        work_deadline,
        busy_deadline,
        cleanup_deadline,
        stop_cause: AtomicU8::new(BEGIN_STOP_NONE),
        #[cfg(test)]
        busy_entered: std::sync::Mutex::new(None),
        #[cfg(test)]
        busy_sleep_gate: std::sync::Mutex::new(None),
        #[cfg(test)]
        test_key: std::sync::Mutex::new(None),
    });
    let worker_cancellation = Arc::clone(&cancellation);
    let (outcome_tx, outcome_rx) = std::sync::mpsc::sync_channel(1);
    let (command_tx, command_rx) = std::sync::mpsc::channel();
    let (worker_result_tx, worker_result_rx) = std::sync::mpsc::sync_channel(0);
    worker_owner
        .handoff_payload_internal(
            std::sync::Mutex::new(Some(connection)),
            move |runtime, terminal_closes, connection| {
                let mut connection = connection
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let decision = run_owned_begin_worker(
                    &mut connection,
                    &outcome_tx,
                    &command_rx,
                    &worker_database,
                    restore_busy_timeout,
                    &worker_cancellation,
                    BeginWorkerExecutors {
                        runtime,
                        terminal_closes,
                    },
                );
                let result = match decision {
                    BeginWorkerDecision::Accepted(identity, authorizer_address) => {
                        BeginWorkerOutput::Accepted(
                            connection
                                .take()
                                .expect("accepted BEGIN connection remains owned"),
                            identity,
                            authorizer_address,
                        )
                    }
                    BeginWorkerDecision::Terminal(close, primary) => {
                        BeginWorkerOutput::Terminal(close, primary)
                    }
                };
                if let Err(error) = worker_result_tx.send(result) {
                    let permit = terminal_closes
                        .take_permit()
                        .expect("rejected BEGIN delivery close capacity was pre-reserved");
                    match error.0 {
                        BeginWorkerOutput::Accepted(connection, _, authorizer_address) => {
                            let _ = permit.submit_with_authorizer(connection, authorizer_address);
                        }
                        BeginWorkerOutput::Terminal(_, _) => {}
                    }
                }
            },
        )
        .map_err(FileControlError::Handle)?;
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
                if cancellation.is_expired()
                    || std::time::Instant::now() >= cancellation.cleanup_deadline()
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
            let primary = if cancellation.stopped_by_work_or_cancellation()
                && matches!(
                    error.code().map(|code| code & 0xff),
                    Some(libsqlite3_sys::SQLITE_BUSY | libsqlite3_sys::SQLITE_INTERRUPT)
                ) {
                FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT)
            } else {
                error
            };
            if let Err(cleanup) = guard.join_failure().await {
                return Err(FileControlError::Handle(format!(
                    "{primary}; terminal cleanup failed: {cleanup}"
                )));
            }
            return Err(primary);
        }
    };
    if cancellation.is_expired() {
        let primary = FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT);
        if cancellation.is_cancelled() {
            drop(guard);
            return Err(primary);
        }
        if let Err(cleanup) = guard.join_failure().await {
            return Err(FileControlError::Handle(format!(
                "{primary}; terminal cleanup failed: {cleanup}"
            )));
        }
        return Err(primary);
    }
    let generation = take_nonzero_generation(
        &NEXT_MANUAL_TRANSACTION_GENERATION,
        "manual transaction generation",
    )?;
    let registration = ActiveTransactionRegistration::register(identity, generation)?;
    let (connection, worker_identity, authorizer_address, cleanup_owner) =
        guard.accept(Arc::clone(&registration.state)).await?;
    debug_assert_eq!(worker_identity, identity);
    let transaction = ManualTransaction {
        connection: Some(TransactionConnection {
            inner: connection,
            state: Arc::clone(&registration.state),
        }),
        token: Some(registration.into_token(authorizer_address)),
        cleanup_owner: Some(cleanup_owner),
        post_commit_owner: Some(post_commit_owner),
    };
    if cancellation.is_expired() {
        let cleanup_cutoff = tokio::time::Instant::from_std(cancellation.cleanup_deadline());
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

fn relative_begin_deadline(
    busy_timeout: std::time::Duration,
) -> (Option<std::time::Instant>, std::time::Instant, bool) {
    let now = std::time::Instant::now();
    if busy_timeout.is_zero() {
        (
            None,
            now.checked_add(std::time::Duration::from_secs(1))
                .unwrap_or(now),
            true,
        )
    } else {
        let work_deadline = now.checked_add(busy_timeout).unwrap_or(now);
        (
            Some(work_deadline),
            work_deadline
                .checked_add(std::time::Duration::from_secs(1))
                .unwrap_or(work_deadline),
            false,
        )
    }
}

/// Starts a manual immediate transaction on an owned, non-pool-returnable connection.
pub async fn begin_manual_transaction(
    connection: sqlx::SqliteConnection,
    busy_timeout: std::time::Duration,
    external_cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Result<ManualTransaction<sqlx::SqliteConnection>, FileControlError> {
    let (deadline, cleanup_deadline, allow_expired_first_attempt) =
        relative_begin_deadline(busy_timeout);
    begin_manual_transaction_inner(
        connection,
        busy_timeout,
        deadline,
        cleanup_deadline,
        allow_expired_first_attempt,
        busy_timeout,
        (external_cancellation, None),
    )
    .await
}

/// Starts a manual immediate transaction while retaining the pool connection lease.
pub async fn begin_manual_pool_transaction(
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    busy_timeout: std::time::Duration,
) -> Result<ManualTransaction<sqlx::pool::PoolConnection<sqlx::Sqlite>>, FileControlError> {
    let (deadline, cleanup_deadline, allow_expired_first_attempt) =
        relative_begin_deadline(busy_timeout);
    begin_manual_transaction_inner(
        connection,
        busy_timeout,
        deadline,
        cleanup_deadline,
        allow_expired_first_attempt,
        busy_timeout,
        (None, None),
    )
    .await
}

/// Starts a pool transaction with a temporary BEGIN busy bound and restores the configured bound.
pub async fn begin_manual_pool_transaction_with_restore(
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    begin_busy_timeout: std::time::Duration,
    restore_busy_timeout: std::time::Duration,
    external_cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Result<ManualTransaction<sqlx::pool::PoolConnection<sqlx::Sqlite>>, FileControlError> {
    let (deadline, cleanup_deadline, allow_expired_first_attempt) =
        relative_begin_deadline(begin_busy_timeout);
    begin_manual_transaction_inner(
        connection,
        begin_busy_timeout,
        deadline,
        cleanup_deadline,
        allow_expired_first_attempt,
        restore_busy_timeout,
        (external_cancellation, None),
    )
    .await
}

/// Starts a pool transaction bounded by an existing absolute operation deadline.
pub async fn begin_manual_pool_transaction_with_restore_deadline(
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    operation_deadline: std::time::Instant,
    begin_busy_timeout: std::time::Duration,
    restore_busy_timeout: std::time::Duration,
    external_cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Result<ManualTransaction<sqlx::pool::PoolConnection<sqlx::Sqlite>>, FileControlError> {
    let cleanup_deadline = operation_deadline
        .checked_add(std::time::Duration::from_secs(1))
        .unwrap_or(operation_deadline);
    begin_manual_pool_transaction_with_restore_deadlines(
        connection,
        operation_deadline,
        cleanup_deadline,
        begin_busy_timeout,
        restore_busy_timeout,
        external_cancellation,
    )
    .await
}

/// Starts a pool transaction with immutable absolute work and cleanup deadlines.
pub async fn begin_manual_pool_transaction_with_restore_deadlines(
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    work_deadline: std::time::Instant,
    cleanup_deadline: std::time::Instant,
    begin_busy_timeout: std::time::Duration,
    restore_busy_timeout: std::time::Duration,
    external_cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Result<ManualTransaction<sqlx::pool::PoolConnection<sqlx::Sqlite>>, FileControlError> {
    begin_manual_transaction_inner(
        connection,
        begin_busy_timeout,
        Some(work_deadline),
        cleanup_deadline,
        false,
        restore_busy_timeout,
        (external_cancellation, None),
    )
    .await
}

/// Starts an absolute-deadline pool transaction using three transferred cleanup owners.
pub async fn begin_manual_pool_transaction_with_restore_deadlines_and_owners(
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    work_deadline: std::time::Instant,
    cleanup_deadline: std::time::Instant,
    begin_busy_timeout: std::time::Duration,
    restore_busy_timeout: std::time::Duration,
    external_cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
    owners: Vec<BlockingCleanupOwner>,
) -> Result<ManualTransaction<sqlx::pool::PoolConnection<sqlx::Sqlite>>, FileControlError> {
    begin_manual_transaction_inner(
        connection,
        begin_busy_timeout,
        Some(work_deadline),
        cleanup_deadline,
        false,
        restore_busy_timeout,
        (external_cancellation, Some(owners)),
    )
    .await
}

fn validate_terminal_transaction_state(
    token: &ManualTransactionToken,
) -> Result<(), FileControlError> {
    if token.state.key != (token.database_address, token.connection_nonce)
        || token.state.generation != token.generation
    {
        return Err(FileControlError::TransactionInvalidated(
            "manual transaction token generation is stale".to_owned(),
        ));
    }
    let registered = ACTIVE_MANUAL_TRANSACTIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&token.state.key)
        .is_some_and(|state| Arc::ptr_eq(state, &token.state));
    if !registered {
        return Err(FileControlError::TransactionInvalidated(
            "transaction generation is no longer registered".to_owned(),
        ));
    }
    let inner = token
        .state
        .inner
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match &inner.phase {
        ManualTransactionPhase::Healthy if inner.in_flight.is_none() => Ok(()),
        ManualTransactionPhase::Healthy => Err(FileControlError::TransactionInvalidated(
            "a statement is still in flight".to_owned(),
        )),
        ManualTransactionPhase::Poisoned(reason) => {
            Err(FileControlError::TransactionInvalidated(reason.clone()))
        }
        ManualTransactionPhase::Terminal => Err(FileControlError::TransactionInvalidated(
            "transaction is terminal".to_owned(),
        )),
    }
}

/// Commits a transaction created by [`begin_manual_transaction`] synchronously
/// while holding SQLx's connection lock.
async fn commit_synchronously(
    connection: &mut sqlx::SqliteConnection,
    token: &mut ManualTransactionToken,
    cancellation: Option<&BeginCancellation>,
) -> Result<(), FileControlError> {
    #[cfg(test)]
    if FAIL_COMMIT_GENERATIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(&token.generation)
    {
        return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_BUSY));
    }
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    if !token.active {
        return Err(FileControlError::TransactionInvalidated(
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
    validate_terminal_transaction_state(token)?;
    if unsafe { libsqlite3_sys::sqlite3_get_autocommit(database.as_raw_handle().as_ptr()) } != 0 {
        poison_transaction_state(
            &token.state,
            "SQLite was already in autocommit before COMMIT",
        );
        return Err(FileControlError::TransactionInvalidated(
            "SQLite was already in autocommit before COMMIT".to_owned(),
        ));
    }
    if cancellation.is_some_and(BeginCancellation::is_expired) {
        return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
    }
    let internal_permit = InternalTransactionPermit::activate(token)?;
    let mut message = std::ptr::null_mut();
    let identity_attempt = arm_identity_commit_attempt(
        NonNull::new(database.as_raw_handle().as_ptr())
            .expect("SQLx locked handle exposes a non-null SQLite connection"),
    );
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
    let identity_veto = finish_identity_commit_attempt(
        NonNull::new(database.as_raw_handle().as_ptr())
            .expect("SQLx locked handle exposes a non-null SQLite connection"),
        identity_attempt,
    );
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
            } else if let Some(veto) = identity_veto {
                FileControlError::IdentityCommitVetoed(
                    veto,
                    Some(format!("transaction authorizer cleanup: {error}")),
                )
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
        Err(identity_veto.map_or_else(
            || {
                FileControlError::CommitOutcomeUncertain(
                    result,
                    "autocommit was restored before the error was reported".to_owned(),
                )
            },
            |veto| FileControlError::IdentityCommitVetoed(veto, None),
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
    #[cfg(test)]
    {
        let mut calls = ROLLBACK_SYNCHRONOUS_CALLS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *calls.entry(token.generation).or_default() += 1;
    }
    #[cfg(test)]
    run_rollback_test_gate(token, RollbackTestStage::BeforeLockHandle);
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    if !token.active {
        return Err(FileControlError::TransactionInvalidated(
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
    validate_terminal_transaction_state(token)?;
    if unsafe { libsqlite3_sys::sqlite3_get_autocommit(database.as_raw_handle().as_ptr()) } != 0 {
        poison_transaction_state(
            &token.state,
            "SQLite was already in autocommit before ROLLBACK",
        );
        return Err(FileControlError::TransactionInvalidated(
            "SQLite was already in autocommit before ROLLBACK".to_owned(),
        ));
    }
    let internal_permit = InternalTransactionPermit::activate(token)?;
    let mut message = std::ptr::null_mut();
    #[cfg(test)]
    run_rollback_test_gate(token, RollbackTestStage::BeforeSqliteExec);
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

struct RawDeadlineContext {
    deadline: std::time::Instant,
    cancelled: Arc<AtomicBool>,
}

unsafe extern "C" fn raw_deadline_progress(context: *mut std::ffi::c_void) -> i32 {
    // SAFETY: the raw operation owns this context for the complete registration.
    let context = unsafe { &*context.cast::<RawDeadlineContext>() };
    i32::from(
        context.cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= context.deadline,
    )
}

struct RawStatement(*mut libsqlite3_sys::sqlite3_stmt);

impl Drop for RawStatement {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns the prepared statement.
        unsafe {
            libsqlite3_sys::sqlite3_finalize(self.0);
        }
    }
}

struct ApplicationIdReadContext {
    deadline: std::time::Instant,
    cancelled: Arc<AtomicBool>,
    value: Option<i64>,
}

unsafe extern "C" fn application_id_progress(context: *mut std::ffi::c_void) -> i32 {
    // SAFETY: the raw read owns this context for the complete registration.
    let context = unsafe { &*context.cast::<ApplicationIdReadContext>() };
    i32::from(
        context.cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= context.deadline,
    )
}

unsafe extern "C" fn capture_application_id(
    context: *mut std::ffi::c_void,
    columns: i32,
    values: *mut *mut std::ffi::c_char,
    _names: *mut *mut std::ffi::c_char,
) -> i32 {
    if columns != 1 || values.is_null() {
        return 1;
    }
    // SAFETY: SQLite supplies one value pointer for the callback invocation.
    let value = unsafe { *values };
    if value.is_null() {
        return 1;
    }
    // SAFETY: SQLite supplies a NUL-terminated text representation.
    let value = unsafe { std::ffi::CStr::from_ptr(value) };
    let Some(value) = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return 1;
    };
    // SAFETY: the raw read owns this context for the callback lifetime.
    unsafe { &mut *context.cast::<ApplicationIdReadContext>() }.value = Some(value);
    0
}

struct RawProgressRegistration(LiveInterruptPointer);

impl Drop for RawProgressRegistration {
    fn drop(&mut self) {
        // SAFETY: the registration guard remains within the locked handle scope.
        unsafe {
            libsqlite3_sys::sqlite3_progress_handler(
                self.0.as_ptr(),
                0,
                None,
                std::ptr::null_mut(),
            );
        }
    }
}

/// Reads `PRAGMA application_id` without releasing ownership across the absolute cutoff.
pub async fn read_application_id_with_deadline(
    connection: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>,
    deadline: std::time::Instant,
    cancelled: Arc<AtomicBool>,
) -> Result<i64, FileControlError> {
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    if cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
        return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
    }
    let database = LiveInterruptPointer(database.as_raw_handle());
    let mut context = ApplicationIdReadContext {
        deadline,
        cancelled,
        value: None,
    };
    // SAFETY: the locked handle and stack context remain live until registration clear.
    unsafe {
        libsqlite3_sys::sqlite3_progress_handler(
            database.as_ptr(),
            1,
            Some(application_id_progress),
            (&raw mut context).cast(),
        );
    }
    let _registration = RawProgressRegistration(database);
    // SAFETY: no await occurs between the cutoff check and raw dispatch.
    let result = unsafe {
        libsqlite3_sys::sqlite3_exec(
            database.as_ptr(),
            c"PRAGMA application_id".as_ptr(),
            Some(capture_application_id),
            (&raw mut context).cast(),
            std::ptr::null_mut(),
        )
    };
    if result != libsqlite3_sys::SQLITE_OK {
        return Err(FileControlError::SQLite(result));
    }
    context.value.ok_or_else(|| {
        FileControlError::Handle("PRAGMA application_id returned no value".to_owned())
    })
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
        commit_attempt: std::sync::Mutex::new(IdentityCommitAttemptState::default()),
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
    commit_attempt: std::sync::Mutex<IdentityCommitAttemptState>,
}

#[cfg(any(unix, windows))]
#[derive(Default)]
struct IdentityCommitAttemptState {
    next_id: u64,
    active: Option<IdentityCommitAttempt>,
}

#[cfg(any(unix, windows))]
struct IdentityCommitAttempt {
    id: u64,
    veto: Option<IdentityCommitVeto>,
}

#[cfg(any(unix, windows))]
fn arm_commit_attempt(state: &std::sync::Mutex<IdentityCommitAttemptState>) -> u64 {
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.next_id = state.next_id.wrapping_add(1);
    let id = state.next_id;
    state.active = Some(IdentityCommitAttempt { id, veto: None });
    id
}

#[cfg(any(unix, windows))]
fn record_commit_veto(
    state: &std::sync::Mutex<IdentityCommitAttemptState>,
    veto: IdentityCommitVeto,
) {
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(attempt) = state.active.as_mut()
        && attempt.veto.is_none()
    {
        attempt.veto = Some(veto);
    }
}

#[cfg(any(unix, windows))]
fn finish_commit_attempt(
    state: &std::sync::Mutex<IdentityCommitAttemptState>,
    id: u64,
) -> Option<IdentityCommitVeto> {
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state
        .active
        .as_ref()
        .is_some_and(|attempt| attempt.id == id)
    {
        state.active.take().and_then(|attempt| attempt.veto)
    } else {
        None
    }
}

#[cfg(unix)]
fn arm_identity_commit_attempt(database: NonNull<libsqlite3_sys::sqlite3>) -> Option<u64> {
    // SAFETY: the locked connection owns any named client-data context.
    let context = unsafe {
        libsqlite3_sys::sqlite3_get_clientdata(
            database.as_ptr(),
            c"gta-claw-commit-identity".as_ptr(),
        )
    };
    let context = NonNull::new(context.cast::<IdentityCommitContext>())?;
    // SAFETY: client data remains live for the locked connection.
    Some(arm_commit_attempt(
        &unsafe { context.as_ref() }.commit_attempt,
    ))
}

#[cfg(unix)]
fn finish_identity_commit_attempt(
    database: NonNull<libsqlite3_sys::sqlite3>,
    id: Option<u64>,
) -> Option<IdentityCommitVeto> {
    let id = id?;
    // SAFETY: the locked connection owns any named client-data context.
    let context = unsafe {
        libsqlite3_sys::sqlite3_get_clientdata(
            database.as_ptr(),
            c"gta-claw-commit-identity".as_ptr(),
        )
    };
    let context = NonNull::new(context.cast::<IdentityCommitContext>())?;
    // SAFETY: client data remains live for the locked connection.
    finish_commit_attempt(&unsafe { context.as_ref() }.commit_attempt, id)
}

#[cfg(windows)]
fn arm_identity_commit_attempt(database: NonNull<libsqlite3_sys::sqlite3>) -> Option<u64> {
    // SAFETY: the locked connection owns any named client-data context.
    let context = unsafe {
        libsqlite3_sys::sqlite3_get_clientdata(
            database.as_ptr(),
            c"gta-claw-windows-commit-identity".as_ptr(),
        )
    };
    let context = NonNull::new(context.cast::<WindowsIdentityCommitContext>())?;
    // SAFETY: client data remains live for the locked connection.
    Some(arm_commit_attempt(
        &unsafe { context.as_ref() }.commit_attempt,
    ))
}

#[cfg(windows)]
fn finish_identity_commit_attempt(
    database: NonNull<libsqlite3_sys::sqlite3>,
    id: Option<u64>,
) -> Option<IdentityCommitVeto> {
    let id = id?;
    // SAFETY: the locked connection owns any named client-data context.
    let context = unsafe {
        libsqlite3_sys::sqlite3_get_clientdata(
            database.as_ptr(),
            c"gta-claw-windows-commit-identity".as_ptr(),
        )
    };
    let context = NonNull::new(context.cast::<WindowsIdentityCommitContext>())?;
    // SAFETY: client data remains live for the locked connection.
    finish_commit_attempt(&unsafe { context.as_ref() }.commit_attempt, id)
}

#[cfg(not(any(unix, windows)))]
fn arm_identity_commit_attempt(_database: NonNull<libsqlite3_sys::sqlite3>) -> Option<u64> {
    None
}

#[cfg(not(any(unix, windows)))]
fn finish_identity_commit_attempt(
    _database: NonNull<libsqlite3_sys::sqlite3>,
    _id: Option<u64>,
) -> Option<IdentityCommitVeto> {
    None
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
    let veto = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unix_identity_rejection(context).or_else(|| {
            database_has_moved(context.database).then(|| IdentityCommitVeto {
                path: context.database_path.clone(),
                reason: "SQLite main database identity changed during COMMIT",
            })
        })
    }))
    .unwrap_or_else(|_| {
        Some(IdentityCommitVeto {
            path: context.database_path.clone(),
            reason: "SQLite identity commit hook panicked",
        })
    });
    if let Some(veto) = veto {
        record_commit_veto(&context.commit_attempt, veto);
        1
    } else {
        0
    }
}

#[cfg(unix)]
fn unix_identity_rejection(context: &IdentityCommitContext) -> Option<IdentityCommitVeto> {
    use std::os::unix::fs::FileExt as _;
    use xattr::FileExt as _;

    if context.writer_generation.load(Ordering::Acquire) != context.expected_writer_generation {
        return Some(IdentityCommitVeto {
            path: context.lock_path.clone(),
            reason: "SQLite writer generation changed during COMMIT",
        });
    }
    if !unix_path_matches_private_directory(
        &context.database_parent_path,
        &context.database_parent,
        context.expected_uid,
    ) {
        return Some(IdentityCommitVeto {
            path: context.database_parent_path.clone(),
            reason: "SQLite database parent identity changed during COMMIT",
        });
    }
    if !unix_path_matches_private_file(
        &context.database_path,
        &context.database_file,
        0o600,
        context.expected_uid,
    ) {
        return Some(IdentityCommitVeto {
            path: context.database_path.clone(),
            reason: "SQLite database path identity changed during COMMIT",
        });
    }
    if !unix_path_matches_private_file(
        &context.lock_path,
        &context.lock_file,
        0o600,
        context.expected_uid,
    ) {
        return Some(IdentityCommitVeto {
            path: context.lock_path.clone(),
            reason: "SQLite writer lock identity changed during COMMIT",
        });
    }
    let Ok(Some(identity)) = context
        .database_file
        .get_xattr("user.gta-claw.writer-lock-path")
    else {
        return Some(IdentityCommitVeto {
            path: context.database_path.clone(),
            reason: "SQLite writer lock identity xattr is missing during COMMIT",
        });
    };
    if identity != context.expected_identity {
        return Some(IdentityCommitVeto {
            path: context.database_path.clone(),
            reason: "SQLite writer lock identity xattr changed during COMMIT",
        });
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
            let reason = if sidecar
                .path
                .as_os_str()
                .as_encoded_bytes()
                .ends_with(b"-wal")
            {
                "SQLite WAL identity changed during COMMIT"
            } else {
                "SQLite shared-memory identity changed during COMMIT"
            };
            return Some(IdentityCommitVeto {
                path: sidecar.path.clone(),
                reason,
            });
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
        return Some(IdentityCommitVeto {
            path: std::path::PathBuf::from(journal),
            reason: "SQLite rollback journal identity changed during COMMIT",
        });
    }
    let Ok(metadata) = context.lock_file.metadata() else {
        return Some(IdentityCommitVeto {
            path: context.lock_path.clone(),
            reason: "SQLite writer lock metadata became unavailable during COMMIT",
        });
    };
    if usize::try_from(metadata.len()).ok() != Some(context.expected_identity.len()) {
        return Some(IdentityCommitVeto {
            path: context.lock_path.clone(),
            reason: "SQLite writer lock contents changed during COMMIT",
        });
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
        Ok(read) if read == contents.len() && contents == context.expected_identity => None,
        Ok(_) | Err(_) => Some(IdentityCommitVeto {
            path: context.lock_path.clone(),
            reason: "SQLite writer lock contents changed during COMMIT",
        }),
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
        commit_attempt: std::sync::Mutex::new(IdentityCommitAttemptState::default()),
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
    commit_attempt: std::sync::Mutex<IdentityCommitAttemptState>,
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
    if valid {
        0
    } else {
        record_commit_veto(
            &context.commit_attempt,
            IdentityCommitVeto {
                path: context.database_path.clone(),
                reason: "Windows SQLite identity binding changed during COMMIT",
            },
        );
        1
    }
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
        || windows_file_link_count(&context.database_file).ok() != Some(1)
        || windows_file_link_count(&database_current).ok() != Some(1)
        || windows_file_link_count(&context.lock_file).ok() != Some(1)
        || windows_file_link_count(&lock_current).ok() != Some(1)
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
            || windows_file_link_count(&sidecar.file).ok() != Some(1)
            || windows_file_link_count(&current).ok() != Some(1)
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
                || windows_file_link_count(&journal).ok() != Some(1)
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

/// Returns the number of hard-link names for a Windows file handle.
#[cfg(windows)]
pub fn windows_file_link_count(file: &std::fs::File) -> Result<u32, FileControlError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandleEx,
    };

    let mut information = FILE_STANDARD_INFO::default();
    // SAFETY: The live file handle and output match FileStandardInfo.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStandardInfo,
            (&raw mut information).cast(),
            u32::try_from(std::mem::size_of::<FILE_STANDARD_INFO>())
                .expect("FILE_STANDARD_INFO size fits u32"),
        )
    };
    if succeeded == 0 {
        Err(FileControlError::Handle(format!(
            "Windows file link-count query failed: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(information.NumberOfLinks)
    }
}

/// Returns the normalized native final path for a Windows file handle.
#[cfg(windows)]
pub fn windows_file_final_path(
    file: &std::fs::File,
) -> Result<std::path::PathBuf, FileControlError> {
    use std::os::windows::{ffi::OsStringExt as _, io::AsRawHandle as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
    };

    // SAFETY: A null output with zero length queries the required buffer size.
    let required = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if required == 0 {
        return Err(FileControlError::Handle(format!(
            "Windows final-path size query failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut path = vec![0_u16; required as usize];
    // SAFETY: `path` provides the size returned by the preceding query.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            required,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if written == 0 || written >= required {
        return Err(FileControlError::Handle(format!(
            "Windows final-path query failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    path.truncate(written as usize);
    Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(
        &path,
    )))
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

/// Marks the exact held Windows file object for deletion when its final handle closes.
#[cfg(windows)]
pub fn delete_file_by_handle(file: &std::fs::File) -> Result<(), FileControlError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the caller supplies a live file handle opened with DELETE access;
    // SetFileInformationByHandle borrows the fixed-size disposition structure.
    let result = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                .expect("file disposition structure size fits u32"),
        )
    };
    if result == 0 {
        Err(FileControlError::Handle(format!(
            "mark held Windows file for deletion: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

/// Derives a DELETE-capable handle for the exact held Windows file object.
#[cfg(windows)]
pub fn reopen_file_for_deletion(file: &std::fs::File) -> Result<std::fs::File, FileControlError> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        ReOpenFile,
    };
    const DELETE_ACCESS: u32 = 0x0001_0000;

    // SAFETY: ReOpenFile derives a new handle for the exact live file object and
    // does not resolve a pathname.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(FileControlError::Handle(format!(
            "derive held Windows deletion handle: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: ReOpenFile returned a fresh uniquely owned handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    Ok(std::fs::File::from(handle))
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use sqlx::{Connection as _, Executor as _, Row as _};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[test]
    fn queued_terminal_close_result_wins_over_elapsed_cutoff() {
        let (result, receiver) = std::sync::mpsc::sync_channel(1);
        result
            .send(TerminalCloseOutcome::Closed)
            .expect("queue completed terminal close");
        assert_eq!(
            TerminalCloseReceipt { result: receiver }.wait(std::time::Instant::now()),
            TerminalCloseOutcome::Closed
        );
    }

    #[derive(Debug)]
    struct StallingPoolConnection {
        connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
        entered: Arc<AtomicUsize>,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }

    impl private::SealedConnection for StallingPoolConnection {
        fn prepare_terminal_close(connection: &mut Self) {
            connection.connection.close_on_drop();
        }

        fn make_close_future(transfer: CloseTransfer<Self>) -> TerminalCloseFuture {
            transfer.into_future(|mut connection| async move {
                connection.entered.fetch_add(1, Ordering::AcqRel);
                let (released, changed) = &*connection.release;
                {
                    let mut released = released
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    while !*released {
                        released = changed
                            .wait(released)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                }
                // SAFETY: the installed future is the unique terminal owner.
                let connection = unsafe { std::mem::ManuallyDrop::take(&mut connection) };
                connection
                    .connection
                    .close()
                    .await
                    .map_err(|error| error.to_string())
            })
        }
    }

    impl BeginOwnedConnection for StallingPoolConnection {
        fn sqlite_ref(&self) -> &sqlx::SqliteConnection {
            &self.connection
        }

        fn sqlite(&mut self) -> &mut sqlx::SqliteConnection {
            &mut self.connection
        }
    }

    #[derive(Debug)]
    struct PanickingPoolConnection {
        connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
        entered: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
    }

    impl Drop for PanickingPoolConnection {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct PanickingCloseFuture {
        transfer: CloseTransfer<PanickingPoolConnection>,
    }

    impl std::future::Future for PanickingCloseFuture {
        type Output = Result<(), String>;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            self.transfer
                .with_mut(|connection| {
                    connection.entered.fetch_add(1, Ordering::AcqRel);
                    std::hint::black_box(&connection.connection);
                })
                .expect("panic close transfer remains owned");
            panic!("injected terminal close panic");
        }
    }

    impl private::SealedConnection for PanickingPoolConnection {
        fn prepare_terminal_close(connection: &mut Self) {
            connection.connection.close_on_drop();
        }

        fn make_close_future(transfer: CloseTransfer<Self>) -> TerminalCloseFuture {
            Box::pin(PanickingCloseFuture { transfer })
        }
    }

    impl BeginOwnedConnection for PanickingPoolConnection {
        fn sqlite_ref(&self) -> &sqlx::SqliteConnection {
            &self.connection
        }

        fn sqlite(&mut self) -> &mut sqlx::SqliteConnection {
            &mut self.connection
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum CloseHookPanic {
        Prepare,
        ConvertBeforeTake,
        ConvertAfterTake,
        PollAfterTake,
    }

    #[derive(Debug)]
    struct HookPanickingPoolConnection {
        connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
        mode: CloseHookPanic,
        entered: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
    }

    impl Drop for HookPanickingPoolConnection {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct OwnedPollPanickingCloseFuture {
        connection: std::mem::ManuallyDrop<HookPanickingPoolConnection>,
    }

    impl std::future::Future for OwnedPollPanickingCloseFuture {
        type Output = Result<(), String>;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            self.connection.entered.fetch_add(1, Ordering::AcqRel);
            std::hint::black_box(&self.connection.connection);
            panic!("injected close poll panic after take");
        }
    }

    impl private::SealedConnection for HookPanickingPoolConnection {
        fn prepare_terminal_close(connection: &mut Self) {
            connection.entered.fetch_add(1, Ordering::AcqRel);
            if matches!(connection.mode, CloseHookPanic::Prepare) {
                panic!("injected prepare close panic");
            }
            connection.connection.close_on_drop();
        }

        fn make_close_future(transfer: CloseTransfer<Self>) -> TerminalCloseFuture {
            let mode = transfer
                .with_mut(|connection| connection.mode)
                .expect("hook close transfer remains owned");
            match mode {
                CloseHookPanic::Prepare => unreachable!("prepare panic prevents conversion"),
                CloseHookPanic::ConvertBeforeTake => {
                    transfer
                        .with_mut(|connection| {
                            connection.entered.fetch_add(1, Ordering::AcqRel);
                        })
                        .expect("hook close transfer remains owned");
                    panic!("injected close conversion panic before take");
                }
                CloseHookPanic::ConvertAfterTake => {
                    let mut slot = transfer
                        .0
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let connection = std::mem::ManuallyDrop::new(
                        slot.take().expect("hook close transfer remains owned"),
                    );
                    connection.entered.fetch_add(1, Ordering::AcqRel);
                    std::hint::black_box(&connection.connection);
                    panic!("injected close conversion panic after take");
                }
                CloseHookPanic::PollAfterTake => {
                    transfer.into_future(|connection| OwnedPollPanickingCloseFuture { connection })
                }
            }
        }
    }

    impl BeginOwnedConnection for HookPanickingPoolConnection {
        fn sqlite_ref(&self) -> &sqlx::SqliteConnection {
            &self.connection
        }

        fn sqlite(&mut self) -> &mut sqlx::SqliteConnection {
            &mut self.connection
        }
    }

    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct RetentionDropProbe {
        entered: Arc<AtomicBool>,
        drops: Arc<AtomicUsize>,
        threads: Arc<std::sync::Mutex<Vec<String>>>,
        release: Option<Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>>,
        panic: bool,
    }

    impl Drop for RetentionDropProbe {
        fn drop(&mut self) {
            self.entered.store(true, Ordering::Release);
            self.drops.fetch_add(1, Ordering::AcqRel);
            self.threads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(
                    std::thread::current()
                        .name()
                        .unwrap_or("unnamed")
                        .to_owned(),
                );
            if let Some(release) = &self.release {
                let (released, changed) = &**release;
                let mut released = released
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !*released {
                    released = changed
                        .wait(released)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            }
            assert!(!self.panic, "injected retention destructor panic");
        }
    }

    fn destroy_cleanup_envelope_for_test(mut envelope: CleanupEnvelope) {
        if let Some(job) = envelope.job.take() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(job)));
        }
        if let Some(retention) = envelope.panic_retention.take() {
            let _ = retention.destroy_once();
        }
        if let Some(callback) = envelope.callback_retention.take() {
            let _ = callback.destroy_once();
        }
        envelope.reservation.take();
        envelope.retirement_reservation.take();
    }

    fn destroy_terminal_envelope_for_test(mut envelope: TerminalCloseEnvelope) {
        if let Some(job) = envelope.job.take() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(job)));
        }
        if let Some(retention) = envelope.panic_retention.take() {
            let _ = retention.destroy_once();
        }
        if let Some(callback) = envelope.callback_retention.take() {
            let _ = callback.destroy_once();
        }
        envelope.cleanup_reservation.take();
        envelope.reservation.take();
    }

    struct RollbackGateRegistration {
        generation: u64,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }

    impl RollbackGateRegistration {
        fn release(&self) {
            let (released, changed) = &*self.release;
            *released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            changed.notify_all();
        }
    }

    impl Drop for RollbackGateRegistration {
        fn drop(&mut self) {
            self.release();
            ROLLBACK_TEST_GATES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.generation);
            FAIL_COMMIT_GENERATIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.generation);
        }
    }

    fn install_rollback_gate<Connection: BeginOwnedConnection>(
        transaction: &ManualTransaction<Connection>,
        stage: RollbackTestStage,
        panic: bool,
        fail_commit: bool,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    ) -> (RollbackGateRegistration, Arc<AtomicBool>) {
        let generation = transaction
            .token
            .as_ref()
            .expect("rollback gate token remains owned")
            .generation;
        let entered = Arc::new(AtomicBool::new(false));
        assert!(
            ROLLBACK_TEST_GATES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(
                    generation,
                    RollbackTestGate {
                        stage,
                        panic,
                        entered: Arc::clone(&entered),
                        release: Arc::clone(&release),
                    },
                )
                .is_none()
        );
        if fail_commit {
            assert!(
                FAIL_COMMIT_GENERATIONS
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(generation)
            );
        }
        (
            RollbackGateRegistration {
                generation,
                release,
            },
            entered,
        )
    }

    #[cfg(unix)]
    struct CommitRestoreGateRegistration {
        generation: u64,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }

    #[cfg(unix)]
    impl Drop for CommitRestoreGateRegistration {
        fn drop(&mut self) {
            let (released, changed) = &*self.release;
            *released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            changed.notify_all();
            COMMIT_RESTORE_TEST_GATES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.generation);
        }
    }

    #[cfg(unix)]
    fn install_commit_restore_gate<Connection: BeginOwnedConnection>(
        transaction: &ManualTransaction<Connection>,
    ) -> (CommitRestoreGateRegistration, Arc<AtomicBool>) {
        let generation = transaction
            .token
            .as_ref()
            .expect("commit restore gate token remains owned")
            .generation;
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let previous = COMMIT_RESTORE_TEST_GATES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                generation,
                CommitRestoreTestGate {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                },
            );
        assert!(previous.is_none(), "commit restore gate is unique");
        (
            CommitRestoreGateRegistration {
                generation,
                release,
            },
            entered,
        )
    }

    async fn wait_for_atomic(flag: &AtomicBool, operation: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !flag.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{operation} did not reach its test gate"));
    }

    fn run_in_isolated_child(test_name: &str, marker: &str) -> bool {
        if std::env::var_os(marker).is_some() {
            return false;
        }
        let status = std::process::Command::new(
            std::env::current_exe().expect("resolve helper test executable"),
        )
        .arg(test_name)
        .arg("--exact")
        .arg("--test-threads=1")
        .env(marker, "1")
        .status()
        .expect("spawn isolated helper test");
        assert!(status.success(), "isolated helper test failed: {test_name}");
        true
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

    fn cancellation_with_busy_sleep_gate(
        external: Option<Arc<AtomicBool>>,
        busy_deadline: std::time::Instant,
    ) -> (
        Arc<BeginCancellation>,
        Arc<tokio::sync::Notify>,
        Arc<AtomicBool>,
    ) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(AtomicBool::new(false));
        (
            Arc::new(BeginCancellation {
                local: AtomicBool::new(false),
                external,
                work_deadline: Some(busy_deadline),
                busy_deadline: Some(busy_deadline),
                cleanup_deadline: busy_deadline
                    .checked_add(std::time::Duration::from_secs(1))
                    .unwrap_or(busy_deadline),
                stop_cause: AtomicU8::new(BEGIN_STOP_NONE),
                busy_entered: std::sync::Mutex::new(None),
                busy_sleep_gate: std::sync::Mutex::new(Some(BeginBusySleepTestGate {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                })),
                test_key: std::sync::Mutex::new(None),
            }),
            entered,
            release,
        )
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
    async fn zero_busy_timeout_attempts_once_without_retrying() {
        if run_in_isolated_child(
            "deadline_tests::zero_busy_timeout_attempts_once_without_retrying",
            "GTA_CLAW_ZERO_BUSY_TIMEOUT_CHILD",
        ) {
            return;
        }
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("zero-busy-begin.sqlite");
        let mut uncontended = manual_transaction_connection(&path).await;
        uncontended
            .execute("CREATE TABLE value(id INTEGER)")
            .await
            .expect("create zero-timeout fixture");
        let (mut uncontended, mut uncontended_token) =
            begin_manual_transaction(uncontended, std::time::Duration::ZERO, None)
                .await
                .expect("zero busy timeout performs one uncontended BEGIN")
                .into_test_parts();
        rollback_synchronously(&mut uncontended, &mut uncontended_token)
            .await
            .expect("rollback zero-timeout transaction");

        let locker = manual_transaction_connection(&path).await;
        let (mut locker, mut locker_token) =
            begin_manual_transaction(locker, std::time::Duration::from_secs(1), None)
                .await
                .expect("start contending transaction")
                .into_test_parts();
        let waiter = manual_transaction_connection(&path).await;
        let started = std::time::Instant::now();
        let error = begin_manual_transaction(waiter, std::time::Duration::ZERO, None)
            .await
            .expect_err("zero busy timeout rejects a contended BEGIN");
        assert_eq!(error.code(), Some(libsqlite3_sys::SQLITE_BUSY));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "zero busy timeout cannot retry a contended BEGIN"
        );
        rollback_synchronously(&mut locker, &mut locker_token)
            .await
            .expect("release contending transaction");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_absolute_deadline_is_not_rebased_as_zero_busy_timeout() {
        if run_in_isolated_child(
            "deadline_tests::expired_absolute_deadline_is_not_rebased_as_zero_busy_timeout",
            "GTA_CLAW_EXPIRED_ABSOLUTE_BEGIN_CHILD",
        ) {
            return;
        }
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("expired-absolute-begin.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open expired absolute deadline pool");
        sqlx::query("CREATE TABLE value(id INTEGER)")
            .execute(&pool)
            .await
            .expect("create expired deadline fixture");
        let connection = pool
            .acquire()
            .await
            .expect("acquire expired deadline lease");
        let error = begin_manual_pool_transaction_with_restore_deadline(
            connection,
            std::time::Instant::now(),
            std::time::Duration::ZERO,
            std::time::Duration::from_millis(500),
            None,
        )
        .await
        .expect_err("expired absolute deadline rejects before BEGIN");
        assert!(
            error.to_string().contains("admission timed out"),
            "absolute expiry remains a timeout instead of zero-timeout permission: {error}"
        );
        sqlx::query("INSERT INTO value VALUES (1)")
            .execute(&pool)
            .await
            .expect("expired deadline returns the unmodified pool lease");
        pool.close().await;
    }

    #[test]
    fn begin_stop_cause_precedence_and_primary_code_mapping_are_deterministic() {
        fn cancellation(
            work_deadline: std::time::Instant,
            busy_deadline: std::time::Instant,
            external: Option<Arc<AtomicBool>>,
        ) -> BeginCancellation {
            BeginCancellation {
                local: AtomicBool::new(false),
                external,
                work_deadline: Some(work_deadline),
                busy_deadline: Some(busy_deadline),
                cleanup_deadline: work_deadline + std::time::Duration::from_secs(1),
                stop_cause: AtomicU8::new(BEGIN_STOP_NONE),
                busy_entered: std::sync::Mutex::new(None),
                busy_sleep_gate: std::sync::Mutex::new(None),
                test_key: std::sync::Mutex::new(None),
            }
        }

        let now = std::time::Instant::now();
        let equal = cancellation(now, now, None);
        assert_eq!(equal.latch_stop_cause(now), BEGIN_STOP_WORK_DEADLINE);
        assert_eq!(
            begin_result_error(libsqlite3_sys::SQLITE_BUSY | (2 << 8), &equal),
            FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT)
        );

        let configured_first = cancellation(now + std::time::Duration::from_secs(1), now, None);
        assert_eq!(
            configured_first.latch_stop_cause(now),
            BEGIN_STOP_BUSY_DEADLINE
        );
        assert_eq!(
            begin_result_error(libsqlite3_sys::SQLITE_BUSY | (3 << 8), &configured_first,),
            FileControlError::SQLite(libsqlite3_sys::SQLITE_BUSY)
        );

        let external = Arc::new(AtomicBool::new(true));
        let cancelled = cancellation(
            now + std::time::Duration::from_secs(1),
            now + std::time::Duration::from_secs(1),
            Some(external),
        );
        assert_eq!(cancelled.latch_stop_cause(now), BEGIN_STOP_CANCELLED);
        assert_eq!(
            begin_result_error(libsqlite3_sys::SQLITE_IOERR | (7 << 8), &cancelled),
            FileControlError::SQLite(libsqlite3_sys::SQLITE_IOERR | (7 << 8))
        );
    }

    #[tokio::test]
    async fn begin_busy_restore_failure_discards_the_connection() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open restore-failure pool");
        let mut connection = pool
            .acquire()
            .await
            .expect("acquire restore-failure connection");
        let nonce = {
            let mut handle = connection
                .lock_handle()
                .await
                .expect("lock restore-failure handle");
            connection_lifetime_nonce(LiveInterruptPointer(handle.as_raw_handle()))
                .expect("read restore-failure nonce")
        };
        assert!(
            FAIL_BEGIN_BUSY_RESTORE_NONCES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(nonce)
        );
        let work_deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let error = begin_manual_pool_transaction_with_restore_deadlines(
            connection,
            work_deadline,
            work_deadline + std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(500),
            None,
        )
        .await
        .expect_err("restore failure discards an otherwise successful BEGIN");
        assert_eq!(error.code(), Some(libsqlite3_sys::SQLITE_ERROR));
        let replacement = tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
            .await
            .expect("discarded restore-failure connection releases pool capacity")
            .expect("replacement restore-failure connection opens");
        drop(replacement);
        pool.close().await;
    }

    #[tokio::test]
    async fn equal_absolute_begin_deadlines_are_rejected_before_dispatch() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open equal-deadline pool");
        let connection = pool
            .acquire()
            .await
            .expect("acquire equal-deadline connection");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let error = begin_manual_pool_transaction_with_restore_deadlines(
            connection,
            deadline,
            deadline,
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(500),
            None,
        )
        .await
        .expect_err("equal work and cleanup deadlines are ambiguous");
        assert!(
            error.to_string().contains("cleanup deadline must be later"),
            "deadline ordering error is explicit: {error}"
        );
        let replacement = tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
            .await
            .expect("pre-dispatch rejection releases pool capacity")
            .expect("equal-deadline lease remains reusable");
        drop(replacement);
        pool.close().await;
    }

    unsafe extern "C" fn reject_hookless_commit(_context: *mut std::ffi::c_void) -> i32 {
        1
    }

    #[tokio::test]
    async fn hookless_commit_veto_remains_uncertain() {
        let directory = tempfile::tempdir().expect("hookless veto directory");
        let path = directory.path().join("hookless-veto.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open hookless veto pool");
        sqlx::query("CREATE TABLE value(id INTEGER)")
            .execute(&pool)
            .await
            .expect("create hookless veto fixture");
        let connection = pool.acquire().await.expect("acquire hookless veto owner");
        let mut transaction =
            begin_manual_pool_transaction(connection, std::time::Duration::from_millis(500))
                .await
                .expect("begin hookless veto transaction");
        sqlx::query("INSERT INTO value VALUES (1)")
            .execute(&mut transaction)
            .await
            .expect("stage hookless veto row");
        {
            let mut handle = transaction
                .connection
                .as_mut()
                .expect("hookless veto connection remains owned")
                .inner
                .sqlite()
                .lock_handle()
                .await
                .expect("lock hookless veto handle");
            // SAFETY: the locked live handle retains this no-context callback until close.
            unsafe {
                libsqlite3_sys::sqlite3_commit_hook(
                    handle.as_raw_handle().as_ptr(),
                    Some(reject_hookless_commit),
                    std::ptr::null_mut(),
                );
            }
        }
        let error = transaction
            .commit()
            .await
            .expect_err("hookless veto cannot be proven safe");
        assert!(matches!(
            error,
            FileControlError::CommitOutcomeUncertain(531, _)
        ));
        let replacement = pool
            .acquire()
            .await
            .expect("hookless veto terminal close restores pool capacity");
        drop(replacement);
        pool.close().await;
    }

    #[cfg(unix)]
    async fn exercise_proven_identity_commit_veto(stall_restore: bool) {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        use xattr::FileExt as _;

        let directory = tempfile::tempdir().expect("identity veto directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure identity veto directory");
        let path = directory.path().join("identity-veto.sqlite");
        let lock_path = directory.path().join("identity-veto.lock");
        let identity = b"identity-veto-generation";
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open identity veto pool");
        sqlx::query("CREATE TABLE value(id INTEGER)")
            .execute(&pool)
            .await
            .expect("create identity veto fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secure identity veto database");
        let database_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open identity veto database");
        database_file
            .set_xattr("user.gta-claw.writer-lock-path", identity)
            .expect("bind identity veto database");
        let mut lock_file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .expect("create identity veto lock");
        lock_file
            .write_all(identity)
            .and_then(|()| lock_file.sync_all())
            .expect("persist identity veto lock");
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))
            .expect("secure identity veto lock");
        let parent_file = std::fs::File::open(directory.path()).expect("open identity veto parent");

        let connection = pool.acquire().await.expect("acquire identity veto owner");
        let mut transaction =
            begin_manual_pool_transaction(connection, std::time::Duration::from_millis(500))
                .await
                .expect("begin identity veto transaction");
        sqlx::query("INSERT INTO value VALUES (1)")
            .execute(&mut transaction)
            .await
            .expect("stage identity veto row");
        sqlx::query("CREATE TABLE veto_schema(value TEXT)")
            .execute(&mut transaction)
            .await
            .expect("stage identity veto schema mutation");
        let writer_generation = Arc::new(AtomicU64::new(7));
        {
            use std::os::unix::fs::MetadataExt as _;

            let mut handle = transaction
                .connection
                .as_mut()
                .expect("identity veto connection remains owned")
                .inner
                .sqlite()
                .lock_handle()
                .await
                .expect("lock identity veto handle");
            let database = handle.as_raw_handle();
            let context = Box::new(IdentityCommitContext {
                database,
                database_parent_path: directory.path().to_owned(),
                database_parent: parent_file.try_clone().expect("clone identity veto parent"),
                database_path: path.clone(),
                database_file: database_file
                    .try_clone()
                    .expect("clone identity veto database"),
                lock_path: lock_path.clone(),
                lock_file: lock_file.try_clone().expect("clone identity veto lock"),
                expected_identity: identity.to_vec(),
                expected_uid: database_file
                    .metadata()
                    .expect("inspect identity veto database")
                    .uid(),
                sidecars: Vec::new(),
                writer_generation,
                expected_writer_generation: 7,
                commit_attempt: std::sync::Mutex::new(IdentityCommitAttemptState::default()),
            });
            let context = Box::into_raw(context);
            // SAFETY: SQLite owns this exact boxed context until connection close.
            let registered = unsafe {
                libsqlite3_sys::sqlite3_set_clientdata(
                    database.as_ptr(),
                    c"gta-claw-commit-identity".as_ptr(),
                    context.cast(),
                    Some(drop_identity_commit_context),
                )
            };
            assert_eq!(registered, libsqlite3_sys::SQLITE_OK);
            // SAFETY: the client-data context is live and bound to this hook.
            unsafe {
                libsqlite3_sys::sqlite3_commit_hook(
                    database.as_ptr(),
                    Some(reject_moved_or_unbound_commit),
                    context.cast(),
                );
            }
        }
        database_file
            .remove_xattr("user.gta-claw.writer-lock-path")
            .expect("remove identity binding before COMMIT");
        let generation = transaction
            .token
            .as_ref()
            .expect("identity veto token remains owned")
            .generation;
        let transaction_key = transaction
            .token
            .as_ref()
            .expect("identity veto token remains owned")
            .state
            .key;
        let rollback_before = ROLLBACK_SYNCHRONOUS_CALLS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&generation)
            .copied()
            .unwrap_or_default();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
        let cleanup_deadline = deadline + std::time::Duration::from_millis(100);
        let error = if stall_restore {
            let (restore_gate, restore_entered) = install_commit_restore_gate(&transaction);
            let commit = tokio::spawn(async move {
                transaction
                    .commit_with_deadline(
                        deadline,
                        cleanup_deadline,
                        Arc::new(AtomicBool::new(false)),
                        std::time::Duration::from_millis(500),
                        None,
                    )
                    .await
            });
            wait_for_atomic(
                &restore_entered,
                "identity veto reaches busy-handler restoration",
            )
            .await;
            let error = commit
                .await
                .expect("stalled identity veto commit task joins")
                .expect_err("proven veto survives restore stall");
            drop(restore_gate);
            error
        } else {
            transaction
                .commit_with_deadline(
                    deadline,
                    cleanup_deadline,
                    Arc::new(AtomicBool::new(false)),
                    std::time::Duration::from_millis(500),
                    None,
                )
                .await
                .expect_err("identity hook vetoes exact COMMIT")
        };
        let FileControlError::IdentityCommitVetoed(veto, cleanup) = error else {
            panic!("expected proven identity veto");
        };
        assert_eq!(veto.path(), path);
        assert_eq!(
            veto.reason(),
            "SQLite writer lock identity xattr is missing during COMMIT"
        );
        if stall_restore {
            assert!(
                cleanup
                    .as_deref()
                    .is_some_and(|cleanup| cleanup.contains("cleanup cutoff")),
                "restore stall preserves typed veto with cleanup detail: {cleanup:?}"
            );
        } else {
            assert!(cleanup.is_none());
        }
        assert!(
            !ACTIVE_MANUAL_TRANSACTIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&transaction_key),
            "proven veto unregisters its exact transaction generation"
        );
        assert_eq!(
            ROLLBACK_SYNCHRONOUS_CALLS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&generation)
                .unwrap_or_default(),
            rollback_before,
            "proven hook rollback cannot dispatch a second SQL ROLLBACK"
        );
        database_file
            .set_xattr("user.gta-claw.writer-lock-path", identity)
            .expect("restore identity binding");
        let mut replacement = pool
            .acquire()
            .await
            .expect("terminally closed veto connection is replaced");
        {
            let mut handle = replacement
                .lock_handle()
                .await
                .expect("lock replacement connection");
            // SAFETY: the replacement handle is locked and live.
            let stale_context = unsafe {
                libsqlite3_sys::sqlite3_get_clientdata(
                    handle.as_raw_handle().as_ptr(),
                    c"gta-claw-commit-identity".as_ptr(),
                )
            };
            assert!(
                stale_context.is_null(),
                "the identity-compromised connection cannot return to the pool"
            );
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM value")
                .fetch_one(&mut *replacement)
                .await
                .expect("read replacement connection"),
            0
        );
        assert!(
            !sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table' AND name = 'veto_schema'
                 )",
            )
            .fetch_one(&mut *replacement)
            .await
            .expect("inspect vetoed schema mutation")
        );
        sqlx::query("INSERT INTO value VALUES (2)")
            .execute(&mut *replacement)
            .await
            .expect("replacement connection remains usable");
        drop(replacement);

        let attempts = std::sync::Mutex::new(IdentityCommitAttemptState::default());
        let first = arm_commit_attempt(&attempts);
        record_commit_veto(
            &attempts,
            IdentityCommitVeto {
                path: path.clone(),
                reason: "first attempt rejection",
            },
        );
        assert!(finish_commit_attempt(&attempts, first).is_some());
        let second = arm_commit_attempt(&attempts);
        assert!(
            finish_commit_attempt(&attempts, second).is_none(),
            "stale veto provenance cannot affect a later COMMIT attempt"
        );
        pool.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn proven_identity_commit_veto_closes_without_second_rollback() {
        exercise_proven_identity_commit_veto(false).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn proven_identity_commit_veto_survives_restore_stall() {
        exercise_proven_identity_commit_veto(true).await;
    }

    #[tokio::test]
    async fn cancellation_after_busy_sleep_stops_the_pending_retry() {
        let external = Arc::new(AtomicBool::new(false));
        let (cancellation, entered, release) = cancellation_with_busy_sleep_gate(
            Some(Arc::clone(&external)),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        let worker_cancellation = Arc::clone(&cancellation);
        let worker = std::thread::spawn(move || {
            // SAFETY: the worker retains the Arc for the complete callback.
            unsafe { begin_busy_handler(Arc::as_ptr(&worker_cancellation).cast_mut().cast(), 0) }
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("busy handler completes its retry sleep");
        external.store(true, Ordering::Release);
        release.store(true, Ordering::Release);
        assert_eq!(
            worker.join().expect("busy handler worker joins"),
            0,
            "cancellation after sleep must prevent SQLite from retrying BEGIN"
        );
    }

    #[test]
    fn deadline_after_busy_sleep_stops_the_pending_retry() {
        let busy_deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
        let (cancellation, _entered, release) =
            cancellation_with_busy_sleep_gate(None, busy_deadline);
        let release_after_expiry = Arc::clone(&release);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(busy_deadline.saturating_duration_since(std::time::Instant::now()));
            release_after_expiry.store(true, Ordering::Release);
        });
        // SAFETY: `cancellation` remains alive for the complete callback.
        let retry = unsafe { begin_busy_handler(Arc::as_ptr(&cancellation).cast_mut().cast(), 0) };
        releaser.join().expect("busy deadline releaser joins");
        assert_eq!(
            retry, 0,
            "deadline expiry after sleep must prevent an extra SQLite busy retry"
        );
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
            Some(std::time::Instant::now() + std::time::Duration::from_millis(500)),
            std::time::Instant::now() + std::time::Duration::from_millis(1_500),
            false,
            std::time::Duration::from_millis(500),
            (None, None),
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
        assert_eq!(
            ACTIVE_MANUAL_TRANSACTIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&key)
                .map(|state| state.generation),
            Some(generation),
            "quarantined active transaction remains registered until close completes"
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
        assert!(
            !ACTIVE_MANUAL_TRANSACTIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&key)
        );
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
            .execute("CREATE TABLE value(id INTEGER CHECK(id > 0))")
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
            work_deadline: Some(std::time::Instant::now() + std::time::Duration::from_secs(1)),
            busy_deadline: Some(std::time::Instant::now() + std::time::Duration::from_secs(1)),
            cleanup_deadline: std::time::Instant::now() + std::time::Duration::from_secs(2),
            stop_cause: AtomicU8::new(BEGIN_STOP_NONE),
            busy_entered: std::sync::Mutex::new(None),
            busy_sleep_gate: std::sync::Mutex::new(None),
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
        assert!(matches!(
            error,
            FileControlError::CommitOutcomeUncertain(
                libsqlite3_sys::SQLITE_INTERRUPT,
                ref message,
            ) if message.contains("cleanup cutoff")
        ));
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
    async fn transferred_begin_owners_release_after_success_and_rejection() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open transferred-owner pool");
        let connection = pool
            .acquire()
            .await
            .expect("acquire transferred-owner connection");
        let owners = BlockingCleanupOwner::acquire_set(
            "transferred-begin-success",
            3,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await
        .expect("reserve complete transferred BEGIN capacity");
        let work_deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let connection = begin_manual_pool_transaction_with_restore_deadlines_and_owners(
            connection,
            work_deadline,
            work_deadline + std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(100),
            None,
            owners,
        )
        .await
        .expect("transferred-owner BEGIN succeeds")
        .rollback()
        .await
        .expect("transferred-owner transaction rolls back");
        drop(connection);

        let rejected_connection = pool
            .acquire()
            .await
            .expect("acquire rejected-transfer connection");
        let rejected_owners = BlockingCleanupOwner::acquire_set(
            "transferred-begin-rejected",
            2,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await
        .expect("reserve incomplete transferred BEGIN capacity");
        begin_manual_pool_transaction_with_restore_deadlines_and_owners(
            rejected_connection,
            work_deadline,
            work_deadline + std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(100),
            None,
            rejected_owners,
        )
        .await
        .expect_err("incomplete transferred owner set is rejected");

        let all = BlockingCleanupOwner::acquire_set(
            "transferred-begin-capacity-proof",
            MAX_CLEANUP_JOBS,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
        .expect("success and rejection release every transferred owner slot");
        for owner in all {
            owner
                .shutdown()
                .expect("release transferred-owner capacity proof");
        }
        pool.close().await;
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
            let is_authorizer_denial = match &error {
                sqlx::Error::Protocol(message) => message.contains("code 23"),
                sqlx::Error::Database(database) => database.code().as_deref() == Some("23"),
                _ => false,
            };
            assert!(
                is_authorizer_denial,
                "{statement} returned {error:?} instead of SQLITE_AUTH"
            );
        }
        transaction
            .execute("INSERT INTO value VALUES (9); COMMIT")
            .await
            .expect_err("mixed allowed and denied statements fail before dispatch");
        assert_eq!(
            transaction
                .fetch_one("SELECT COUNT(*) FROM value")
                .await
                .expect("mixed batch leaves transaction queryable")
                .get::<i64, _>(0),
            0,
            "allowed prefix was not executed before denied tail"
        );
        sqlx::Executor::fetch_optional(
            &mut transaction,
            sqlx::query("INSERT INTO value VALUES (8) RETURNING id; COMMIT"),
        )
        .await
        .expect_err("fetch_optional rejects a denied statement tail before RETURNING");
        assert_eq!(
            transaction
                .fetch_one("SELECT COUNT(*) FROM value")
                .await
                .expect("RETURNING batch leaves transaction queryable")
                .get::<i64, _>(0),
            0
        );
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

    #[tokio::test]
    async fn implicit_constraint_rollback_poison_rejects_later_statements() {
        let directory = tempfile::tempdir().expect("implicit rollback directory");
        let path = directory.path().join("implicit-rollback.sqlite");
        let mut connection = manual_transaction_connection(&path).await;
        sqlx::raw_sql(
            "CREATE TABLE value(id INTEGER PRIMARY KEY);
             INSERT INTO value VALUES (1);",
        )
        .execute(&mut connection)
        .await
        .expect("seed implicit rollback fixture");
        let mut transaction =
            begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                .await
                .expect("begin implicit rollback transaction");
        transaction
            .execute("INSERT INTO value VALUES (2)")
            .await
            .expect("stage row before implicit rollback");
        transaction
            .execute("INSERT OR ROLLBACK INTO value VALUES (1)")
            .await
            .expect_err("constraint conflict rolls back native transaction");
        let rejected = transaction
            .execute("INSERT INTO value VALUES (3)")
            .await
            .expect_err("poisoned transaction rejects later SQL");
        assert!(rejected.to_string().contains("poison"));
        transaction
            .commit()
            .await
            .expect_err("poisoned transaction cannot return a reusable connection");

        let mut connection = manual_transaction_connection(&path).await;
        assert_eq!(
            connection
                .fetch_one("SELECT COUNT(*) FROM value")
                .await
                .expect("read implicit rollback rows")
                .get::<i64, _>(0),
            1
        );
    }

    #[tokio::test]
    async fn implicit_rollback_closes_pool_lease_and_cleans_generation_state() {
        let directory = tempfile::tempdir().expect("pooled implicit rollback directory");
        let path = directory.path().join("pooled-implicit-rollback.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open pooled implicit rollback fixture");
        pool.execute("CREATE TABLE value(id INTEGER PRIMARY KEY)")
            .await
            .expect("create pooled implicit rollback table");
        pool.execute("INSERT INTO value VALUES (1)")
            .await
            .expect("seed pooled implicit rollback table");
        let connection = pool
            .acquire()
            .await
            .expect("acquire pooled implicit rollback lease");
        let mut transaction =
            begin_manual_pool_transaction(connection, std::time::Duration::from_secs(1))
                .await
                .expect("begin pooled implicit rollback transaction");
        let token = transaction
            .token
            .as_ref()
            .expect("pooled implicit rollback token remains owned");
        let key = token.state.key;
        let generation = token.generation;
        transaction
            .execute("INSERT INTO value VALUES (2)")
            .await
            .expect("stage pooled implicit rollback row");
        transaction
            .execute("INSERT OR ROLLBACK INTO value VALUES (1)")
            .await
            .expect_err("pooled constraint conflict rolls back native transaction");
        assert!(
            ACTIVE_MANUAL_TRANSACTIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&key)
                .is_none(),
            "implicit rollback unregisters the exact generation"
        );
        transaction
            .commit()
            .await
            .expect_err("implicit rollback never returns the pool lease reusable");
        assert_eq!(
            DROPPED_AUTHORIZER_GENERATIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&generation),
            Some(&1),
            "physical close destroys the authorizer exactly once"
        );
        let mut replacement =
            tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
                .await
                .expect("terminal close restores pool capacity")
                .expect("pool opens a replacement connection");
        assert!(
            is_autocommit(&mut replacement)
                .await
                .expect("inspect replacement autocommit"),
            "replacement connection is not inside the rolled-back transaction"
        );
        assert_eq!(
            replacement
                .fetch_one("SELECT COUNT(*) FROM value")
                .await
                .expect("read pooled implicit rollback rows")
                .get::<i64, _>(0),
            1
        );
    }

    #[tokio::test]
    async fn injected_fatal_rollback_is_detected_before_success_delivery() {
        let mut connection = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open injected fatal fixture");
        connection
            .execute("CREATE TABLE value(id INTEGER)")
            .await
            .expect("create injected fatal table");
        let mut transaction =
            begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                .await
                .expect("begin injected fatal transaction");
        let generation = transaction
            .token
            .as_ref()
            .expect("fatal token remains owned")
            .generation;
        assert!(
            FORCE_IMPLICIT_ROLLBACK_GENERATIONS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(generation)
        );
        assert!(
            transaction
                .execute("INSERT INTO value VALUES (1)")
                .await
                .expect_err("injected fatal rollback replaces success")
                .to_string()
                .contains("implicitly rolled back")
        );
        assert!(
            transaction
                .execute("INSERT INTO value VALUES (2)")
                .await
                .expect_err("fatal rollback poisons later SQL")
                .to_string()
                .contains("poison")
        );
        drop(transaction);
    }

    #[tokio::test]
    async fn trigger_raise_rollback_poison_is_terminal() {
        let mut connection = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open trigger rollback fixture");
        sqlx::raw_sql(
            "CREATE TABLE value(id INTEGER PRIMARY KEY);
             CREATE TRIGGER rollback_value BEFORE INSERT ON value
             WHEN NEW.id = 2
             BEGIN
               SELECT RAISE(ROLLBACK, 'rollback trigger');
             END;",
        )
        .execute(&mut connection)
        .await
        .expect("create rollback trigger");
        let mut transaction =
            begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                .await
                .expect("begin trigger rollback transaction");
        transaction
            .execute("INSERT INTO value VALUES (1)")
            .await
            .expect("stage trigger fixture row");
        transaction
            .execute("INSERT INTO value VALUES (2)")
            .await
            .expect_err("trigger raises rollback");
        assert!(
            transaction
                .execute("INSERT INTO value VALUES (3)")
                .await
                .expect_err("trigger rollback poisons transaction")
                .to_string()
                .contains("poison")
        );
        drop(transaction);
    }

    #[tokio::test]
    async fn multi_statement_is_rejected_before_execution_but_single_statement_remains_healthy() {
        let mut connection = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open statement preflight fixture");
        connection
            .execute("CREATE TABLE value(id INTEGER CHECK(id > 0))")
            .await
            .expect("create preflight table");
        let mut transaction =
            begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                .await
                .expect("begin preflight transaction");
        let error = sqlx::raw_sql("INSERT INTO value VALUES (1); INSERT INTO value VALUES (2)")
            .execute(&mut transaction)
            .await
            .expect_err("multiple statements are rejected");
        assert!(error.to_string().contains("exactly one"));
        sqlx::raw_sql("ROLLBACK; INSERT INTO value VALUES (9)")
            .execute(&mut transaction)
            .await
            .expect_err("rollback batch is rejected before execution");
        assert_eq!(
            transaction
                .fetch_one("SELECT COUNT(*) FROM value")
                .await
                .expect("rollback batch leaves transaction active")
                .get::<i64, _>(0),
            0
        );
        transaction
            .execute("PRAGMA ignore_check_constraints=ON; COMMIT")
            .await
            .expect_err("prepare-time PRAGMA tail is denied before mutation");
        transaction
            .execute("INSERT INTO value VALUES (-1)")
            .await
            .expect_err("denied PRAGMA did not disable CHECK constraints");
        transaction
            .execute("INSERT INTO value VALUES (3)")
            .await
            .expect("single statement remains usable");
        let mut connection = transaction.commit().await.expect("commit single statement");
        assert_eq!(
            connection
                .fetch_one("SELECT id FROM value")
                .await
                .expect("read preflight row")
                .get::<i64, _>(0),
            3
        );
    }

    #[tokio::test]
    async fn dropped_row_stream_poisons_but_fully_drained_stream_commits() {
        let mut connection = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open guarded stream fixture");
        sqlx::raw_sql(
            "CREATE TABLE value(id INTEGER);
             INSERT INTO value VALUES (1), (2), (3);",
        )
        .execute(&mut connection)
        .await
        .expect("seed guarded stream fixture");
        let mut transaction =
            begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                .await
                .expect("begin dropped stream transaction");
        let mut rows = sqlx::Executor::fetch(&mut transaction, "SELECT id FROM value ORDER BY id");
        let first =
            std::future::poll_fn(|context| futures_core::Stream::poll_next(rows.as_mut(), context))
                .await
                .expect("guarded stream yields one row")
                .expect("first guarded row is valid");
        assert_eq!(first.get::<i64, _>(0), 1);
        drop(rows);
        assert!(
            transaction
                .execute("INSERT INTO value VALUES (4)")
                .await
                .expect_err("early stream drop poisons transaction")
                .to_string()
                .contains("poison")
        );
        drop(transaction);

        let mut connection = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open fully-drained stream fixture");
        sqlx::raw_sql(
            "CREATE TABLE value(id INTEGER);
             INSERT INTO value VALUES (1), (2), (3);",
        )
        .execute(&mut connection)
        .await
        .expect("seed fully-drained stream fixture");
        let mut transaction =
            begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                .await
                .expect("begin fully-drained transaction");
        let rows = sqlx::Executor::fetch_all(&mut transaction, "SELECT id FROM value ORDER BY id")
            .await
            .expect("fully drain guarded rows");
        assert_eq!(rows.len(), 3);
        transaction
            .execute("INSERT INTO value VALUES (4)")
            .await
            .expect("healthy transaction accepts later statement");
        transaction.commit().await.expect("commit drained stream");
    }

    #[tokio::test]
    async fn unpolled_queries_poison_while_prepare_only_preserves_transaction_health() {
        let mut connection = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open prepare guard fixture");
        connection
            .execute("CREATE TABLE value(id INTEGER)")
            .await
            .expect("create prepare guard table");
        let mut transaction =
            begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                .await
                .expect("begin prepare guard transaction");
        let rows = sqlx::Executor::fetch(&mut transaction, "SELECT 1");
        drop(rows);
        assert!(
            transaction
                .execute("INSERT INTO value VALUES (1)")
                .await
                .expect_err("unpolled stream poisons the transaction")
                .to_string()
                .contains("poison")
        );
        transaction
            .commit()
            .await
            .expect_err("unpolled stream cannot return a reusable connection");

        let connection = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open optional guard fixture");
        let mut transaction =
            begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                .await
                .expect("begin optional guard transaction");
        let optional = sqlx::Executor::fetch_optional(&mut transaction, sqlx::query("SELECT 1"));
        drop(optional);
        assert!(
            transaction
                .execute("SELECT 2")
                .await
                .expect_err("unpolled optional query poisons the transaction")
                .to_string()
                .contains("poison")
        );
        transaction
            .commit()
            .await
            .expect_err("unpolled optional query cannot return a reusable connection");

        let mut connection = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open prepare-only fixture");
        connection
            .execute("CREATE TABLE value(id INTEGER CHECK(id > 0))")
            .await
            .expect("create prepare-only table");
        let mut transaction =
            begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                .await
                .expect("begin prepare-only transaction");
        transaction
            .prepare(sqlx::SqlStr::from_static("SELECT ';' /* ; */"))
            .await
            .expect("quoted and commented semicolons are one statement");
        transaction
            .prepare(sqlx::SqlStr::from_static("SELECT 1; SELECT 2"))
            .await
            .expect_err("prepare rejects multiple executable statements");
        transaction
            .prepare(sqlx::SqlStr::from_static(
                "PRAGMA ignore_check_constraints=ON",
            ))
            .await
            .expect_err("prepare rejects PRAGMA side effects");
        transaction
            .execute("INSERT INTO value VALUES (-1)")
            .await
            .expect_err("rejected PRAGMA prepare cannot mutate transaction flags");
        transaction
            .execute("INSERT INTO value VALUES (1)")
            .await
            .expect("prepare-only transaction stays healthy");
        transaction
            .commit()
            .await
            .expect("commit prepare guard transaction");

        let connection = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("open cancelled prepare fixture");
        let mut transaction =
            begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                .await
                .expect("begin cancelled prepare transaction");
        let generation = transaction
            .token
            .as_ref()
            .expect("cancelled prepare token remains owned")
            .generation;
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(AtomicBool::new(false));
        assert!(
            PREPARE_DELIVERY_TEST_GATES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(
                    generation,
                    PrepareDeliveryTestGate {
                        entered: Arc::clone(&entered),
                        release: Arc::clone(&release),
                    },
                )
                .is_none()
        );
        let mut prepare = transaction.prepare(sqlx::SqlStr::from_static("SELECT 1"));
        tokio::select! {
            result = &mut prepare => panic!("prepare completed before cancellation gate: {result:?}"),
            () = entered.notified() => {}
        }
        drop(prepare);
        PREPARE_DELIVERY_TEST_GATES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&generation);
        assert!(
            transaction
                .execute("SELECT 2")
                .await
                .expect_err("cancelled dispatched prepare poisons the transaction")
                .to_string()
                .contains("poison")
        );
        drop(transaction);
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

        let begin = helper
            .split("fn run_locked_begin")
            .nth(1)
            .and_then(|source| source.split("struct BeginWorkerExecutors").next())
            .expect("locate bounded BEGIN worker source");
        assert!(
            !begin.contains("c\"ROLLBACK\""),
            "provisional BEGIN cancellation must transfer directly to terminal close"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_link_count_distinguishes_single_name_and_hardlink() {
        use std::io::Write as _;

        let directory = tempfile::tempdir().expect("Windows link-count directory");
        let path = directory.path().join("source");
        let alias = directory.path().join("alias");
        let mut file = std::fs::File::create(&path).expect("create Windows link-count file");
        file.write_all(b"x").expect("write Windows link-count file");
        assert_eq!(
            windows_file_link_count(&file).expect("single link count"),
            1
        );
        std::fs::hard_link(&path, &alias).expect("create Windows test hardlink");
        assert_eq!(windows_file_link_count(&file).expect("hardlink count"), 2);
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
            state: Arc::clone(&current.state),
        };
        assert!(matches!(
            commit_synchronously(&mut connection, &mut stale, None).await,
            Err(FileControlError::TransactionInvalidated(message))
                if message.contains("generation is stale")
        ));
        let mut wrong_lifetime = ManualTransactionToken {
            database_address: current.database_address,
            connection_nonce: current.connection_nonce.wrapping_add(1),
            generation: current.generation,
            authorizer_address: current.authorizer_address,
            active: true,
            state: Arc::clone(&current.state),
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
            let _ = owner.handoff(move |_, mut terminal_closes| {
                let permit = terminal_closes
                    .take_permit()
                    .expect("stalled close capacity was pre-reserved");
                let _ = outcome_tx.send(permit.close(connection));
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
        let _ = heartbeat_owner.handoff(move |_, _| {
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

    #[tokio::test]
    async fn worker_panics_are_quarantined_without_killing_either_executor() {
        if run_in_isolated_child(
            "deadline_tests::worker_panics_are_quarantined_without_killing_either_executor",
            "GTA_CLAW_WORKER_PANIC_CHILD",
        ) {
            return;
        }
        let _executor_serial = Arc::clone(&EXECUTOR_TEST_SERIAL).lock_owned().await;
        let cleanup_panics = CLEANUP_JOB_PANICS.load(Ordering::Acquire);
        let terminal_panics = TERMINAL_CLOSE_JOB_PANICS.load(Ordering::Acquire);
        let cleanup_drops = Arc::new(AtomicUsize::new(0));
        let terminal_drops = Arc::new(AtomicUsize::new(0));

        for _ in 0..5 {
            let mut owner =
                BlockingCleanupOwner::acquire_without_runtime("panicking-cleanup-worker")
                    .expect("reserve panicking cleanup job");
            owner
                .handoff_payload_internal(DropProbe(Arc::clone(&cleanup_drops)), |_, _, probe| {
                    std::hint::black_box(probe);
                    panic!("injected normal cleanup panic");
                })
                .expect("submit panicking cleanup job");
        }
        let captured_drops = Arc::new(AtomicUsize::new(0));
        let captured_probe = DropProbe(Arc::clone(&captured_drops));
        let mut owner =
            BlockingCleanupOwner::acquire_without_runtime("panicking-captured-cleanup-worker")
                .expect("reserve captured cleanup panic");
        owner
            .handoff_payload_internal((), move |_, _, _| {
                std::hint::black_box(&captured_probe);
                panic!("injected panic with retained callback capture");
            })
            .expect("submit captured cleanup panic");
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while CLEANUP_JOB_PANICS.load(Ordering::Acquire) < cleanup_panics + 6 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("normal cleanup panics are caught");
        assert_eq!(cleanup_drops.load(Ordering::Acquire), 0);
        assert_eq!(
            captured_drops.load(Ordering::Acquire),
            0,
            "FnMut callback captures remain quarantined instead of unwinding"
        );
        assert_eq!(
            LIVE_CLEANUP_WORKERS.load(Ordering::Acquire),
            CLEANUP_THREADS
        );

        let mut heartbeat =
            BlockingCleanupOwner::acquire_without_runtime("post-panic-cleanup-heartbeat")
                .expect("normal cleanup still admits a healthy job");
        let (heartbeat_tx, heartbeat_rx) = tokio::sync::oneshot::channel();
        heartbeat
            .handoff(move |_, _| {
                let _ = heartbeat_tx.send(());
            })
            .expect("submit post-panic cleanup heartbeat");
        tokio::time::timeout(std::time::Duration::from_secs(1), heartbeat_rx)
            .await
            .expect("post-panic cleanup heartbeat completes")
            .expect("post-panic cleanup worker remains live");

        for _ in 0..5 {
            let mut owner =
                BlockingCleanupOwner::acquire_without_runtime("panicking-terminal-worker")
                    .expect("reserve panicking terminal job");
            owner
                .terminal_closes
                .as_mut()
                .expect("terminal capacity remains owned")
                .take_permit()
                .expect("panicking terminal capacity was pre-reserved")
                .submit_job(
                    Box::new(|_| panic!("injected terminal cleanup panic")),
                    Some(Box::new(DropProbe(Arc::clone(&terminal_drops)))),
                )
                .expect("submit panicking terminal job");
            owner.shutdown().expect("release unused owner capacity");
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while TERMINAL_CLOSE_JOB_PANICS.load(Ordering::Acquire) < terminal_panics + 5 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("terminal cleanup panics are caught");
        assert_eq!(terminal_drops.load(Ordering::Acquire), 0);
        assert_eq!(
            LIVE_TERMINAL_CLOSE_WORKERS.load(Ordering::Acquire),
            TERMINAL_CLOSE_THREADS
        );

        let mut owner =
            BlockingCleanupOwner::acquire_without_runtime("post-panic-terminal-heartbeat")
                .expect("terminal cleanup still admits a healthy job");
        let (terminal_tx, terminal_rx) = tokio::sync::oneshot::channel();
        owner
            .terminal_closes
            .as_mut()
            .expect("terminal heartbeat capacity remains owned")
            .take_permit()
            .expect("terminal heartbeat capacity was pre-reserved")
            .submit_job(
                Box::new(move |_| {
                    let _ = terminal_tx.send(());
                    TerminalJobDisposition::Completed
                }),
                None,
            )
            .expect("submit terminal heartbeat");
        owner.shutdown().expect("release heartbeat owner capacity");
        tokio::time::timeout(std::time::Duration::from_secs(1), terminal_rx)
            .await
            .expect("post-panic terminal heartbeat completes")
            .expect("post-panic terminal worker remains live");
    }

    #[tokio::test]
    async fn retention_destructors_are_terminal_bounded_and_panic_isolated() {
        if run_in_isolated_child(
            "deadline_tests::retention_destructors_are_terminal_bounded_and_panic_isolated",
            "GTA_CLAW_RETENTION_DROP_CHILD",
        ) {
            return;
        }
        let _executor_serial = Arc::clone(&EXECUTOR_TEST_SERIAL).lock_owned().await;
        let threads = Arc::new(std::sync::Mutex::new(Vec::new()));
        let cleanup_before = ACTIVE_CLEANUP_JOBS.load(Ordering::Acquire);
        let terminal_before = ACTIVE_TERMINAL_CLOSE_JOBS.load(Ordering::Acquire);

        let captured_entered = Arc::new(AtomicBool::new(false));
        let captured_drops = Arc::new(AtomicUsize::new(0));
        let captured_retention = RetentionDropProbe {
            entered: Arc::clone(&captured_entered),
            drops: Arc::clone(&captured_drops),
            threads: Arc::clone(&threads),
            release: None,
            panic: false,
        };
        let mut owner = BlockingCleanupOwner::acquire_without_runtime("captured-retention-drop")
            .expect("reserve captured retention job");
        owner
            .handoff_payload_internal((), move |_, _, _| {
                std::hint::black_box(&captured_retention);
            })
            .expect("submit captured retention job");
        wait_for_atomic(&captured_entered, "captured retention destructor").await;
        assert_eq!(captured_drops.load(Ordering::Acquire), 1);

        let entered = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(AtomicUsize::new(0));
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let mut owner = BlockingCleanupOwner::acquire_without_runtime("blocking-retention-drop")
            .expect("reserve blocking retention job");
        owner
            .handoff_payload_internal(
                RetentionDropProbe {
                    entered: Arc::clone(&entered),
                    drops: Arc::clone(&drops),
                    threads: Arc::clone(&threads),
                    release: Some(Arc::clone(&release)),
                    panic: false,
                },
                |_, _, _| {},
            )
            .expect("submit blocking retention job");
        wait_for_atomic(&entered, "blocking retention destructor").await;
        let mut heartbeat =
            BlockingCleanupOwner::acquire_without_runtime("retention-normal-heartbeat")
                .expect("normal cleanup remains live during terminal Drop");
        let (heartbeat_tx, heartbeat_rx) = tokio::sync::oneshot::channel();
        heartbeat
            .handoff(move |_, _| {
                let _ = heartbeat_tx.send(());
            })
            .expect("submit normal retention heartbeat");
        tokio::time::timeout(std::time::Duration::from_secs(1), heartbeat_rx)
            .await
            .expect("normal heartbeat is not blocked by retention Drop")
            .expect("normal heartbeat worker remains live");
        {
            let (released, changed) = &*release;
            *released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            changed.notify_all();
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while drops.load(Ordering::Acquire) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking retention destructor completes");

        let panic_entered = Arc::new(AtomicBool::new(false));
        let panic_drops = Arc::new(AtomicUsize::new(0));
        let mut owner = BlockingCleanupOwner::acquire_without_runtime("panicking-retention-drop")
            .expect("reserve panicking retention job");
        owner
            .handoff_payload_internal(
                RetentionDropProbe {
                    entered: Arc::clone(&panic_entered),
                    drops: Arc::clone(&panic_drops),
                    threads: Arc::clone(&threads),
                    release: None,
                    panic: true,
                },
                |_, _, _| {},
            )
            .expect("submit panicking retention job");
        wait_for_atomic(&panic_entered, "panicking retention destructor").await;
        assert_eq!(panic_drops.load(Ordering::Acquire), 1);

        let terminal_entered = Arc::new(AtomicBool::new(false));
        let terminal_drops = Arc::new(AtomicUsize::new(0));
        let mut owner = BlockingCleanupOwner::acquire_without_runtime("terminal-retention-drop")
            .expect("reserve terminal retention job");
        owner
            .take_terminal_permit()
            .expect("terminal retention capacity was pre-reserved")
            .submit_job(
                Box::new(|_| TerminalJobDisposition::Completed),
                Some(Box::new(RetentionDropProbe {
                    entered: Arc::clone(&terminal_entered),
                    drops: Arc::clone(&terminal_drops),
                    threads: Arc::clone(&threads),
                    release: None,
                    panic: true,
                })),
            )
            .expect("submit terminal retention job");
        owner.shutdown().expect("release unused retention owner");
        wait_for_atomic(&terminal_entered, "terminal retention destructor").await;
        assert_eq!(terminal_drops.load(Ordering::Acquire), 1);

        let combined_entered = Arc::new(AtomicBool::new(false));
        let combined_drops = Arc::new(AtomicUsize::new(0));
        let cleanup_panics = CLEANUP_JOB_PANICS.load(Ordering::Acquire);
        let mut owner = BlockingCleanupOwner::acquire_without_runtime("job-and-retention-panic")
            .expect("reserve combined panic job");
        owner
            .handoff_payload_internal(
                RetentionDropProbe {
                    entered: Arc::clone(&combined_entered),
                    drops: Arc::clone(&combined_drops),
                    threads: Arc::clone(&threads),
                    release: None,
                    panic: true,
                },
                |_, _, _| panic!("injected job before retention destruction"),
            )
            .expect("submit combined panic job");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while CLEANUP_JOB_PANICS.load(Ordering::Acquire) == cleanup_panics {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("combined job panic is caught");
        assert!(!combined_entered.load(Ordering::Acquire));
        assert_eq!(combined_drops.load(Ordering::Acquire), 0);
        assert_eq!(
            LIVE_CLEANUP_WORKERS.load(Ordering::Acquire),
            CLEANUP_THREADS
        );
        assert_eq!(
            LIVE_TERMINAL_CLOSE_WORKERS.load(Ordering::Acquire),
            TERMINAL_CLOSE_THREADS
        );
        assert!(
            threads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .all(|name| name.starts_with("claw-sqlite-terminal-close-"))
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while ACTIVE_CLEANUP_JOBS.load(Ordering::Acquire) != cleanup_before + 2
                || ACTIVE_TERMINAL_CLOSE_JOBS.load(Ordering::Acquire) != terminal_before + 5
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("panic quarantine retains each reservation exactly once");
    }

    #[tokio::test]
    async fn waiting_admission_rechecks_executor_health_before_returning_capacity() {
        if run_in_isolated_child(
            "deadline_tests::waiting_admission_rechecks_executor_health_before_returning_capacity",
            "GTA_CLAW_ADMISSION_HEALTH_CHILD",
        ) {
            return;
        }
        let owners = BlockingCleanupOwner::acquire_set(
            "health-generation-capacity-holder",
            MAX_CLEANUP_JOBS,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await
        .expect("reserve all cleanup capacity");
        let waiter = tokio::spawn(async {
            BlockingCleanupOwner::acquire_set(
                "health-generation-waiter",
                1,
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .await
        });
        tokio::task::yield_now().await;
        mark_executor_unhealthy(&CLEANUP_EXECUTOR_HEALTHY);
        drop(owners);
        assert!(
            waiter
                .await
                .expect("health-generation waiter does not panic")
                .is_err(),
            "a waiter must not return capacity after executor health changes"
        );
        assert_eq!(ACTIVE_CLEANUP_JOBS.load(Ordering::Acquire), 0);
        assert_eq!(ACTIVE_TERMINAL_CLOSE_JOBS.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn cold_executor_readiness_obeys_admission_deadline() {
        if run_in_isolated_child(
            "deadline_tests::cold_executor_readiness_obeys_admission_deadline",
            "GTA_CLAW_COLD_EXECUTOR_DEADLINE_CHILD",
        ) {
            return;
        }
        let started = std::time::Instant::now();
        let owners = BlockingCleanupOwner::acquire_set(
            "cold-executor-deadline",
            1,
            std::time::Instant::now() + std::time::Duration::from_millis(10),
        )
        .await;
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "cold executor readiness must not inherit the five-second worker timeout"
        );
        if let Ok(owners) = owners {
            for owner in owners {
                owner.shutdown().expect("release cold executor owner");
            }
        }
    }

    #[test]
    fn full_and_disconnected_sends_retain_exact_envelopes_fail_closed() {
        if run_in_isolated_child(
            "deadline_tests::full_and_disconnected_sends_retain_exact_envelopes_fail_closed",
            "GTA_CLAW_SEND_FAILURE_CHILD",
        ) {
            return;
        }
        let cleanup_before = ACTIVE_CLEANUP_JOBS.load(Ordering::Acquire);
        let terminal_before = ACTIVE_TERMINAL_CLOSE_JOBS.load(Ordering::Acquire);
        let cleanup_drops = Arc::new(AtomicUsize::new(0));
        let callback_drops = Arc::new(AtomicUsize::new(0));
        let terminal_drops = Arc::new(AtomicUsize::new(0));

        for disconnected in [false, true] {
            let (sender, receiver) = std::sync::mpsc::sync_channel(0);
            let receiver = if disconnected {
                drop(receiver);
                None
            } else {
                Some(receiver)
            };
            let healthy = AtomicBool::new(true);
            ACTIVE_CLEANUP_JOBS.fetch_add(1, Ordering::AcqRel);
            ACTIVE_TERMINAL_CLOSE_JOBS.fetch_add(1, Ordering::AcqRel);
            let probe = DropProbe(Arc::clone(&cleanup_drops));
            let envelope = CleanupEnvelope {
                job: DropSlot::new(Box::new(move |_| drop(probe))),
                panic_retention: None,
                callback_retention: Some(Box::new(RetainedDrop::new(DropProbe(Arc::clone(
                    &callback_drops,
                ))))),
                reservation: DropSlot::new(CleanupReservation),
                retirement_reservation: DropSlot::new(TerminalCloseReservation::new()),
            };
            assert!(try_send_cleanup_envelope(&sender, envelope, &healthy).is_err());
            assert!(!healthy.load(Ordering::Acquire));
            assert!(validate_worker_health(&healthy, &AtomicUsize::new(1), 1, "test").is_err());
            drop(receiver);
        }
        assert_eq!(cleanup_drops.load(Ordering::Acquire), 0);
        assert_eq!(callback_drops.load(Ordering::Acquire), 0);
        {
            let mut retained = FAILED_CLEANUP_HANDOFFS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let envelopes: Vec<_> = retained.iter_mut().filter_map(Option::take).collect();
            assert_eq!(envelopes.len(), 2);
            for envelope in envelopes {
                destroy_cleanup_envelope_for_test(envelope);
            }
        }
        assert_eq!(cleanup_drops.load(Ordering::Acquire), 2);
        assert_eq!(callback_drops.load(Ordering::Acquire), 2);
        assert_eq!(ACTIVE_CLEANUP_JOBS.load(Ordering::Acquire), cleanup_before);

        for disconnected in [false, true] {
            let (sender, receiver) = std::sync::mpsc::sync_channel(0);
            let receiver = if disconnected {
                drop(receiver);
                None
            } else {
                Some(receiver)
            };
            let healthy = AtomicBool::new(true);
            ACTIVE_TERMINAL_CLOSE_JOBS.fetch_add(1, Ordering::AcqRel);
            let envelope = TerminalCloseEnvelope {
                job: DropSlot::new(Box::new(|_| TerminalJobDisposition::Completed)),
                panic_retention: Some(RetainedDrop::new(Box::new(DropProbe(Arc::clone(
                    &terminal_drops,
                ))))),
                callback_retention: None,
                cleanup_reservation: DropSlot::empty(),
                reservation: DropSlot::new(TerminalCloseReservation::new()),
            };
            assert!(try_send_terminal_envelope(&sender, envelope, &healthy).is_err());
            assert!(!healthy.load(Ordering::Acquire));
            drop(receiver);
        }
        assert_eq!(terminal_drops.load(Ordering::Acquire), 0);
        {
            let mut retained = FAILED_TERMINAL_HANDOFFS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let envelopes: Vec<_> = retained.iter_mut().filter_map(Option::take).collect();
            assert_eq!(envelopes.len(), 2);
            for envelope in envelopes {
                destroy_terminal_envelope_for_test(envelope);
            }
        }
        assert_eq!(terminal_drops.load(Ordering::Acquire), 2);
        assert_eq!(
            ACTIVE_TERMINAL_CLOSE_JOBS.load(Ordering::Acquire),
            terminal_before
        );

        let queued_drops = Arc::new(AtomicUsize::new(0));
        ACTIVE_CLEANUP_JOBS.fetch_add(1, Ordering::AcqRel);
        ACTIVE_TERMINAL_CLOSE_JOBS.fetch_add(1, Ordering::AcqRel);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let receiver = Arc::new(std::sync::Mutex::new(receiver));
        let executor = CleanupExecutor {
            sender,
            _receiver: Arc::clone(&receiver),
        };
        let probe = DropProbe(Arc::clone(&queued_drops));
        executor
            .sender
            .try_send(CleanupEnvelope {
                job: DropSlot::new(Box::new(move |_| drop(probe))),
                panic_retention: None,
                callback_retention: None,
                reservation: DropSlot::new(CleanupReservation),
                retirement_reservation: DropSlot::new(TerminalCloseReservation::new()),
            })
            .expect("queue ownership test accepts one job");
        drop(receiver);
        assert_eq!(
            queued_drops.load(Ordering::Acquire),
            0,
            "executor supervisor retains queued ownership without workers"
        );
        let queued = executor
            ._receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_recv()
            .expect("supervisor can recover queued ownership");
        destroy_cleanup_envelope_for_test(queued);
        assert_eq!(queued_drops.load(Ordering::Acquire), 1);
        assert_eq!(ACTIVE_CLEANUP_JOBS.load(Ordering::Acquire), cleanup_before);

        let queued_terminal_drops = Arc::new(AtomicUsize::new(0));
        ACTIVE_TERMINAL_CLOSE_JOBS.fetch_add(1, Ordering::AcqRel);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let receiver = Arc::new(std::sync::Mutex::new(receiver));
        let executor = TerminalCloseExecutor {
            sender,
            _receiver: Arc::clone(&receiver),
        };
        executor
            .sender
            .try_send(TerminalCloseEnvelope {
                job: DropSlot::new(Box::new(|_| TerminalJobDisposition::Completed)),
                panic_retention: Some(RetainedDrop::new(Box::new(DropProbe(Arc::clone(
                    &queued_terminal_drops,
                ))))),
                callback_retention: None,
                cleanup_reservation: DropSlot::empty(),
                reservation: DropSlot::new(TerminalCloseReservation::new()),
            })
            .expect("terminal queue ownership test accepts one job");
        drop(receiver);
        assert_eq!(queued_terminal_drops.load(Ordering::Acquire), 0);
        let queued = executor
            ._receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_recv()
            .expect("terminal supervisor can recover queued ownership");
        destroy_terminal_envelope_for_test(queued);
        assert_eq!(queued_terminal_drops.load(Ordering::Acquire), 1);
        assert_eq!(
            ACTIVE_TERMINAL_CLOSE_JOBS.load(Ordering::Acquire),
            terminal_before
        );
    }

    #[test]
    fn terminal_batch_exhaustion_rejects_third_and_fourth_before_payload_transfer() {
        fn submit_probe(batch: &mut TerminalCloseBatch, probe: DropProbe) -> Result<(), DropProbe> {
            let permit = match batch.take_permit() {
                Ok(permit) => permit,
                Err(_) => return Err(probe),
            };
            permit
                .submit_job(
                    Box::new(move |_| {
                        drop(probe);
                        TerminalJobDisposition::Completed
                    }),
                    None,
                )
                .expect("reserved probe submission succeeds");
            Ok(())
        }

        if run_in_isolated_child(
            "deadline_tests::terminal_batch_exhaustion_rejects_third_and_fourth_before_payload_transfer",
            "GTA_CLAW_TERMINAL_EXHAUSTION_CHILD",
        ) {
            return;
        }
        let mut owner = BlockingCleanupOwner::acquire_without_runtime("terminal-exhaustion-owner")
            .expect("reserve terminal exhaustion owner");
        for _ in 0..TERMINAL_CLOSE_SLOTS_PER_OWNER {
            owner
                .terminal_closes
                .as_mut()
                .expect("terminal exhaustion batch remains owned")
                .take_permit()
                .expect("terminal test capacity was pre-reserved")
                .submit_job(Box::new(|_| TerminalJobDisposition::Completed), None)
                .expect("submit reserved terminal job");
        }
        let dropped = Arc::new(AtomicUsize::new(0));
        let third = DropProbe(Arc::clone(&dropped));
        let fourth = DropProbe(Arc::clone(&dropped));
        let batch = owner
            .terminal_closes
            .as_mut()
            .expect("terminal exhaustion batch remains owned");
        let third = submit_probe(batch, third).expect_err("third resource remains caller-owned");
        let fourth = submit_probe(batch, fourth).expect_err("fourth resource remains caller-owned");
        assert_eq!(dropped.load(Ordering::Acquire), 0);
        drop((third, fourth));
        assert_eq!(dropped.load(Ordering::Acquire), 2);
        assert!(TERMINAL_CLOSE_EXECUTOR_HEALTHY.load(Ordering::Acquire));
        owner.shutdown().expect("release exhausted cleanup owner");
    }

    #[tokio::test]
    async fn rollback_panics_from_explicit_commit_failure_and_drop_remain_quarantined() {
        if run_in_isolated_child(
            "deadline_tests::rollback_panics_from_explicit_commit_failure_and_drop_remain_quarantined",
            "GTA_CLAW_ROLLBACK_PANIC_CHILD",
        ) {
            return;
        }
        let _executor_serial = Arc::clone(&EXECUTOR_TEST_SERIAL).lock_owned().await;
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let mut registrations = Vec::new();
        let mut entered = Vec::new();
        let mut keys = Vec::new();
        let mut generations = Vec::new();

        for operation in 0..3 {
            let connection = sqlx::SqliteConnection::connect("sqlite::memory:")
                .await
                .expect("open rollback-panic connection");
            let transaction =
                begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                    .await
                    .expect("begin rollback-panic transaction");
            let token = transaction
                .token
                .as_ref()
                .expect("rollback-panic token remains owned");
            keys.push((token.database_address, token.connection_nonce));
            generations.push(token.generation);
            let (registration, gate_entered) = install_rollback_gate(
                &transaction,
                RollbackTestStage::BeforeLockHandle,
                true,
                operation == 1,
                Arc::clone(&release),
            );
            registrations.push(registration);
            entered.push(gate_entered);
            match operation {
                0 => {
                    let error = transaction
                        .rollback()
                        .await
                        .expect_err("explicit rollback panic is quarantined");
                    assert!(error.to_string().contains("panicked"));
                }
                1 => {
                    let error = transaction
                        .commit()
                        .await
                        .expect_err("commit-failure rollback panic is quarantined");
                    assert!(error.to_string().contains("panicked"));
                }
                _ => drop(transaction),
            }
        }
        for gate in &entered {
            wait_for_atomic(gate, "rollback panic").await;
        }
        for (key, generation) in keys.into_iter().zip(generations) {
            assert_eq!(
                ACTIVE_MANUAL_TRANSACTIONS
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&key)
                    .map(|state| state.generation),
                Some(generation)
            );
            assert!(
                DROPPED_AUTHORIZER_GENERATIONS
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&generation)
                    .is_none()
            );
        }
        assert_eq!(
            LIVE_TERMINAL_CLOSE_WORKERS.load(Ordering::Acquire),
            TERMINAL_CLOSE_THREADS
        );
        drop(registrations);
    }

    #[tokio::test]
    async fn panicking_custom_close_never_returns_the_active_connection_to_pool() {
        if run_in_isolated_child(
            "deadline_tests::panicking_custom_close_never_returns_the_active_connection_to_pool",
            "GTA_CLAW_CLOSE_PANIC_CHILD",
        ) {
            return;
        }
        let _executor_serial = Arc::clone(&EXECUTOR_TEST_SERIAL).lock_owned().await;
        let directory = tempfile::tempdir().expect("panicking-close directory");
        let path = directory.path().join("panicking-close.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open panicking-close pool");
        let connection = pool.acquire().await.expect("acquire panicking-close lease");
        let entered = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut transaction = begin_manual_transaction_inner(
            PanickingPoolConnection {
                connection,
                entered: Arc::clone(&entered),
                dropped: Arc::clone(&dropped),
            },
            std::time::Duration::from_secs(1),
            Some(std::time::Instant::now() + std::time::Duration::from_secs(1)),
            std::time::Instant::now() + std::time::Duration::from_secs(2),
            false,
            std::time::Duration::from_secs(1),
            (None, None),
        )
        .await
        .expect("begin panicking-close transaction");
        let connection = transaction
            .connection
            .take()
            .expect("panicking-close connection remains owned")
            .inner;
        let mut token = transaction
            .token
            .take()
            .expect("panicking-close token remains owned");
        let mut owner = transaction
            .cleanup_owner
            .take()
            .expect("panicking-close cleanup owner remains owned");
        let authorizer = token.take_authorizer_for_terminal_close();
        unregister_manual_transaction(&mut token);
        drop(token);
        let receipt = owner
            .terminal_closes
            .as_mut()
            .expect("panicking-close terminal capacity remains owned")
            .take_permit()
            .expect("panicking-close capacity was pre-reserved")
            .submit_with_authorizer(connection, authorizer);
        owner.shutdown().expect("release unused close capacity");
        assert_eq!(
            receipt.wait(std::time::Instant::now() + std::time::Duration::from_secs(1)),
            TerminalCloseOutcome::Panicked
        );
        assert_eq!(entered.load(Ordering::Acquire), 1);
        assert_eq!(
            dropped.load(Ordering::Acquire),
            0,
            "panicking close future remains owned by bounded quarantine"
        );
        if let Ok(Ok(mut replacement)) =
            tokio::time::timeout(std::time::Duration::from_millis(100), pool.acquire()).await
        {
            assert!(
                is_autocommit(&mut replacement)
                    .await
                    .expect("inspect replacement after panicking close"),
                "a panicking close must never return an active transaction to the pool"
            );
        }
        assert_eq!(dropped.load(Ordering::Acquire), 0);
        assert_eq!(
            LIVE_TERMINAL_CLOSE_WORKERS.load(Ordering::Acquire),
            TERMINAL_CLOSE_THREADS
        );
    }

    #[test]
    fn completed_retained_close_is_idempotent_in_release_paths() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build retained close test runtime");
        let connection = runtime
            .block_on(sqlx::SqliteConnection::connect("sqlite::memory:"))
            .expect("open retained close test connection");
        let mut close = RetainedTerminalClose::new(connection);
        assert_eq!(close.run(&runtime), TerminalCloseOutcome::Closed);
        assert_eq!(close.run(&runtime), TerminalCloseOutcome::Closed);
        assert!(close.finish_success());
        assert_eq!(close.run(&runtime), TerminalCloseOutcome::Closed);
    }

    #[tokio::test]
    async fn prepare_and_conversion_panics_retain_exact_pool_lease() {
        if run_in_isolated_child(
            "deadline_tests::prepare_and_conversion_panics_retain_exact_pool_lease",
            "GTA_CLAW_CLOSE_HOOK_PANIC_CHILD",
        ) {
            return;
        }
        let _executor_serial = Arc::clone(&EXECUTOR_TEST_SERIAL).lock_owned().await;
        for mode in [
            CloseHookPanic::Prepare,
            CloseHookPanic::ConvertBeforeTake,
            CloseHookPanic::ConvertAfterTake,
            CloseHookPanic::PollAfterTake,
        ] {
            let directory = tempfile::tempdir().expect("close-hook panic directory");
            let path = directory.path().join(format!("close-hook-{mode:?}.sqlite"));
            let options = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true);
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(options)
                .await
                .expect("open close-hook panic pool");
            let entered = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let connection = pool.acquire().await.expect("acquire close-hook lease");
            let mut transaction = begin_manual_transaction_inner(
                HookPanickingPoolConnection {
                    connection,
                    mode,
                    entered: Arc::clone(&entered),
                    dropped: Arc::clone(&dropped),
                },
                std::time::Duration::from_secs(1),
                Some(std::time::Instant::now() + std::time::Duration::from_secs(1)),
                std::time::Instant::now() + std::time::Duration::from_secs(2),
                false,
                std::time::Duration::from_secs(1),
                (None, None),
            )
            .await
            .expect("begin close-hook panic transaction");
            let permit = transaction
                .cleanup_owner
                .as_mut()
                .expect("close-hook cleanup owner remains owned")
                .take_terminal_permit()
                .expect("close-hook capacity was pre-reserved");
            let connection = transaction
                .connection
                .take()
                .expect("close-hook connection remains owned")
                .inner;
            let mut token = transaction
                .token
                .take()
                .expect("close-hook token remains owned");
            let generation = token.generation;
            let owner = transaction
                .cleanup_owner
                .take()
                .expect("close-hook cleanup owner remains owned");
            let authorizer = token.take_authorizer_for_terminal_close();
            unregister_manual_transaction(&mut token);
            drop(token);
            let retention_drops = Arc::new(AtomicUsize::new(0));
            let retention: Arc<dyn Send + Sync> = Arc::new(DropProbe(Arc::clone(&retention_drops)));
            let receipt = permit.submit_full(connection, authorizer, Some(retention));
            owner.shutdown().expect("release close-hook owner");
            assert_eq!(
                receipt.wait(std::time::Instant::now() + std::time::Duration::from_secs(1)),
                TerminalCloseOutcome::Panicked
            );
            assert_eq!(
                entered.load(Ordering::Acquire),
                if matches!(mode, CloseHookPanic::Prepare) {
                    1
                } else {
                    2
                }
            );
            assert_eq!(dropped.load(Ordering::Acquire), 0);
            assert_eq!(
                retention_drops.load(Ordering::Acquire),
                0,
                "close-hook panic retains the exact auxiliary payload"
            );
            assert!(
                DROPPED_AUTHORIZER_GENERATIONS
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&generation)
                    .is_none()
            );
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(100), pool.acquire())
                    .await
                    .is_err(),
                "close-hook panic retains the exact pool lease"
            );
        }

        assert_eq!(
            LIVE_TERMINAL_CLOSE_WORKERS.load(Ordering::Acquire),
            TERMINAL_CLOSE_THREADS
        );
    }

    async fn run_rollback_stall_matrix(stage: RollbackTestStage, count: usize) {
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let baseline_terminal = ACTIVE_TERMINAL_CLOSE_JOBS.load(Ordering::Acquire);
        let mut registrations = Vec::new();
        let mut entered = Vec::new();
        let mut tasks = Vec::new();
        for operation in 0..count {
            let connection = sqlx::SqliteConnection::connect("sqlite::memory:")
                .await
                .expect("open rollback-stall connection");
            let transaction =
                begin_manual_transaction(connection, std::time::Duration::from_secs(1), None)
                    .await
                    .expect("begin rollback-stall transaction");
            let (registration, gate_entered) = install_rollback_gate(
                &transaction,
                stage,
                false,
                operation % 3 == 1,
                Arc::clone(&release),
            );
            registrations.push(registration);
            entered.push(gate_entered);
            match operation % 3 {
                0 => tasks.push(tokio::spawn(async move {
                    let _ = transaction.rollback().await;
                })),
                1 => tasks.push(tokio::spawn(async move {
                    let _ = transaction.commit().await;
                })),
                _ => drop(transaction),
            }
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let entered = entered
                    .iter()
                    .filter(|entered| entered.load(Ordering::Acquire))
                    .count();
                if entered == count.min(TERMINAL_CLOSE_THREADS) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("rollback stalls occupy only terminal workers");

        let mut heartbeat =
            BlockingCleanupOwner::acquire_without_runtime("rollback-stall-cleanup-heartbeat")
                .expect("normal cleanup remains admissible");
        let (heartbeat_tx, heartbeat_rx) = tokio::sync::oneshot::channel();
        heartbeat
            .handoff(move |_, _| {
                let _ = heartbeat_tx.send(());
            })
            .expect("submit rollback-stall heartbeat");
        tokio::time::timeout(std::time::Duration::from_secs(1), heartbeat_rx)
            .await
            .expect("normal cleanup heartbeat progresses")
            .expect("normal cleanup worker remains live");
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            tokio::time::sleep(std::time::Duration::from_millis(10)),
        )
        .await
        .expect("Tokio heartbeat remains live");

        assert!(
            BlockingCleanupOwner::acquire_set(
                "rollback-stall-oversized-admission",
                MAX_CLEANUP_JOBS,
                std::time::Instant::now() + std::time::Duration::from_millis(20),
            )
            .await
            .is_err(),
            "whole-operation terminal admission fails closed before oversubscription"
        );
        assert!(ACTIVE_TERMINAL_CLOSE_JOBS.load(Ordering::Acquire) <= MAX_TERMINAL_CLOSE_JOBS);

        {
            let (released, changed) = &*release;
            *released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            changed.notify_all();
        }
        for task in tasks {
            tokio::time::timeout(std::time::Duration::from_secs(3), task)
                .await
                .expect("rollback-stall task reaches terminal outcome")
                .expect("rollback-stall task does not panic");
        }
        drop(registrations);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while ACTIVE_TERMINAL_CLOSE_JOBS.load(Ordering::Acquire) > baseline_terminal {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("released terminal stalls drain their bounded jobs");
    }

    #[tokio::test]
    async fn rollback_lock_handle_stalls_beyond_normal_worker_count() {
        if run_in_isolated_child(
            "deadline_tests::rollback_lock_handle_stalls_beyond_normal_worker_count",
            "GTA_CLAW_ROLLBACK_LOCK_STALL_CHILD",
        ) {
            return;
        }
        let _executor_serial = Arc::clone(&EXECUTOR_TEST_SERIAL).lock_owned().await;
        run_rollback_stall_matrix(RollbackTestStage::BeforeLockHandle, CLEANUP_THREADS + 4).await;
    }

    #[tokio::test]
    async fn rollback_sqlite_exec_stalls_cover_explicit_commit_failure_and_drop() {
        if run_in_isolated_child(
            "deadline_tests::rollback_sqlite_exec_stalls_cover_explicit_commit_failure_and_drop",
            "GTA_CLAW_ROLLBACK_EXEC_STALL_CHILD",
        ) {
            return;
        }
        let _executor_serial = Arc::clone(&EXECUTOR_TEST_SERIAL).lock_owned().await;
        run_rollback_stall_matrix(RollbackTestStage::BeforeSqliteExec, 3).await;
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
        let _ = owner.handoff(move |_, _terminal_closes| {
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
            commit_attempt: std::sync::Mutex::new(IdentityCommitAttemptState::default()),
        };
        assert!(windows_identity_matches(&context));

        for (label, path) in [
            ("database", &database_path),
            ("lock", &context.lock_path),
            ("wal", &wal_path),
            ("shm", &shm_path),
        ] {
            let alias = directory.path().join(format!("{label}-hard-link"));
            std::fs::hard_link(path, &alias).expect("create commit-identity hard link");
            assert!(
                !windows_identity_matches(&context),
                "{label} hard link must veto commit"
            );
            std::fs::remove_file(alias).expect("remove commit-identity hard link");
            assert!(windows_identity_matches(&context));
        }

        let journal_path = directory.path().join("state.sqlite-journal");
        std::fs::write(&journal_path, b"journal").expect("create journal fixture");
        let journal = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(
                windows_sys::Win32::Foundation::GENERIC_READ
                    | windows_sys::Win32::Foundation::GENERIC_WRITE
                    | windows_sys::Win32::Storage::FileSystem::WRITE_DAC
                    | windows_sys::Win32::Storage::FileSystem::WRITE_OWNER,
            )
            .open(&journal_path)
            .expect("open journal security fixture");
        secure_new_windows_file(&journal).expect("protect journal fixture");
        let mut journal_generation = journal_path.as_os_str().to_owned();
        journal_generation.push(":gta-claw-generation");
        std::fs::File::create(std::path::PathBuf::from(journal_generation))
            .and_then(|mut file| file.write_all(&generation_record))
            .expect("attach journal generation");
        drop(journal);
        assert!(windows_identity_matches(&context));
        let journal_alias = directory.path().join("journal-hard-link");
        std::fs::hard_link(&journal_path, &journal_alias).expect("create journal hard link");
        assert!(!windows_identity_matches(&context));
        std::fs::remove_file(journal_alias).expect("remove journal hard link");
        std::fs::remove_file(journal_path).expect("remove journal fixture");
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

    #[test]
    fn held_handle_deletion_never_deletes_substituted_path() {
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let directory = tempfile::tempdir().expect("held deletion directory");
        let original = directory.path().join("original.tmp");
        let detached = directory.path().join("detached.tmp");
        let victim = directory.path().join("victim.txt");
        let mut held = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&original)
            .expect("create held deletion fixture");
        held.write_all(b"original")
            .and_then(|()| held.sync_all())
            .expect("persist held deletion fixture");
        let first_clone = held.try_clone().expect("clone held deletion fixture");
        let second_clone = held.try_clone().expect("clone held deletion fixture again");
        std::fs::write(&victim, b"victim").expect("create held deletion victim");
        std::fs::rename(&original, &detached).expect("detach held original path");
        std::fs::hard_link(&victim, &original).expect("substitute victim at original path");

        let deletion = reopen_file_for_deletion(&held).expect("derive exact held deletion handle");
        delete_file_by_handle(&deletion).expect("mark exact held original for deletion");
        assert_eq!(
            std::fs::read(&original).expect("read substituted victim"),
            b"victim"
        );
        drop(first_clone);
        drop(second_clone);
        drop(held);
        drop(deletion);
        assert!(!detached.exists(), "final close deletes only held original");
        assert_eq!(
            std::fs::read(&original).expect("reread substituted victim"),
            b"victim"
        );

        let read_only = std::fs::File::open(&victim).expect("open victim without DELETE access");
        assert!(matches!(
            delete_file_by_handle(&read_only),
            Err(FileControlError::Handle(_))
        ));
        std::fs::remove_file(&original).expect("remove attacker alias");
    }
}

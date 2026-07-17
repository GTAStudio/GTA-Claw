//! Minimal audited access to SQLite file-control operations.

#[cfg(windows)]
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::ptr::NonNull;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
/// Failure returned by SQLite while inspecting its open main database file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileControlError {
    /// SQLx could not lock its live SQLite handle.
    Handle(String),
    /// SQLite rejected the file-control request.
    SQLite(i32),
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

impl FileControlError {
    /// Returns SQLite's result code.
    #[must_use]
    pub const fn code(&self) -> Option<i32> {
        match self {
            Self::Handle(_) => None,
            Self::SQLite(code) => Some(*code),
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
        }
    }
}

impl Error for FileControlError {}

/// Outcome of one deadline-bound SQLite VACUUM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VacuumDeadlineOutcome {
    /// SQLite completed and the destination is ready for validation.
    Completed,
    /// The deadline elapsed; SQLite was interrupted and joined before return.
    TimedOut,
}

/// Optional execution-boundary gate used by deterministic cross-thread tests.
pub struct VacuumExecutionGate {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<std::sync::atomic::AtomicBool>,
    observed: std::sync::atomic::AtomicBool,
}

impl VacuumExecutionGate {
    /// Creates a gate backed by caller-observable synchronization primitives.
    pub fn new(
        entered: Arc<tokio::sync::Notify>,
        release: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            entered,
            release,
            observed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn wait_at_execution_boundary(
        &self,
        expired: &std::sync::atomic::AtomicBool,
        cancelled: &std::sync::atomic::AtomicBool,
    ) {
        if !self
            .observed
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.entered.notify_one();
            while !self.release.load(std::sync::atomic::Ordering::Acquire)
                && !expired.load(std::sync::atomic::Ordering::Acquire)
                && !cancelled.load(std::sync::atomic::Ordering::Acquire)
            {
                std::thread::yield_now();
            }
        }
    }
}

#[derive(Clone, Copy)]
struct LiveInterruptPointer(NonNull<libsqlite3_sys::sqlite3>);

#[cfg(test)]
struct VacuumTestGate {
    entered: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
    interrupted: std::sync::Arc<tokio::sync::Notify>,
    interrupts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    progress_hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
fn record_vacuum_test_progress(destination: &str) {
    if let Some(progress_hits) = VACUUM_TEST_GATE
        .lock()
        .expect("vacuum test gate lock poisoned")
        .get(destination)
        .map(|gate| std::sync::Arc::clone(&gate.progress_hits))
    {
        progress_hits.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }
}

#[cfg(test)]
static VACUUM_TEST_GATE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, VacuumTestGate>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
async fn wait_at_vacuum_test_gate(destination: &str) {
    let gate = VACUUM_TEST_GATE
        .lock()
        .expect("vacuum test gate lock poisoned")
        .get(destination)
        .map(|gate| {
            (
                std::sync::Arc::clone(&gate.entered),
                std::sync::Arc::clone(&gate.release),
            )
        });
    if let Some((entered, release)) = gate {
        entered.notify_one();
        release.notified().await;
    }
}

#[cfg(test)]
fn record_vacuum_test_interrupt(destination: &str) {
    if let Some((interrupts, interrupted)) = VACUUM_TEST_GATE
        .lock()
        .expect("vacuum test gate lock poisoned")
        .get(destination)
        .map(|gate| {
            (
                std::sync::Arc::clone(&gate.interrupts),
                std::sync::Arc::clone(&gate.interrupted),
            )
        })
    {
        interrupts.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        interrupted.notify_one();
    }
}

// SAFETY: SQLite permits sqlite3_interrupt() from another thread, and this
// pointer never outlives the connection borrowed by vacuum_into_with_deadline.
unsafe impl Send for LiveInterruptPointer {}
// SAFETY: sqlite3_interrupt() is concurrency-safe.
unsafe impl Sync for LiveInterruptPointer {}

impl LiveInterruptPointer {
    fn as_ptr(&self) -> *mut libsqlite3_sys::sqlite3 {
        self.0.as_ptr()
    }
}

async fn vacuum_into_borrowed(
    connection: &mut sqlx::SqliteConnection,
    destination: &str,
    deadline: tokio::time::Instant,
    deadline_expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pointer_slot: Arc<std::sync::Mutex<Option<LiveInterruptPointer>>>,
    execution_gate: Option<Arc<VacuumExecutionGate>>,
) -> Result<VacuumDeadlineOutcome, sqlx::Error> {
    let database = match tokio::time::timeout_at(deadline, connection.lock_handle()).await {
        Ok(handle) => {
            let mut handle = handle?;
            let database = LiveInterruptPointer(handle.as_raw_handle());
            let progress_expired = std::sync::Arc::clone(&deadline_expired);
            let progress_cancelled = Arc::clone(&cancelled);
            let progress_execution_gate = execution_gate;
            #[cfg(test)]
            let progress_destination = destination.to_owned();
            handle.set_progress_handler(1, move || {
                if let Some(gate) = &progress_execution_gate {
                    gate.wait_at_execution_boundary(&progress_expired, &progress_cancelled);
                }
                let expired = progress_expired.load(std::sync::atomic::Ordering::Acquire)
                    || progress_cancelled.load(std::sync::atomic::Ordering::Acquire);
                #[cfg(test)]
                if expired {
                    record_vacuum_test_progress(&progress_destination);
                }
                !expired
            });
            *pointer_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(database);
            database
        }
        Err(_) => {
            deadline_expired.store(true, std::sync::atomic::Ordering::Release);
            return Ok(VacuumDeadlineOutcome::TimedOut);
        }
    };
    let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let query_started = std::sync::Arc::clone(&started);
    let query_deadline_expired = std::sync::Arc::clone(&deadline_expired);
    let operation = {
        let query = async {
            if tokio::time::Instant::now() >= deadline
                || query_deadline_expired.load(std::sync::atomic::Ordering::Acquire)
                || cancelled.load(std::sync::atomic::Ordering::Acquire)
            {
                query_deadline_expired.store(true, std::sync::atomic::Ordering::Release);
                return None;
            }
            query_started.store(true, std::sync::atomic::Ordering::Release);
            #[cfg(test)]
            wait_at_vacuum_test_gate(destination).await;
            Some(
                sqlx::query("VACUUM main INTO ?")
                    .bind(destination)
                    .execute(&mut *connection)
                    .await,
            )
        };
        tokio::pin!(query);
        tokio::select! {
        biased;
        () = tokio::time::sleep_until(deadline) => {
            deadline_expired.store(true, std::sync::atomic::Ordering::Release);
            if started.load(std::sync::atomic::Ordering::Acquire) {
                let mut interrupt = tokio::time::interval(std::time::Duration::from_millis(1));
                interrupt.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    // SAFETY: `connection` remains mutably borrowed by `query`, so its
                    // SQLite handle stays live until the interrupted query is joined.
                    unsafe {
                        libsqlite3_sys::sqlite3_interrupt(database.0.as_ptr());
                    }
                    #[cfg(test)]
                    record_vacuum_test_interrupt(destination);
                    tokio::select! {
                        biased;
                        _ = &mut query => break,
                        _ = interrupt.tick() => {}
                    }
                }
            }
            Ok(VacuumDeadlineOutcome::TimedOut)
        }
        result = &mut query => {
            if tokio::time::Instant::now() >= deadline {
                deadline_expired.store(true, std::sync::atomic::Ordering::Release);
            }
            if deadline_expired.load(std::sync::atomic::Ordering::Acquire)
                || cancelled.load(std::sync::atomic::Ordering::Acquire)
            {
                Ok(VacuumDeadlineOutcome::TimedOut)
            } else {
                match result {
                    Some(Ok(_)) => Ok(VacuumDeadlineOutcome::Completed),
                    Some(Err(error)) => Err(error),
                    None => Ok(VacuumDeadlineOutcome::TimedOut),
                }
            }
        }
        }
    };
    let clear = connection.lock_handle().await.map(|mut handle| {
        handle.set_progress_handler(0, || true);
    });
    *pointer_slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    match (operation, clear) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(outcome), Ok(())) => Ok(outcome),
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

/// Proof that this crate started a manual transaction on one SQLite connection.
pub struct ManualTransactionToken {
    database_address: usize,
    generation: u64,
    active: bool,
}

static NEXT_MANUAL_TRANSACTION_GENERATION: AtomicU64 = AtomicU64::new(1);
static ACTIVE_MANUAL_TRANSACTIONS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<usize, u64>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

fn unregister_manual_transaction(token: &mut ManualTransactionToken) {
    if token.active {
        let mut active = ACTIVE_MANUAL_TRANSACTIONS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active.get(&token.database_address) == Some(&token.generation) {
            active.remove(&token.database_address);
        }
        token.active = false;
    }
}

impl Drop for ManualTransactionToken {
    fn drop(&mut self) {
        unregister_manual_transaction(self);
    }
}

enum BeginWorkerCommand {
    Accept,
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum BeginTestStage {
    BeforeDispatch,
    AfterBegin,
}

#[cfg(test)]
struct BeginTestGate {
    stage: BeginTestStage,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
static BEGIN_TEST_GATE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, BeginTestGate>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
static BEGIN_BUSY_OBSERVERS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Notify>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
fn begin_test_key(path: &str) -> String {
    #[cfg(windows)]
    {
        path.replace('\\', "/").to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        path.to_owned()
    }
}

#[cfg(test)]
fn begin_database_path(database: LiveInterruptPointer) -> Option<String> {
    // SAFETY: callers hold SQLx's locked live SQLite handle.
    unsafe {
        let path = libsqlite3_sys::sqlite3_db_filename(database.as_ptr(), c"main".as_ptr());
        (!path.is_null()).then(|| {
            std::ffi::CStr::from_ptr(path)
                .to_string_lossy()
                .into_owned()
        })
    }
}

#[cfg(test)]
fn wait_at_begin_test_gate(
    stage: BeginTestStage,
    database: LiveInterruptPointer,
    command: &std::sync::mpsc::Receiver<BeginWorkerCommand>,
) -> bool {
    let database_path = begin_database_path(database);
    let gate = BEGIN_TEST_GATE
        .lock()
        .expect("BEGIN test gate lock poisoned")
        .get(&begin_test_key(
            database_path.as_deref().unwrap_or_default(),
        ))
        .filter(|gate| gate.stage == stage)
        .map(|gate| (Arc::clone(&gate.entered), Arc::clone(&gate.release)));
    let Some((entered, release)) = gate else {
        return true;
    };
    entered.notify_one();
    while !release.load(std::sync::atomic::Ordering::Acquire) {
        match command.try_recv() {
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return false,
            Ok(BeginWorkerCommand::Accept) => return false,
        }
    }
    true
}

trait BeginOwnedConnection: Send + 'static {
    fn sqlite(&mut self) -> &mut sqlx::SqliteConnection;

    fn close_owned(self, runtime: &tokio::runtime::Runtime);
}

impl BeginOwnedConnection for sqlx::SqliteConnection {
    fn sqlite(&mut self) -> &mut sqlx::SqliteConnection {
        self
    }

    fn close_owned(self, runtime: &tokio::runtime::Runtime) {
        let _ = runtime.block_on(sqlx::Connection::close(self));
    }
}

impl BeginOwnedConnection for sqlx::pool::PoolConnection<sqlx::Sqlite> {
    fn sqlite(&mut self) -> &mut sqlx::SqliteConnection {
        self
    }

    fn close_owned(self, runtime: &tokio::runtime::Runtime) {
        let _ = runtime.block_on(self.close());
    }
}

type VacuumWorkerOutput<Connection> =
    Option<Result<(Connection, VacuumDeadlineOutcome), sqlx::Error>>;

struct VacuumWorkerContext {
    destination: String,
    deadline: tokio::time::Instant,
    deadline_expired: Arc<std::sync::atomic::AtomicBool>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    pointer: Arc<std::sync::Mutex<Option<LiveInterruptPointer>>>,
    execution_gate: Option<Arc<VacuumExecutionGate>>,
}

struct OwnedVacuumGuard<Connection> {
    worker: Option<std::thread::JoinHandle<VacuumWorkerOutput<Connection>>>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    pointer: Arc<std::sync::Mutex<Option<LiveInterruptPointer>>>,
    armed: bool,
}

impl<Connection> OwnedVacuumGuard<Connection> {
    fn finish(mut self) -> Result<(Connection, VacuumDeadlineOutcome), sqlx::Error> {
        let result = self
            .worker
            .take()
            .ok_or_else(|| sqlx::Error::Protocol("VACUUM worker is missing".to_owned()))?
            .join()
            .map_err(|_| sqlx::Error::Protocol("VACUUM worker panicked".to_owned()))?
            .ok_or_else(|| sqlx::Error::Protocol("VACUUM worker was cancelled".to_owned()))?;
        self.armed = false;
        result
    }
}

impl<Connection> Drop for OwnedVacuumGuard<Connection> {
    fn drop(&mut self) {
        if self.armed {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::Release);
        }
        if let Some(worker) = self.worker.take() {
            while !worker.is_finished() {
                let pointer = self
                    .pointer
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(pointer) = pointer.as_ref() {
                    // SAFETY: the worker clears this slot under the same mutex
                    // before it may close the owned SQLite connection.
                    unsafe {
                        libsqlite3_sys::sqlite3_interrupt(pointer.as_ptr());
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let _ = worker.join();
        }
    }
}

fn run_owned_vacuum_worker<Connection: BeginOwnedConnection>(
    mut connection: Connection,
    runtime: tokio::runtime::Runtime,
    context: VacuumWorkerContext,
) -> VacuumWorkerOutput<Connection> {
    let cancelled = Arc::clone(&context.cancelled);
    let result = runtime.block_on(vacuum_into_borrowed(
        connection.sqlite(),
        &context.destination,
        context.deadline,
        context.deadline_expired,
        Arc::clone(&cancelled),
        context.pointer,
        context.execution_gate,
    ));
    match result {
        Ok(outcome) if !cancelled.load(std::sync::atomic::Ordering::Acquire) => {
            Some(Ok((connection, outcome)))
        }
        Ok(_) => {
            connection.close_owned(&runtime);
            None
        }
        Err(error) => {
            connection.close_owned(&runtime);
            Some(Err(error))
        }
    }
}

async fn vacuum_owned_into_with_deadline<Connection: BeginOwnedConnection>(
    connection: Connection,
    destination: String,
    deadline: tokio::time::Instant,
    deadline_expired: Arc<std::sync::atomic::AtomicBool>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    execution_gate: Option<Arc<VacuumExecutionGate>>,
) -> Result<(Connection, VacuumDeadlineOutcome), sqlx::Error> {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            drop(connection);
            return Err(sqlx::Error::Protocol(format!(
                "build VACUUM worker runtime: {error}"
            )));
        }
    };
    let runtime_slot = Arc::new(std::sync::Mutex::new(Some(runtime)));
    let worker_runtime_slot = Arc::clone(&runtime_slot);
    let pointer = Arc::new(std::sync::Mutex::new(None));
    let worker_pointer = Arc::clone(&pointer);
    let worker_cancelled = Arc::clone(&cancelled);
    let worker = std::thread::Builder::new()
        .name("claw-sqlite-vacuum".to_owned())
        .spawn(move || {
            let runtime = worker_runtime_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let runtime = runtime?;
            run_owned_vacuum_worker(
                connection,
                runtime,
                VacuumWorkerContext {
                    destination,
                    deadline,
                    deadline_expired,
                    cancelled: worker_cancelled,
                    pointer: worker_pointer,
                    execution_gate,
                },
            )
        });
    let worker = match worker {
        Ok(worker) => worker,
        Err(error) => {
            if let Some(runtime) = runtime_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                runtime.shutdown_background();
            }
            return Err(sqlx::Error::Protocol(format!(
                "spawn VACUUM worker: {error}"
            )));
        }
    };
    let guard = OwnedVacuumGuard {
        worker: Some(worker),
        cancelled: Arc::clone(&cancelled),
        pointer,
        armed: true,
    };
    while !guard
        .worker
        .as_ref()
        .is_none_or(std::thread::JoinHandle::is_finished)
    {
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return Err(sqlx::Error::Protocol("VACUUM cancelled".to_owned()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    guard.finish()
}

/// Runs deadline-bound VACUUM while retaining the SQLx pool connection lease.
pub async fn vacuum_pool_into_with_deadline(
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    destination: String,
    deadline: tokio::time::Instant,
    deadline_expired: Arc<std::sync::atomic::AtomicBool>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    execution_gate: Option<Arc<VacuumExecutionGate>>,
) -> Result<
    (
        sqlx::pool::PoolConnection<sqlx::Sqlite>,
        VacuumDeadlineOutcome,
    ),
    sqlx::Error,
> {
    vacuum_owned_into_with_deadline(
        connection,
        destination,
        deadline,
        deadline_expired,
        cancelled,
        execution_gate,
    )
    .await
}

/// Runs deadline-bound VACUUM on an owned standalone SQLite connection.
pub async fn vacuum_into_with_deadline(
    connection: sqlx::SqliteConnection,
    destination: String,
    deadline: tokio::time::Instant,
    deadline_expired: Arc<std::sync::atomic::AtomicBool>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    execution_gate: Option<Arc<VacuumExecutionGate>>,
) -> Result<(sqlx::SqliteConnection, VacuumDeadlineOutcome), sqlx::Error> {
    vacuum_owned_into_with_deadline(
        connection,
        destination,
        deadline,
        deadline_expired,
        cancelled,
        execution_gate,
    )
    .await
}

type BeginWorkerOutput<Connection> = Option<(Connection, usize)>;

struct BeginCancellation {
    local: std::sync::atomic::AtomicBool,
    external: Option<Arc<std::sync::atomic::AtomicBool>>,
    deadline: std::time::Instant,
    #[cfg(test)]
    busy_entered: std::sync::Mutex<Option<Arc<tokio::sync::Notify>>>,
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

struct OwnedBeginGuard<Connection> {
    worker: Option<std::thread::JoinHandle<BeginWorkerOutput<Connection>>>,
    command: Option<std::sync::mpsc::Sender<BeginWorkerCommand>>,
    database: Arc<std::sync::Mutex<Option<LiveInterruptPointer>>>,
    cancellation: Arc<BeginCancellation>,
}

impl<Connection> OwnedBeginGuard<Connection> {
    fn join(&mut self) -> Result<BeginWorkerOutput<Connection>, FileControlError> {
        self.worker
            .take()
            .ok_or_else(|| FileControlError::Handle("BEGIN worker is missing".to_owned()))?
            .join()
            .map_err(|_| FileControlError::Handle("BEGIN worker panicked".to_owned()))
    }

    fn accept(mut self) -> Result<(Connection, usize), FileControlError> {
        self.command
            .take()
            .ok_or_else(|| FileControlError::Handle("BEGIN command channel is missing".to_owned()))?
            .send(BeginWorkerCommand::Accept)
            .map_err(|_| {
                FileControlError::Handle("BEGIN worker stopped before accept".to_owned())
            })?;
        self.join()?.ok_or_else(|| {
            FileControlError::Handle("BEGIN worker discarded the connection".to_owned())
        })
    }

    fn join_failure(mut self) -> Result<(), FileControlError> {
        self.command.take();
        let _ = self.join()?;
        Ok(())
    }
}

impl<Connection> Drop for OwnedBeginGuard<Connection> {
    fn drop(&mut self) {
        self.cancellation
            .local
            .store(true, std::sync::atomic::Ordering::Release);
        self.command.take();
        if let Some(worker) = self.worker.take() {
            while !worker.is_finished() {
                let database = self
                    .database
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(database) = database.as_ref() {
                    // SAFETY: the worker owns the connection until it reaches
                    // terminal cleanup, and sqlite3_interrupt is cross-thread safe.
                    unsafe {
                        libsqlite3_sys::sqlite3_interrupt(database.as_ptr());
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let _ = worker.join();
        }
    }
}

fn close_owned_begin_connection<Connection: BeginOwnedConnection>(
    runtime: &tokio::runtime::Runtime,
    connection: Connection,
) {
    connection.close_owned(runtime);
}

enum LockedBeginOutcome {
    Accepted(usize),
    Failed(FileControlError),
    Cancelled,
}

fn run_locked_begin<Connection: BeginOwnedConnection>(
    runtime: &tokio::runtime::Runtime,
    connection: &mut Connection,
    outcome: &std::sync::mpsc::SyncSender<Result<usize, FileControlError>>,
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
    #[cfg(test)]
    if let Some(path) = begin_database_path(pointer) {
        *cancellation
            .busy_entered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = BEGIN_BUSY_OBSERVERS
            .lock()
            .expect("BEGIN busy observers lock poisoned")
            .get(&begin_test_key(&path))
            .cloned();
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
    *database_slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(pointer);
    #[cfg(test)]
    if !wait_at_begin_test_gate(BeginTestStage::BeforeDispatch, pointer, command) {
        *database_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
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
    // SAFETY: restore SQLite's configured timeout while the locked handle is live.
    unsafe {
        libsqlite3_sys::sqlite3_busy_timeout(pointer.as_ptr(), restore_busy_timeout_ms);
    }
    if !message.is_null() {
        // SAFETY: sqlite3_exec allocated this diagnostic.
        unsafe {
            libsqlite3_sys::sqlite3_free(message.cast());
        }
    }
    if result != libsqlite3_sys::SQLITE_OK {
        *database_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        return LockedBeginOutcome::Failed(FileControlError::SQLite(result));
    }
    #[cfg(test)]
    if !wait_at_begin_test_gate(BeginTestStage::AfterBegin, pointer, command) {
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
        *database_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        return LockedBeginOutcome::Cancelled;
    }
    let address = pointer.as_ptr() as usize;
    let accepted = outcome.send(Ok(address)).is_ok()
        && matches!(command.recv(), Ok(BeginWorkerCommand::Accept));
    if accepted {
        *database_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        return LockedBeginOutcome::Accepted(address);
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
    *database_slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    LockedBeginOutcome::Cancelled
}

fn run_owned_begin_worker<Connection: BeginOwnedConnection>(
    connection_slot: Arc<std::sync::Mutex<Option<Connection>>>,
    outcome: std::sync::mpsc::SyncSender<Result<usize, FileControlError>>,
    command: std::sync::mpsc::Receiver<BeginWorkerCommand>,
    database_slot: Arc<std::sync::Mutex<Option<LiveInterruptPointer>>>,
    restore_busy_timeout: std::time::Duration,
    cancellation: Arc<BeginCancellation>,
    runtime: tokio::runtime::Runtime,
) -> BeginWorkerOutput<Connection> {
    let connection = connection_slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let Some(mut connection) = connection else {
        let _ = outcome.send(Err(FileControlError::Handle(
            "BEGIN worker connection is missing".to_owned(),
        )));
        return None;
    };
    match run_locked_begin(
        &runtime,
        &mut connection,
        &outcome,
        &command,
        &database_slot,
        restore_busy_timeout,
        &cancellation,
    ) {
        LockedBeginOutcome::Accepted(address) => Some((connection, address)),
        LockedBeginOutcome::Failed(error) => {
            let _ = outcome.send(Err(error));
            close_owned_begin_connection(&runtime, connection);
            None
        }
        LockedBeginOutcome::Cancelled => {
            close_owned_begin_connection(&runtime, connection);
            None
        }
    }
}

async fn begin_manual_transaction_inner<Connection: BeginOwnedConnection>(
    connection: Connection,
    busy_timeout: std::time::Duration,
    restore_busy_timeout: std::time::Duration,
    external_cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Result<(Connection, ManualTransactionToken), FileControlError> {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            drop(connection);
            return Err(FileControlError::Handle(format!(
                "build BEGIN worker runtime: {error}"
            )));
        }
    };
    let runtime_slot = Arc::new(std::sync::Mutex::new(Some(runtime)));
    let worker_runtime_slot = Arc::clone(&runtime_slot);
    let connection_slot = Arc::new(std::sync::Mutex::new(Some(connection)));
    let worker_connection = Arc::clone(&connection_slot);
    let database = Arc::new(std::sync::Mutex::new(None));
    let worker_database = Arc::clone(&database);
    let cancellation = Arc::new(BeginCancellation {
        local: std::sync::atomic::AtomicBool::new(false),
        external: external_cancellation,
        deadline: std::time::Instant::now()
            .checked_add(busy_timeout)
            .unwrap_or(std::time::Instant::now()),
        #[cfg(test)]
        busy_entered: std::sync::Mutex::new(None),
    });
    let worker_cancellation = Arc::clone(&cancellation);
    let (outcome_tx, outcome_rx) = std::sync::mpsc::sync_channel(1);
    let (command_tx, command_rx) = std::sync::mpsc::channel();
    let worker = match std::thread::Builder::new()
        .name("claw-sqlite-begin".to_owned())
        .spawn(move || {
            let runtime = worker_runtime_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let runtime = runtime?;
            run_owned_begin_worker(
                worker_connection,
                outcome_tx,
                command_rx,
                worker_database,
                restore_busy_timeout,
                worker_cancellation,
                runtime,
            )
        }) {
        Ok(worker) => worker,
        Err(error) => {
            if let Some(runtime) = runtime_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                runtime.shutdown_background();
            }
            let connection = connection_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(connection) = connection {
                drop(connection);
            }
            return Err(FileControlError::Handle(format!(
                "spawn BEGIN worker: {error}"
            )));
        }
    };
    let guard = OwnedBeginGuard {
        worker: Some(worker),
        command: Some(command_tx),
        database,
        cancellation: Arc::clone(&cancellation),
    };
    let outcome = loop {
        match outcome_rx.try_recv() {
            Ok(outcome) => break outcome,
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                if cancellation.is_cancelled() {
                    return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                guard.join_failure()?;
                return Err(FileControlError::Handle(
                    "BEGIN worker stopped without an outcome".to_owned(),
                ));
            }
        }
    };
    let database_address = match outcome {
        Ok(address) => address,
        Err(error) => {
            guard.join_failure()?;
            return Err(error);
        }
    };
    if cancellation.is_cancelled() {
        return Err(FileControlError::SQLite(libsqlite3_sys::SQLITE_INTERRUPT));
    }
    let (connection, worker_address) = guard.accept()?;
    debug_assert_eq!(worker_address, database_address);
    let generation = NEXT_MANUAL_TRANSACTION_GENERATION.fetch_add(1, Ordering::Relaxed);
    let generation = generation.max(1);
    let mut active = ACTIVE_MANUAL_TRANSACTIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = active.insert(database_address, generation) {
        active.insert(database_address, existing);
        drop(active);
        drop(connection);
        return Err(FileControlError::Handle(
            "SQLite handle already has an active manual transaction".to_owned(),
        ));
    }
    drop(active);
    Ok((
        connection,
        ManualTransactionToken {
            database_address,
            generation,
            active: true,
        },
    ))
}

/// Starts a manual immediate transaction on an owned, non-pool-returnable connection.
pub async fn begin_manual_transaction(
    connection: sqlx::SqliteConnection,
    busy_timeout: std::time::Duration,
    external_cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Result<(sqlx::SqliteConnection, ManualTransactionToken), FileControlError> {
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
) -> Result<
    (
        sqlx::pool::PoolConnection<sqlx::Sqlite>,
        ManualTransactionToken,
    ),
    FileControlError,
> {
    begin_manual_transaction_inner(connection, busy_timeout, busy_timeout, None).await
}

/// Starts a pool transaction with a temporary BEGIN busy bound and restores the configured bound.
pub async fn begin_manual_pool_transaction_with_restore(
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    begin_busy_timeout: std::time::Duration,
    restore_busy_timeout: std::time::Duration,
) -> Result<
    (
        sqlx::pool::PoolConnection<sqlx::Sqlite>,
        ManualTransactionToken,
    ),
    FileControlError,
> {
    begin_manual_transaction_inner(connection, begin_busy_timeout, restore_busy_timeout, None).await
}

/// Commits a transaction created by [`begin_manual_transaction`] synchronously
/// while holding SQLx's connection lock.
pub async fn commit_synchronously(
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
    if ACTIVE_MANUAL_TRANSACTIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&token.database_address)
        != Some(&token.generation)
    {
        return Err(FileControlError::Handle(
            "manual transaction token generation is stale".to_owned(),
        ));
    }

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
    // A failed COMMIT can leave the transaction active (notably SQLITE_BUSY).
    // Invalidate the linear token only once SQLite confirms autocommit.
    if result == libsqlite3_sys::SQLITE_OK
        || unsafe { libsqlite3_sys::sqlite3_get_autocommit(database.as_raw_handle().as_ptr()) } != 0
    {
        unregister_manual_transaction(token);
    }
    if !message.is_null() {
        // SAFETY: sqlite3_exec allocates an error message with sqlite3_malloc.
        unsafe {
            libsqlite3_sys::sqlite3_free(message.cast());
        }
    }
    if result == libsqlite3_sys::SQLITE_OK {
        Ok(())
    } else {
        Err(FileControlError::SQLite(result))
    }
}

/// Rolls back a transaction created by [`begin_manual_transaction`] while
/// holding SQLx's connection lock.
pub async fn rollback_synchronously(
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
    if ACTIVE_MANUAL_TRANSACTIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&token.database_address)
        != Some(&token.generation)
    {
        return Err(FileControlError::Handle(
            "manual transaction token generation is stale".to_owned(),
        ));
    }

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
    if result == libsqlite3_sys::SQLITE_OK
        || unsafe { libsqlite3_sys::sqlite3_get_autocommit(database.as_raw_handle().as_ptr()) } != 0
    {
        unregister_manual_transaction(token);
    }
    if !message.is_null() {
        // SAFETY: sqlite3_exec allocated this diagnostic with sqlite3_malloc.
        unsafe {
            libsqlite3_sys::sqlite3_free(message.cast());
        }
    }
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
        if !unix_path_matches_private_file(
            &sidecar.path,
            &sidecar.file,
            0o600,
            context.expected_uid,
        ) || !matches!(
            sidecar
                .file
                .get_xattr("user.gta-claw.sidecar-generation"),
            Ok(Some(generation)) if generation == context.expected_identity
        ) {
            return false;
        }
    }
    let mut journal = context.database_path.as_os_str().to_owned();
    journal.push("-journal");
    if !unix_sidecar_matches_generation(
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
        matches!(
            file.get_xattr("user.gta-claw.sidecar-generation"),
            Ok(Some(generation)) if generation == expected_identity
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
            if !metadata.file_type().is_file()
                || !unix_file_is_service_private(&file, expected_uid, 0o600).unwrap_or(false)
                || metadata.nlink() != 1
                || !matches!(
                    file.get_xattr("user.gta-claw.sidecar-generation"),
                    Ok(Some(generation)) if generation == expected_identity
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
            const WRITE_AUTHORITY: u32 = 0x0000_0002
                | 0x0000_0004
                | 0x0000_0010
                | 0x0000_0040
                | 0x0000_0100
                | 0x0001_0000
                | 0x0004_0000
                | 0x0008_0000
                | 0x1000_0000
                | 0x4000_0000;
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
                if matches!(header.AceType, 5 | 9 | 11) {
                    return Ok(false);
                }
                if header.AceType != 0 {
                    continue;
                }
                // SAFETY: A type-zero ACE has ACCESS_ALLOWED_ACE layout.
                let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
                if allowed.Mask & WRITE_AUTHORITY == 0 {
                    continue;
                }
                let sid = (&raw const allowed.SidStart).cast_mut().cast();
                // SAFETY: sid points into the live ACE and current_sid is live.
                let trusted = unsafe {
                    EqualSid(sid, current_sid) != 0
                        || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                        || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
                };
                if !trusted {
                    return Ok(false);
                }
            }
            Ok(true)
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
        DACL_SECURITY_INFORMATION, GetTokenInformation, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetKernelObjectSecurity,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
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
        let sddl = format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)");
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
    use sqlx::{Connection as _, Executor as _};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    async fn manual_transaction_connection(path: &std::path::Path) -> sqlx::SqliteConnection {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .busy_timeout(std::time::Duration::from_millis(500));
        sqlx::SqliteConnection::connect_with(&options)
            .await
            .expect("open manual transaction fixture")
    }

    fn install_begin_gate(
        stage: BeginTestStage,
        path: &std::path::Path,
    ) -> (Arc<tokio::sync::Notify>, Arc<std::sync::atomic::AtomicBool>) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        BEGIN_TEST_GATE
            .lock()
            .expect("BEGIN test gate lock poisoned")
            .insert(
                begin_test_key(&path.to_string_lossy()),
                BeginTestGate {
                    stage,
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                },
            );
        (entered, release)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_owned_begin_before_dispatch_closes_without_late_transaction() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("cancel-before-begin.sqlite");
        let connection = manual_transaction_connection(&path).await;
        let (entered, release) = install_begin_gate(BeginTestStage::BeforeDispatch, &path);
        let begin = tokio::spawn(async move {
            begin_manual_transaction(connection, std::time::Duration::from_millis(500), None).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("BEGIN worker reaches pre-dispatch gate");
        begin.abort();
        let cancellation = tokio::time::timeout(std::time::Duration::from_secs(2), begin)
            .await
            .expect("pre-dispatch cancellation joins");
        assert!(matches!(cancellation, Err(error) if error.is_cancelled()));
        release.store(true, Ordering::Release);
        BEGIN_TEST_GATE
            .lock()
            .expect("BEGIN test gate lock poisoned")
            .remove(&begin_test_key(&path.to_string_lossy()));

        let replacement = manual_transaction_connection(&path).await;
        let (mut replacement, mut token) =
            begin_manual_transaction(replacement, std::time::Duration::from_millis(500), None)
                .await
                .expect("pre-dispatch cancellation leaves no transaction");
        rollback_synchronously(&mut replacement, &mut token)
            .await
            .expect("replacement transaction rolls back");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_owned_begin_after_sqlite_begin_rolls_back_before_join() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("cancel-after-begin.sqlite");
        for _ in 0..16 {
            let connection = manual_transaction_connection(&path).await;
            let (entered, release) = install_begin_gate(BeginTestStage::AfterBegin, &path);
            let begin = tokio::spawn(async move {
                begin_manual_transaction(connection, std::time::Duration::from_millis(500), None)
                    .await
            });
            tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
                .await
                .expect("BEGIN worker reaches post-BEGIN gate");
            begin.abort();
            let cancellation = tokio::time::timeout(std::time::Duration::from_secs(2), begin)
                .await
                .expect("post-BEGIN cancellation joins rollback");
            assert!(matches!(cancellation, Err(error) if error.is_cancelled()));
            release.store(true, Ordering::Release);
            BEGIN_TEST_GATE
                .lock()
                .expect("BEGIN test gate lock poisoned")
                .remove(&begin_test_key(&path.to_string_lossy()));

            let replacement = manual_transaction_connection(&path).await;
            let (mut replacement, mut token) =
                begin_manual_transaction(replacement, std::time::Duration::from_millis(500), None)
                    .await
                    .expect("post-BEGIN cancellation rolled back before close");
            rollback_synchronously(&mut replacement, &mut token)
                .await
                .expect("replacement transaction rolls back");
        }
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
                .expect("start locking transaction");
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
            .expect("waiting BEGIN eventually starts");
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
                .expect("start locking transaction");
        locker = returned_locker;
        let waiter = manual_transaction_connection(&path).await;
        let busy_entered = Arc::new(tokio::sync::Notify::new());
        BEGIN_BUSY_OBSERVERS
            .lock()
            .expect("BEGIN busy observers lock poisoned")
            .insert(
                begin_test_key(&path.to_string_lossy()),
                Arc::clone(&busy_entered),
            );
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
        BEGIN_BUSY_OBSERVERS
            .lock()
            .expect("BEGIN busy observers lock poisoned")
            .remove(&begin_test_key(&path.to_string_lossy()));
        rollback_synchronously(&mut locker, &mut locker_token)
            .await
            .expect("release locking transaction");

        let replacement = manual_transaction_connection(&path).await;
        let (mut replacement, mut replacement_token) =
            begin_manual_transaction(replacement, std::time::Duration::from_millis(500), None)
                .await
                .expect("replacement connection starts a transaction");
        rollback_synchronously(&mut replacement, &mut replacement_token)
            .await
            .expect("replacement transaction rolls back");
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
            begin_manual_transaction(writer, std::time::Duration::from_millis(20), None)
                .await
                .expect("begin busy commit writer");
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
            commit_synchronously(&mut writer, &mut token)
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
        let (mut connection, mut token) =
            begin_manual_pool_transaction(connection, std::time::Duration::from_millis(100))
                .await
                .expect("begin pool-owned transaction");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), pool.acquire())
                .await
                .is_err(),
            "manual transaction must retain SQLx's sole pool permit"
        );
        rollback_synchronously(&mut connection, &mut token)
            .await
            .expect("rollback pool-owned transaction");
        drop(connection);
        tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
            .await
            .expect("pool permit returns after transaction terminal state")
            .expect("replacement pool acquisition succeeds");
    }

    #[tokio::test]
    async fn stale_manual_token_cannot_control_later_same_handle_transaction() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("token-generation.sqlite");
        let connection = manual_transaction_connection(&path).await;
        let (mut connection, mut first) =
            begin_manual_transaction(connection, std::time::Duration::from_millis(100), None)
                .await
                .expect("begin first generation");
        rollback_synchronously(&mut connection, &mut first)
            .await
            .expect("finish first generation");
        let (mut connection, mut current) =
            begin_manual_transaction(connection, std::time::Duration::from_millis(100), None)
                .await
                .expect("begin current generation");
        let mut stale = ManualTransactionToken {
            database_address: current.database_address,
            generation: current.generation.wrapping_sub(1),
            active: true,
        };
        assert!(matches!(
            commit_synchronously(&mut connection, &mut stale).await,
            Err(FileControlError::Handle(message)) if message.contains("generation is stale")
        ));
        rollback_synchronously(&mut connection, &mut current)
            .await
            .expect("stale token did not affect current transaction");
    }

    #[tokio::test]
    async fn queued_vacuum_is_repeatedly_interrupted_and_joined_after_expiry() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("source.sqlite");
        let destination = directory.path().join("snapshot.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&source)
            .create_if_missing(true);
        let mut connection = sqlx::SqliteConnection::connect_with(&options)
            .await
            .expect("open tiny SQLite source");
        connection
            .execute("CREATE TABLE tiny(value INTEGER)")
            .await
            .expect("create tiny SQLite schema");

        let expired = Arc::new(AtomicBool::new(false));
        let progress_hits = Arc::new(AtomicUsize::new(0));

        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let interrupted = Arc::new(tokio::sync::Notify::new());
        let interrupts = Arc::new(AtomicUsize::new(0));
        let destination_text = destination
            .to_str()
            .expect("snapshot path is Unicode")
            .to_owned();
        VACUUM_TEST_GATE
            .lock()
            .expect("vacuum test gate lock poisoned")
            .insert(
                destination_text.clone(),
                VacuumTestGate {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                    interrupted: Arc::clone(&interrupted),
                    interrupts: Arc::clone(&interrupts),
                    progress_hits: Arc::clone(&progress_hits),
                },
            );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(30);
        let gate_key = destination_text.clone();
        let task_expired = Arc::clone(&expired);
        let task = tokio::spawn(async move {
            vacuum_into_with_deadline(
                connection,
                destination_text,
                deadline,
                task_expired,
                Arc::new(AtomicBool::new(false)),
                None,
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("VACUUM future reaches queued gate");
        tokio::time::timeout(std::time::Duration::from_secs(1), interrupted.notified())
            .await
            .expect("deadline loop issues its first queued interrupt");
        assert!(
            interrupts.load(Ordering::Acquire) > 0,
            "the first queued interrupt must occur before execution is released"
        );
        assert!(!destination.exists());
        release.notify_one();
        let (mut connection, outcome) =
            tokio::time::timeout(std::time::Duration::from_secs(2), task)
                .await
                .expect("interrupted VACUUM joins")
                .expect("VACUUM task joins")
                .expect("VACUUM returns owned connection");
        VACUUM_TEST_GATE
            .lock()
            .expect("vacuum test gate lock poisoned")
            .remove(&gate_key);
        assert_eq!(outcome, VacuumDeadlineOutcome::TimedOut);
        assert!(
            progress_hits.load(Ordering::Acquire) > 0,
            "expired progress callback must reach the worker after the queued no-op interrupt"
        );
        assert!(!destination.exists());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!destination.exists());
        connection
            .execute("SELECT 1")
            .await
            .expect("VACUUM helper clears its own progress handler");
        connection.close().await.expect("close tiny source");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_queued_vacuum_joins_clears_handler_and_leaves_no_output() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("cancel-source.sqlite");
        let destination = directory.path().join("cancel-snapshot.sqlite");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&source)
            .create_if_missing(true);
        let mut connection = sqlx::SqliteConnection::connect_with(&options)
            .await
            .expect("open cancellation source");
        connection
            .execute("CREATE TABLE tiny(value INTEGER)")
            .await
            .expect("create cancellation schema");
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let interrupted = Arc::new(tokio::sync::Notify::new());
        let interrupts = Arc::new(AtomicUsize::new(0));
        let progress_hits = Arc::new(AtomicUsize::new(0));
        let destination_text = destination.to_string_lossy().into_owned();
        VACUUM_TEST_GATE
            .lock()
            .expect("vacuum test gate lock poisoned")
            .insert(
                destination_text.clone(),
                VacuumTestGate {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                    interrupted,
                    interrupts,
                    progress_hits,
                },
            );
        let cancellation = Arc::new(AtomicBool::new(false));
        let task_cancellation = Arc::clone(&cancellation);
        let gate_key = destination_text.clone();
        let task = tokio::spawn(async move {
            vacuum_into_with_deadline(
                connection,
                destination_text,
                tokio::time::Instant::now() + std::time::Duration::from_secs(5),
                Arc::new(AtomicBool::new(false)),
                task_cancellation,
                None,
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("VACUUM reaches queued cancellation gate");
        task.abort();
        release.notify_one();
        let joined = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("cancelled VACUUM joins its worker");
        assert!(joined.expect_err("VACUUM task is cancelled").is_cancelled());
        VACUUM_TEST_GATE
            .lock()
            .expect("vacuum test gate lock poisoned")
            .remove(&gate_key);
        assert!(cancellation.load(Ordering::Acquire));
        assert!(!destination.exists());
        let mut replacement = sqlx::SqliteConnection::connect_with(&options)
            .await
            .expect("reopen source after cancelled VACUUM");
        replacement
            .execute("SELECT 1")
            .await
            .expect("cancelled VACUUM leaves no poisoned handler");
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

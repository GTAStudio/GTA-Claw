//! Minimal audited access to SQLite file-control operations.

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

struct LiveInterruptPointer(NonNull<libsqlite3_sys::sqlite3>);

#[cfg(test)]
struct VacuumTestGate {
    entered: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
    interrupted: std::sync::Arc<tokio::sync::Notify>,
    interrupts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
static VACUUM_TEST_GATE: std::sync::LazyLock<std::sync::Mutex<Option<VacuumTestGate>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
async fn wait_at_vacuum_test_gate() {
    let gate = VACUUM_TEST_GATE
        .lock()
        .expect("vacuum test gate lock poisoned")
        .as_ref()
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
fn record_vacuum_test_interrupt() {
    if let Some((interrupts, interrupted)) = VACUUM_TEST_GATE
        .lock()
        .expect("vacuum test gate lock poisoned")
        .as_ref()
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

/// Executes `VACUUM main INTO ?` and interrupts/joins SQLite on deadline.
pub async fn vacuum_into_with_deadline(
    connection: &mut sqlx::SqliteConnection,
    destination: &str,
    deadline: tokio::time::Instant,
    deadline_expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<VacuumDeadlineOutcome, sqlx::Error> {
    let database = match tokio::time::timeout_at(deadline, connection.lock_handle()).await {
        Ok(handle) => LiveInterruptPointer(handle?.as_raw_handle()),
        Err(_) => {
            deadline_expired.store(true, std::sync::atomic::Ordering::Release);
            return Ok(VacuumDeadlineOutcome::TimedOut);
        }
    };
    let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let query_started = std::sync::Arc::clone(&started);
    let query_deadline_expired = std::sync::Arc::clone(&deadline_expired);
    let query = async move {
        if tokio::time::Instant::now() >= deadline
            || query_deadline_expired.load(std::sync::atomic::Ordering::Acquire)
        {
            query_deadline_expired.store(true, std::sync::atomic::Ordering::Release);
            return None;
        }
        query_started.store(true, std::sync::atomic::Ordering::Release);
        #[cfg(test)]
        wait_at_vacuum_test_gate().await;
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
                    record_vacuum_test_interrupt();
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
            match result {
                Some(result) => {
                    result?;
                    Ok(VacuumDeadlineOutcome::Completed)
                }
                None => Ok(VacuumDeadlineOutcome::TimedOut),
            }
        }
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
        fn acl_get_fd_np(file_descriptor: c_int, acl_type: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    // SAFETY: The file descriptor is live and ACL_TYPE_EXTENDED is the Darwin
    // extended-ACL selector.
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
}

/// Starts a manual immediate transaction and returns an opaque connection-bound token.
pub async fn begin_manual_transaction(
    connection: &mut sqlx::SqliteConnection,
) -> Result<ManualTransactionToken, FileControlError> {
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let mut message = std::ptr::null_mut();
    // SAFETY: SQL is static/NUL-terminated and the locked handle excludes the
    // SQLx worker until the manual transaction has synchronously started.
    let result = unsafe {
        libsqlite3_sys::sqlite3_exec(
            database.as_raw_handle().as_ptr(),
            c"BEGIN IMMEDIATE".as_ptr(),
            None,
            std::ptr::null_mut(),
            &raw mut message,
        )
    };
    if !message.is_null() {
        // SAFETY: sqlite3_exec allocated this diagnostic with sqlite3_malloc.
        unsafe {
            libsqlite3_sys::sqlite3_free(message.cast());
        }
    }
    if result != libsqlite3_sys::SQLITE_OK {
        return Err(FileControlError::SQLite(result));
    }
    Ok(ManualTransactionToken {
        database_address: database.as_raw_handle().as_ptr() as usize,
    })
}

/// Commits a transaction created by [`begin_manual_transaction`] synchronously
/// while holding SQLx's connection lock.
pub async fn commit_synchronously(
    connection: &mut sqlx::SqliteConnection,
    token: ManualTransactionToken,
) -> Result<(), FileControlError> {
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    if database.as_raw_handle().as_ptr() as usize != token.database_address {
        return Err(FileControlError::Handle(
            "manual transaction token belongs to another SQLite connection".to_owned(),
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

/// Installs a commit hook that rolls back if SQLite's main file was moved.
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
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
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
                    | rustix::fs::OFlags::NOFOLLOW,
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
fn windows_identity_matches(context: &WindowsIdentityCommitContext) -> bool {
    use std::io::Read as _;
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
        let Ok(mut metadata) = std::fs::File::open(std::path::PathBuf::from(generation_path))
        else {
            return false;
        };
        let mut generation = Vec::new();
        if metadata.read_to_end(&mut generation).is_err() || generation != context.expected_identity
        {
            return false;
        }
    }
    true
}

#[cfg(windows)]
fn windows_pinned_sidecars(
    database_path: &std::path::Path,
    expected_identity: &[u8],
) -> Result<Vec<PinnedSidecar>, FileControlError> {
    use std::io::Read as _;
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
            let mut generation = Vec::new();
            std::fs::File::open(std::path::PathBuf::from(generation_path))
                .and_then(|mut metadata| metadata.read_to_end(&mut generation))
                .map_err(|error| FileControlError::Handle(error.to_string()))?;
            if generation != expected_identity {
                return Err(FileControlError::Handle(
                    "Windows SQLite sidecar generation changed".to_owned(),
                ));
            }
            Ok(PinnedSidecar { path, file })
        })
        .collect()
}

unsafe extern "C" fn reject_moved_commit(context: *mut std::ffi::c_void) -> i32 {
    let Some(database) = NonNull::new(context.cast::<libsqlite3_sys::sqlite3>()) else {
        return 1;
    };
    i32::from(database_has_moved(database))
}

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
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
        IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
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

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use sqlx::{Connection as _, Executor as _};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

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
        {
            let expired = Arc::clone(&expired);
            let progress_hits = Arc::clone(&progress_hits);
            let mut handle = connection.lock_handle().await.expect("lock tiny source");
            handle.set_progress_handler(1, move || {
                if expired.load(Ordering::Acquire) {
                    progress_hits.fetch_add(1, Ordering::AcqRel);
                    false
                } else {
                    true
                }
            });
        }

        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let interrupted = Arc::new(tokio::sync::Notify::new());
        let interrupts = Arc::new(AtomicUsize::new(0));
        *VACUUM_TEST_GATE
            .lock()
            .expect("vacuum test gate lock poisoned") = Some(VacuumTestGate {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            interrupted: Arc::clone(&interrupted),
            interrupts: Arc::clone(&interrupts),
        });
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(30);
        let destination_text = destination
            .to_str()
            .expect("snapshot path is Unicode")
            .to_owned();
        let task_expired = Arc::clone(&expired);
        let task = tokio::spawn(async move {
            let outcome = vacuum_into_with_deadline(
                &mut connection,
                &destination_text,
                deadline,
                task_expired,
            )
            .await;
            (connection, outcome)
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
                .expect("VACUUM task joins");
        VACUUM_TEST_GATE
            .lock()
            .expect("vacuum test gate lock poisoned")
            .take();
        assert_eq!(
            outcome.expect("VACUUM returns typed outcome"),
            VacuumDeadlineOutcome::TimedOut
        );
        assert!(
            progress_hits.load(Ordering::Acquire) > 0,
            "expired progress callback must reach the worker after the queued no-op interrupt"
        );
        assert!(!destination.exists());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!destination.exists());
        let mut handle = connection.lock_handle().await.expect("relock tiny source");
        handle.set_progress_handler(0, || true);
        drop(handle);
        connection.close().await.expect("close tiny source");
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
        std::fs::write(&database_path, b"database").expect("create database fixture");
        std::fs::write(&lock_path, &generation).expect("create lock fixture");
        std::fs::write(&wal_path, b"wal").expect("create WAL fixture");
        std::fs::write(&shm_path, b"shm").expect("create SHM fixture");
        for sidecar in [&wal_path, &shm_path] {
            let mut generation_path = sidecar.as_os_str().to_owned();
            generation_path.push(":gta-claw-generation");
            std::fs::File::create(std::path::PathBuf::from(generation_path))
                .and_then(|mut file| file.write_all(&generation))
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

use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::atomicfs::{self, ObjectIdentity};
use crate::error::ConfigError;
use crate::{ConfigSnapshot, to_json5};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Successful atomic-write result, including non-fatal post-publication warnings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WriteOutcome {
    /// Cleanup or durability limitations observed after the new file was published.
    pub warnings: Vec<WriteWarning>,
}

/// A non-fatal condition discovered after atomic publication succeeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteWarning {
    /// Windows preserved the old destination as a backup but could not remove it.
    BackupCleanupFailed {
        /// Backup containing the old destination bytes.
        path: PathBuf,
        /// Operating-system cleanup diagnostic.
        message: String,
    },
    /// Unix published the rename but could not synchronize the directory entry.
    DirectorySyncFailed {
        /// Directory whose metadata could not be synchronized.
        path: PathBuf,
        /// Operating-system synchronization diagnostic.
        message: String,
    },
}

/// Loads and validates a UTF-8 JSON5 configuration file.
///
/// # Errors
///
/// Returns [`ConfigError::Io`] carrying `path` when the file cannot be opened
/// or read, or when its bytes are not UTF-8. Otherwise returns whatever
/// [`crate::parse_json5`] rejects: [`ConfigError::Syntax`] for malformed JSON5,
/// [`ConfigError::Decode`] for a mistyped or unknown field,
/// [`ConfigError::UnsupportedVersion`] for a foreign `schema_version`, and
/// [`ConfigError::Validation`] for a violated domain invariant.
pub fn load_file(path: impl AsRef<Path>) -> Result<ConfigSnapshot, ConfigError> {
    let path = path.as_ref();
    let source = fs::read_to_string(path).map_err(|error| ConfigError::io(path, error))?;
    crate::parse_json5(&source, &path.display().to_string())
}

/// Atomically writes a validated snapshot in the destination directory.
///
/// The caller must place configuration in a trusted directory that untrusted
/// processes cannot rename while this operation runs. Every existing path
/// component and the destination are rejected when they are a Unix symlink or
/// Windows reparse point, but path-based platform replacement APIs cannot close
/// every ancestor race without a permanently held directory handle.
///
/// Temporary contents are flushed before publication. Unix synchronizes the
/// containing directory after rename. Windows uses `ReplaceFileW` for an
/// existing destination, preserving its ACLs, attributes, creation time, named
/// streams, encryption, and compression. Windows has no documented equivalent
/// for synchronizing directory metadata, so durability of the final directory
/// entry across sudden power loss cannot be guaranteed.
///
/// # Errors
///
/// Returns [`ConfigError::Serialize`] when `snapshot` cannot be encoded as
/// JSON5. Otherwise returns [`ConfigError::Io`] carrying `path` when any step of
/// the atomic write fails: `path` has no file name, an ancestor directory or the
/// destination itself is a symlink or Windows reparse point, the destination
/// exists but is not a regular file, the parent cannot be canonicalized, no
/// unique temporary name could be allocated in 128 attempts, or writing,
/// flushing, `fsync`-ing, or publishing the temporary file failed. When
/// publication fails the destination keeps its previous bytes; if removing the
/// temporary file also fails, its path is appended to the returned message.
///
/// A successful call can still report non-fatal [`WriteWarning`] values in
/// [`WriteOutcome::warnings`]; those are not errors and the new bytes are
/// already published.
pub fn write_file(
    path: impl AsRef<Path>,
    snapshot: &ConfigSnapshot,
) -> Result<WriteOutcome, ConfigError> {
    let path = path.as_ref();
    let contents = to_json5(snapshot)?;
    atomic_write_bytes(path, contents.as_bytes(), || Ok(()))
        .map_err(|error| ConfigError::io(path, error))
}

/// Atomically writes non-secret auxiliary bytes with the same path hardening.
///
/// This is intended for typed subsystem state colocated with configuration.
/// Callers remain responsible for serializing only data that is safe to persist.
///
/// # Errors
///
/// Returns [`ConfigError::Io`] carrying `path` under exactly the same conditions
/// as [`write_file`]: a rejected path shape, a symlink or reparse point anywhere
/// in the ancestor chain or at the destination, a destination that exists but is
/// not a regular file, exhausted temporary-name attempts, or a failed write,
/// flush, `fsync`, or publication. The destination is left untouched whenever
/// this returns an error.
pub fn write_bytes_atomically(
    path: impl AsRef<Path>,
    contents: &[u8],
) -> Result<WriteOutcome, ConfigError> {
    let path = path.as_ref();
    atomic_write_bytes(path, contents, || Ok(())).map_err(|error| ConfigError::io(path, error))
}

/// What the destination must still hold when publication actually happens.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum PublicationGuard<'a> {
    /// Publish whatever is there; no comparison is made.
    #[default]
    Unchecked,
    /// The destination must still hold bytes with exactly this SHA-256 digest.
    Digest(&'a str),
}

/// Outcome of a guarded publication.
#[derive(Debug)]
pub(crate) enum Publication {
    /// The new bytes were published.
    Published(WriteOutcome),
    /// The destination held something else; it was left exactly as found.
    Conflict {
        /// The exact bytes that occupied the destination instead.
        actual: Vec<u8>,
        /// Durable copy of those bytes, written before the destination was
        /// restored, so the only copy never depended on a step that can fail.
        preserved: Option<PathBuf>,
    },
}

/// Flushes a directory's entries to stable storage.
///
/// Rename-based publication is only durable once the directory entry itself has
/// reached stable storage, so subsystems that publish files next to
/// configuration need the same primitive the atomic writer uses.
///
/// # Errors
///
/// Returns [`ConfigError::Io`] carrying `path` when the directory cannot be
/// opened or flushed, including when the platform provides no way to flush a
/// directory at all. The failure is reported rather than swallowed: a caller
/// that treated it as success would claim a durability guarantee the filesystem
/// never gave.
pub fn sync_directory(path: impl AsRef<Path>) -> Result<(), ConfigError> {
    let path = path.as_ref();
    atomicfs::sync_directory(path).map_err(|error| ConfigError::io(path, error))
}

pub(crate) fn atomic_write_bytes(
    path: &Path,
    contents: &[u8],
    precommit: impl FnOnce() -> io::Result<()>,
) -> io::Result<WriteOutcome> {
    with_destination_lock(path, move |destination| {
        atomic_write_bytes_locked(destination, contents, precommit)
    })
}

pub(crate) fn atomic_write_bytes_locked(
    destination: &Path,
    contents: &[u8],
    precommit: impl FnOnce() -> io::Result<()>,
) -> io::Result<WriteOutcome> {
    match publish_bytes_locked(
        destination,
        contents,
        PublicationGuard::Unchecked,
        precommit,
    )? {
        Publication::Published(outcome) => Ok(outcome),
        Publication::Conflict { .. } => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "unchecked publication cannot report a conflict",
        )),
    }
}

/// Publishes `contents` over `destination` under a compare-and-swap.
///
/// The comparison is bound to the publication rather than performed before it.
/// The advisory lock only orders writers that agreed to take it: an editor or an
/// installer that simply writes the file does not, and a digest read before an
/// unconditional rename cannot see a write that lands in between. Exchanging the
/// temporary file with the destination moves the previous occupant to the
/// temporary path in the same atomic step, so the object that is inspected is
/// exactly the object that was replaced. When it is not what the caller
/// expected, the exchange is undone and the destination is left byte for byte as
/// the other writer left it.
pub(crate) fn publish_bytes_locked(
    destination: &Path,
    contents: &[u8],
    guard: PublicationGuard<'_>,
    precommit: impl FnOnce() -> io::Result<()>,
) -> io::Result<Publication> {
    let existing = fs::symlink_metadata(destination).ok();
    let (mut temporary, mut file) = TemporaryArtifact::create(destination, "tmp")?;

    let operation = (|| {
        set_permissions(existing.as_ref(), &file)?;
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(contents)?;
        file.flush()?;
        file.sync_all()?;
        precommit()?;
        temporary.verify_identity()?;
        #[cfg(test)]
        test_failpoint::run_external_writer_barrier(destination);
        drop(file);
        publish_temporary(&mut temporary, destination, guard)
    })();

    match operation {
        Ok(publication) => Ok(publication),
        Err(operation_error) => match temporary.cleanup() {
            Ok(()) => Err(operation_error),
            Err(cleanup_error) => Err(io::Error::new(
                operation_error.kind(),
                format!(
                    "{operation_error}; additionally failed to remove temporary file {}: \
                     {cleanup_error}",
                    temporary.path().display()
                ),
            )),
        },
    }
}

/// Puts a displaced object back at `destination`, or refuses to lose it.
///
/// A refused exchange leaves the temporary holding the only copy of what the
/// destination used to contain. The temporary stays disarmed and the error names
/// it — and any durable copy — rather than reporting something success-shaped
/// while cleanup deletes the evidence.
fn undo_displacement(
    temporary: &TemporaryArtifact,
    destination: &Path,
    preserved: Option<&PathBuf>,
) -> io::Result<()> {
    let restored = test_failpoint_restore_failure(destination).map_or_else(
        || atomicfs::exchange_paths(temporary.path(), destination),
        Err,
    );
    let Err(error) = restored else {
        return Ok(());
    };
    let copies = preserved.map_or_else(
        || " and was not copied anywhere else".to_owned(),
        |path| format!(" and copied to {}", path.display()),
    );
    Err(io::Error::new(
        error.kind(),
        format!(
            "could not restore the concurrently changed destination {}: {error}; the destination \
             still holds the newly published bytes and the displaced object is retained at {}{}",
            destination.display(),
            temporary.path().display(),
            copies
        ),
    ))
}

#[cfg(test)]
fn test_failpoint_restore_failure(destination: &Path) -> Option<io::Error> {
    test_failpoint::injected_restore_failure(destination)
}

#[cfg(not(test))]
const fn test_failpoint_restore_failure(_destination: &Path) -> Option<io::Error> {
    None
}

/// Writes an exact durable copy of displaced bytes beside the destination.
fn write_durable_conflict_copy(destination: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = destination.with_file_name(format!(
            "{}.gta-claw.conflict.{}.{sequence}.bak",
            destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("config"),
            std::process::id()
        ));
        match atomicfs::create_new_no_follow(&path) {
            Ok(mut file) => {
                file.write_all(bytes)?;
                file.flush()?;
                file.sync_all()?;
                drop(file);
                sync_parent(&path)?;
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique conflict backup",
    ))
}

fn publish_temporary(
    temporary: &mut TemporaryArtifact,
    destination: &Path,
    guard: PublicationGuard<'_>,
) -> io::Result<Publication> {
    let guarded = matches!(guard, PublicationGuard::Digest(_));
    let mut warnings = Vec::new();
    // The destination can be created or removed by a non-cooperating writer
    // between the shape check and the operation chosen for it. Each attempt is
    // decided by the operation's own atomic outcome, and the loop only re-runs
    // when the shape genuinely changed underneath it.
    let mut attempts = 0;
    loop {
        attempts += 1;
        if attempts > 16 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "destination kept changing shape during publication",
            ));
        }
        let occupied = match fs::symlink_metadata(destination) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        if !occupied {
            // A guarded publication expected specific prior bytes; a destination
            // that is gone is as much a concurrent change as one that was
            // rewritten, and the caller decides what to do about it.
            if guarded {
                return Ok(Publication::Conflict {
                    actual: Vec::new(),
                    preserved: None,
                });
            }
            match atomicfs::rename_no_replace(temporary.path(), destination) {
                Ok(()) => {
                    temporary.disarm();
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        match atomicfs::exchange_paths(temporary.path(), destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
        // From here until the temporary is proven expendable it holds the only
        // copy of whatever was displaced from the destination, so nothing may
        // remove it — not the error path, not `Drop`.
        temporary.disarm();
        let displaced = match fs::read(temporary.path()) {
            Ok(bytes) => bytes,
            Err(error) => {
                undo_displacement(temporary, destination, None).map_err(|restore| {
                    io::Error::new(restore.kind(), format!("{error}; {restore}"))
                })?;
                temporary.rearm();
                return Err(error);
            }
        };
        if let PublicationGuard::Digest(expected) = guard
            && crate::versioning::digest_hex(&displaced) != expected
        {
            // Durability first: the displaced bytes are already in hand, so an
            // exact copy is written before the exchange that could fail is even
            // attempted.
            let preserved = write_durable_conflict_copy(destination, &displaced);
            undo_displacement(temporary, destination, preserved.as_ref().ok())?;
            temporary.rearm();
            return Ok(Publication::Conflict {
                actual: displaced,
                preserved: Some(preserved?),
            });
        }
        temporary.rearm();
        // The temporary now holds the old destination bytes; removing it is the
        // last step, and a failure only leaves a stale copy of the *previous*
        // contents, which is reported rather than hidden.
        if let Err(error) = temporary.cleanup() {
            let path = temporary.path().to_owned();
            temporary.disarm();
            warnings.push(WriteWarning::BackupCleanupFailed {
                path,
                message: error.to_string(),
            });
        }
        break;
    }
    #[cfg(test)]
    if let Some(warning) = test_failpoint::directory_sync_warning(destination) {
        warnings.push(warning);
        return Ok(Publication::Published(WriteOutcome { warnings }));
    }
    if let Err(error) = sync_parent(destination) {
        warnings.push(WriteWarning::DirectorySyncFailed {
            path: destination
                .parent()
                .expect("prepared destination always has a parent")
                .to_owned(),
            message: error.to_string(),
        });
    }
    Ok(Publication::Published(WriteOutcome { warnings }))
}

pub(crate) fn with_destination_lock<T>(
    path: &Path,
    action: impl FnOnce(&Path) -> io::Result<T>,
) -> io::Result<T> {
    let destination = prepare_destination(path)?;
    let _lock = DestinationLock::acquire(&destination)?;
    action(&destination)
}

fn prepare_destination(path: &Path) -> io::Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| unsafe_path("destination has no file name"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let absolute_parent = if parent.is_absolute() {
        parent.to_owned()
    } else {
        std::env::current_dir()?.join(parent)
    };
    reject_unsafe_ancestors(&absolute_parent)?;
    let canonical_parent = fs::canonicalize(&absolute_parent)?;
    reject_unsafe_ancestors(&canonical_parent)?;

    let metadata = fs::symlink_metadata(&canonical_parent)?;
    if !metadata.is_dir() {
        return Err(unsafe_path("destination parent is not a directory"));
    }

    let destination = canonical_parent.join(file_name);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if is_link_or_reparse(&metadata) {
                return Err(unsafe_path(
                    "destination must not be a symlink or reparse point",
                ));
            }
            if !metadata.is_file() {
                return Err(unsafe_path("destination must be a regular file"));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(destination)
}

fn reject_unsafe_ancestors(path: &Path) -> io::Result<()> {
    let mut ancestors: Vec<_> = path.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor)?;
        if is_link_or_reparse(&metadata) {
            return Err(unsafe_path(
                "destination parent chain must not contain symlinks or reparse points",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(any(unix, windows)))]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn unsafe_path(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

struct DestinationLock {
    file: File,
}

impl DestinationLock {
    fn path(destination: &Path) -> PathBuf {
        destination.with_file_name(format!(
            ".{}.gta-claw.lock",
            destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("config")
        ))
    }

    fn acquire(destination: &Path) -> io::Result<Self> {
        let lock_path = Self::path(destination);
        reject_lock_link_or_reparse(&lock_path)?;
        let file = atomicfs::open_lock_no_follow(&lock_path)?;
        file.lock()?;
        // The OS file lock is advisory; syncing the lock file itself adds latency
        // with no correctness benefit.  The durable backup written during the
        // migration is what must be fsync'd, not the lock sentinel.
        reject_lock_link_or_reparse(&lock_path)?;
        if !lock_file_matches_path(&file, &lock_path)? {
            return Err(unsafe_path(
                "destination lock identity changed during acquisition",
            ));
        }
        Ok(Self { file })
    }
}

/// Confirms the sentinel path still names the object the lock is held on.
///
/// The comparison is by volume and file identifier on every supported platform.
/// Trusting the path alone would let another process unlink the sentinel between
/// the open and the lock and leave a different file — or a link — behind, and
/// two writers would then each hold a lock on a different object.
fn lock_file_matches_path(file: &File, lock_path: &Path) -> io::Result<bool> {
    let handle = atomicfs::identity_of_handle(file)?;
    let on_disk = atomicfs::identity_of_path(lock_path)?;
    Ok(handle == on_disk)
}

impl Drop for DestinationLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
pub(crate) fn destination_lock_path_for_tests(path: &Path) -> PathBuf {
    prepare_destination(path).map_or_else(
        |_| DestinationLock::path(path),
        |destination| DestinationLock::path(&destination),
    )
}

#[cfg(test)]
pub(crate) fn inject_directory_sync_warning_for_tests() -> test_failpoint::Guard {
    test_failpoint::inject_directory_sync_warning()
}

#[cfg(test)]
pub(crate) fn inject_external_writer_for_tests(
    destination: &Path,
    action: impl Fn(&Path) + Send + Sync + 'static,
) -> test_failpoint::ExternalWriterGuard {
    test_failpoint::inject_external_writer(destination, action)
}

#[cfg(test)]
pub(crate) fn fail_restore_for_tests(destination: &Path) -> test_failpoint::RestoreFailureGuard {
    test_failpoint::fail_restore(destination)
}

#[cfg(test)]
mod test_failpoint {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::WriteWarning;

    static INJECT_DIRECTORY_SYNC_WARNING: Mutex<Option<std::thread::ThreadId>> = Mutex::new(None);

    type ExternalWriter = Box<dyn Fn(&Path) + Send + Sync>;

    // Keyed by destination so tests running in parallel arm independent
    // barriers instead of consuming each other's.
    static EXTERNAL_WRITERS: Mutex<Vec<(PathBuf, ExternalWriter)>> = Mutex::new(Vec::new());

    // Destinations whose next restoring exchange must be refused, so the only
    // case in which the temporary holds the sole copy of the displaced object is
    // reachable without an unmountable filesystem.
    static RESTORE_FAILURES: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    pub(crate) struct Guard;

    /// Held for the duration of a test; clears its own barrier on drop.
    pub(crate) struct ExternalWriterGuard {
        destination: PathBuf,
    }

    /// Held for the duration of a test; clears its own injected failure on drop.
    pub(crate) struct RestoreFailureGuard {
        destination: PathBuf,
    }

    /// Makes the next attempt to undo a displacement of `destination` fail.
    pub(crate) fn fail_restore(destination: &Path) -> RestoreFailureGuard {
        RESTORE_FAILURES
            .lock()
            .expect("lock restore failpoint")
            .push(destination.to_path_buf());
        RestoreFailureGuard {
            destination: destination.to_path_buf(),
        }
    }

    pub(super) fn injected_restore_failure(destination: &Path) -> Option<std::io::Error> {
        let armed = {
            let mut failures = RESTORE_FAILURES.lock().expect("lock restore failpoint");
            failures
                .iter()
                .position(|path| path == destination)
                .map(|index| failures.swap_remove(index))
        };
        armed.map(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected restoring exchange failure",
            )
        })
    }

    impl Drop for RestoreFailureGuard {
        fn drop(&mut self) {
            let mut failures = RESTORE_FAILURES.lock().expect("lock restore failpoint");
            if let Some(index) = failures.iter().position(|path| *path == self.destination) {
                failures.swap_remove(index);
            }
        }
    }

    /// Arms a one-shot write that lands after every pre-publication check and
    /// immediately before the atomic exchange.
    pub(crate) fn inject_external_writer(
        destination: &Path,
        action: impl Fn(&Path) + Send + Sync + 'static,
    ) -> ExternalWriterGuard {
        EXTERNAL_WRITERS
            .lock()
            .expect("lock external writer barrier")
            .push((destination.to_path_buf(), Box::new(action)));
        ExternalWriterGuard {
            destination: destination.to_path_buf(),
        }
    }

    pub(super) fn run_external_writer_barrier(destination: &Path) {
        let armed = {
            let mut writers = EXTERNAL_WRITERS
                .lock()
                .expect("lock external writer barrier");
            writers
                .iter()
                .position(|(path, _)| path == destination)
                .map(|index| writers.swap_remove(index))
        };
        if let Some((_, action)) = armed {
            action(destination);
        }
    }

    impl Drop for ExternalWriterGuard {
        fn drop(&mut self) {
            let mut writers = EXTERNAL_WRITERS
                .lock()
                .expect("lock external writer barrier");
            if let Some(index) = writers
                .iter()
                .position(|(path, _)| *path == self.destination)
            {
                drop(writers.swap_remove(index));
            }
        }
    }

    pub(crate) fn inject_directory_sync_warning() -> Guard {
        *INJECT_DIRECTORY_SYNC_WARNING
            .lock()
            .expect("lock io warning failpoint") = Some(std::thread::current().id());
        Guard
    }

    pub(crate) fn directory_sync_warning(destination: &Path) -> Option<WriteWarning> {
        let inject = {
            let mut enabled = INJECT_DIRECTORY_SYNC_WARNING
                .lock()
                .expect("lock io warning failpoint");
            let inject = enabled.is_some_and(|thread_id| thread_id == std::thread::current().id());
            if inject {
                *enabled = None;
            }
            inject
        };
        inject.then(|| WriteWarning::DirectorySyncFailed {
            path: destination
                .parent()
                .expect("prepared destination always has a parent")
                .to_path_buf(),
            message: "injected directory sync warning".to_owned(),
        })
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            *INJECT_DIRECTORY_SYNC_WARNING
                .lock()
                .expect("lock io warning failpoint") = None;
        }
    }
}

fn reject_lock_link_or_reparse(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_link_or_reparse(&metadata) => Err(unsafe_path(
            "destination lock must not be a symlink or reparse point",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

struct TemporaryArtifact {
    path: PathBuf,
    identity: ObjectIdentity,
    armed: bool,
}

impl TemporaryArtifact {
    fn create(destination: &Path, label: &str) -> io::Result<(Self, File)> {
        for _ in 0..128 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!(
                ".{}.gta-claw.{label}.{}.{sequence}",
                destination
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("config"),
                std::process::id()
            );
            let path = destination.with_file_name(name);
            match atomicfs::create_new_no_follow(&path) {
                Ok(file) => {
                    let identity = atomicfs::identity_of_handle(&file)?;
                    let artifact = Self {
                        path,
                        identity,
                        armed: true,
                    };
                    artifact.verify_identity()?;
                    return Ok((artifact, file));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary file",
        ))
    }

    /// Confirms the reservation path still names the object opened at creation.
    fn verify_identity(&self) -> io::Result<()> {
        if atomicfs::identity_of_path(&self.path)? == self.identity {
            return Ok(());
        }
        Err(unsafe_path(
            "temporary file identity changed before publication",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }

    /// Re-arms cleanup after the temporary is safe to remove again.
    const fn rearm(&mut self) {
        self.armed = true;
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if !self.armed {
            return Ok(());
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {
                self.armed = false;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.armed = false;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for TemporaryArtifact {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn set_permissions(existing: Option<&fs::Metadata>, file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = existing.map_or(0o600, |metadata| metadata.permissions().mode() & 0o777);
    file.set_permissions(fs::Permissions::from_mode(mode))
}

/// Permission propagation has no counterpart outside Unix.
///
/// Windows keeps the destination's own security descriptor across the exchange,
/// so there is nothing for the temporary file to inherit and nothing that can
/// fail; the signature matches the Unix one only so the caller stays uniform.
#[cfg(not(unix))]
#[expect(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "the signature mirrors the fallible Unix implementation the caller is written against"
)]
fn set_permissions(_existing: Option<&fs::Metadata>, _file: &File) -> io::Result<()> {
    Ok(())
}

/// Flushes the directory entry that publication just changed.
///
/// The operating-system failure is returned rather than swallowed. A platform
/// that cannot honour the request has not made the rename durable, and reporting
/// success would let a caller claim a guarantee the filesystem never gave; the
/// caller turns the failure into a [`WriteWarning::DirectorySyncFailed`] that
/// migration and rollback refuse to treat as success.
fn sync_parent(destination: &Path) -> io::Result<()> {
    atomicfs::sync_directory(
        destination
            .parent()
            .expect("prepared destination always has a parent"),
    )
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt::{self, Display, Formatter};
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{ConfigError, atomic_write_bytes};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn precommit_failure_preserves_destination_and_removes_temporary_file() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let path = directory.join("config.json5");
        std::fs::write(&path, "old").expect("write old file");

        let error = atomic_write_bytes(&path, b"new", || {
            Err(io::Error::other(InjectedPrecommitFailure))
        })
        .map_err(|source| ConfigError::io(&path, source))
        .expect_err("write must fail");

        let ConfigError::Io { source, .. } = error else {
            panic!("expected typed I/O failure: {error}");
        };
        assert!(
            source
                .get_ref()
                .and_then(|error| error.downcast_ref::<InjectedPrecommitFailure>())
                .is_some(),
            "failure must originate from the injected precommit stage: {source}"
        );
        assert_eq!(std::fs::read_to_string(path).expect("read old file"), "old");
        let entries = std::fs::read_dir(&directory)
            .expect("read temporary directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect directory entries");
        assert!(
            entries.iter().all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name == "config.json5" || name == ".config.json5.gta-claw.lock"
            }),
            "temporary artifacts must be removed"
        );
        drop(cleanup);
    }

    /// A writer that lands after every pre-publication check and immediately
    /// before the atomic exchange must not have its bytes destroyed.
    ///
    /// The advisory lock only orders writers that take it. This barrier stands
    /// in for the ones that do not — a text editor saving the file, an installer
    /// dropping a new copy — and lands in the exact window an unconditional
    /// rename cannot see.
    #[test]
    fn an_external_write_immediately_before_publication_is_preserved() {
        use super::{Publication, PublicationGuard, publish_bytes_locked, with_destination_lock};

        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let path = directory.join("config.json5");
        std::fs::write(&path, "old").expect("write old file");
        let expected = super::super::versioning::digest_hex(b"old");
        let destination = std::fs::canonicalize(&path).expect("canonicalize destination");

        let _barrier = super::inject_external_writer_for_tests(&destination, |destination| {
            let staging = destination.with_file_name(".external-writer");
            std::fs::write(&staging, "external").expect("stage external bytes");
            std::fs::rename(&staging, destination).expect("publish external bytes");
        });
        let publication = with_destination_lock(&path, |locked| {
            publish_bytes_locked(locked, b"new", PublicationGuard::Digest(&expected), || {
                Ok(())
            })
        })
        .expect("publication must not fail outright");

        let Publication::Conflict { actual, preserved } = publication else {
            panic!("publication must report a conflict, not overwrite foreign bytes");
        };
        assert_eq!(actual, b"external");
        let preserved = preserved.expect("displaced bytes must be preserved durably");
        assert_eq!(
            std::fs::read(&preserved).expect("read preserved copy"),
            b"external",
            "the durable copy must hold the displaced bytes exactly"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read destination"),
            "external",
            "the external writer's bytes must survive"
        );
        drop(cleanup);
    }

    /// When the platform refuses to undo the displacement, the displaced object
    /// must survive — in the durable copy *and* at the retained temporary path.
    ///
    /// The durable copy is written from bytes already in hand, before the
    /// exchange that can fail is attempted, so the only copy never depends on a
    /// step that might not happen. Cleanup is disarmed for the same reason: the
    /// error path used to delete the very object it was reporting about.
    #[test]
    fn a_refused_restore_never_deletes_the_only_copy_of_the_displaced_object() {
        use super::{PublicationGuard, publish_bytes_locked, with_destination_lock};

        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let path = directory.join("config.json5");
        std::fs::write(&path, "old").expect("write old file");
        let expected = super::super::versioning::digest_hex(b"old");
        let destination = std::fs::canonicalize(&path).expect("canonicalize destination");

        let _barrier = super::inject_external_writer_for_tests(&destination, |destination| {
            let staging = destination.with_file_name(".external-writer-refused");
            std::fs::write(&staging, "external").expect("stage external bytes");
            std::fs::rename(&staging, destination).expect("publish external bytes");
        });
        let _refuse = super::fail_restore_for_tests(&destination);
        let error = with_destination_lock(&path, |locked| {
            publish_bytes_locked(locked, b"new", PublicationGuard::Digest(&expected), || {
                Ok(())
            })
        })
        .expect_err("a refused restore must not look like success");

        let message = error.to_string();
        assert!(
            message.contains("could not restore the concurrently changed destination"),
            "the error must say the destination was not restored: {message}"
        );
        assert!(
            message.contains("still holds the newly published bytes"),
            "the error must name the state the destination was left in: {message}"
        );

        // Both surviving copies are named, and both really exist.
        let retained = retained_path(&message, "retained at ");
        assert_eq!(
            std::fs::read(&retained).expect("read retained temporary"),
            b"external",
            "the retained temporary must still hold the displaced bytes"
        );
        let preserved = retained_path(&message, "copied to ");
        assert_eq!(
            std::fs::read(&preserved).expect("read durable copy"),
            b"external",
            "the durable copy must hold the displaced bytes exactly"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read destination"),
            "new",
            "the destination state must be exactly what the error reports"
        );
        drop(cleanup);
    }

    /// Extracts a path the failure message names after `marker`.
    fn retained_path(message: &str, marker: &str) -> PathBuf {
        let rest = message
            .split_once(marker)
            .unwrap_or_else(|| panic!("message must contain {marker:?}: {message}"))
            .1;
        let end = rest.find(" and ").unwrap_or(rest.len());
        PathBuf::from(rest[..end].trim_end_matches(['.', ';']))
    }

    /// A destination removed in the same window is a concurrent change too, and
    /// a guarded publication must not recreate the file it no longer describes.
    #[test]
    fn a_destination_removed_immediately_before_publication_is_not_recreated() {
        use super::{Publication, PublicationGuard, publish_bytes_locked, with_destination_lock};

        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let path = directory.join("config.json5");
        std::fs::write(&path, "old").expect("write old file");
        let expected = super::super::versioning::digest_hex(b"old");
        let destination = std::fs::canonicalize(&path).expect("canonicalize destination");

        let _barrier = super::inject_external_writer_for_tests(&destination, |destination| {
            std::fs::remove_file(destination).expect("remove destination");
        });
        let publication = with_destination_lock(&path, |locked| {
            publish_bytes_locked(locked, b"new", PublicationGuard::Digest(&expected), || {
                Ok(())
            })
        })
        .expect("publication must not fail outright");

        assert!(
            matches!(
                publication,
                Publication::Conflict {
                    ref actual,
                    preserved: None
                } if actual.is_empty()
            ),
            "removal must be reported as a conflict, got {publication:?}"
        );
        assert!(!path.exists(), "the destination must stay removed");
        drop(cleanup);
    }

    fn temporary_directory() -> PathBuf {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "claw-config-unit-test-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create temporary directory");
        std::fs::canonicalize(directory).expect("canonicalize temporary directory")
    }

    #[derive(Debug)]
    struct InjectedPrecommitFailure;

    impl Display for InjectedPrecommitFailure {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected precommit failure")
        }
    }

    impl Error for InjectedPrecommitFailure {}

    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

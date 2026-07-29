use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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
    let existing = fs::symlink_metadata(destination).ok();
    let (mut temporary, mut file) = TemporaryArtifact::create(destination, "tmp")?;

    let operation = (|| {
        set_permissions(existing.as_ref(), &file)?;
        file.write_all(contents)?;
        file.flush()?;
        file.sync_all()?;
        precommit()?;
        drop(file);
        let mut warnings = Vec::new();
        if let Some(warning) =
            replace_destination(temporary.path(), destination, existing.is_some())?
        {
            warnings.push(warning);
        }
        temporary.disarm();
        if let Err(error) = sync_parent(destination) {
            warnings.push(WriteWarning::DirectorySyncFailed {
                path: destination
                    .parent()
                    .expect("prepared destination always has a parent")
                    .to_owned(),
                message: error.to_string(),
            });
        }
        Ok(WriteOutcome { warnings })
    })();

    match operation {
        Ok(outcome) => Ok(outcome),
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
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        file.lock()?;
        file.sync_all()?;
        sync_parent(&lock_path)?;
        reject_lock_link_or_reparse(&lock_path)?;
        Ok(Self { file })
    }
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
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    return Ok((Self { path, armed: true }, file));
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

    #[cfg(windows)]
    fn reserve_path(destination: &Path, label: &str) -> io::Result<Self> {
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
            if !path.try_exists()? {
                return Ok(Self { path, armed: true });
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique backup path",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    const fn disarm(&mut self) {
        self.armed = false;
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

#[cfg(not(unix))]
fn set_permissions(_existing: Option<&fs::Metadata>, _file: &File) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn replace_destination(
    temporary: &Path,
    destination: &Path,
    _exists: bool,
) -> io::Result<Option<WriteWarning>> {
    fs::rename(temporary, destination)?;
    Ok(None)
}

#[cfg(windows)]
fn replace_destination(
    temporary: &Path,
    destination: &Path,
    exists: bool,
) -> io::Result<Option<WriteWarning>> {
    if !exists {
        fs::rename(temporary, destination)?;
        return Ok(None);
    }
    windows_replace::replace_with_backup(destination, temporary)
}

#[cfg(not(any(unix, windows)))]
fn replace_destination(
    temporary: &Path,
    destination: &Path,
    _exists: bool,
) -> io::Result<Option<WriteWarning>> {
    fs::rename(temporary, destination)?;
    Ok(None)
}

#[cfg(unix)]
fn sync_parent(destination: &Path) -> io::Result<()> {
    File::open(
        destination
            .parent()
            .expect("prepared destination always has a parent"),
    )?
    .sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_destination: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "publishing over an existing Windows destination requires ReplaceFileW, which has \
              no safe std equivalent; the crate denies unsafe everywhere else so this module is \
              the single audited FFI surface"
)]
mod windows_replace {
    use std::fs;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    use super::{TemporaryArtifact, WriteWarning};

    /// Publishes `replacement` over an existing `destination` via `ReplaceFileW`.
    ///
    /// `ReplaceFileW` keeps the destination's ACLs, attributes, creation time,
    /// named streams, encryption, and compression, which a plain rename would
    /// discard. It writes the old destination to a reserved backup path first,
    /// so a failed replacement can be rolled back to the exact original bytes.
    ///
    /// Returns `Ok(Some(_))` when the new bytes were published but the backup
    /// could not be removed afterwards; the caller surfaces that as a non-fatal
    /// [`WriteWarning::BackupCleanupFailed`] naming the retained backup.
    pub(super) fn replace_with_backup(
        destination: &Path,
        replacement: &Path,
    ) -> io::Result<Option<WriteWarning>> {
        replace_with_backup_and_cleanup(destination, replacement, TemporaryArtifact::cleanup)
    }

    fn replace_with_backup_and_cleanup(
        destination: &Path,
        replacement: &Path,
        cleanup: impl FnOnce(&mut TemporaryArtifact) -> io::Result<()>,
    ) -> io::Result<Option<WriteWarning>> {
        let mut backup = TemporaryArtifact::reserve_path(destination, "backup")?;
        let destination_wide = wide(destination);
        let replacement_wide = wide(replacement);
        let backup_wide = wide(backup.path());

        // SAFETY: All three buffers are valid, NUL-terminated UTF-16 paths for
        // the duration of the call. Reserved pointers are null as required.
        let replaced = unsafe {
            ReplaceFileW(
                destination_wide.as_ptr(),
                replacement_wide.as_ptr(),
                backup_wide.as_ptr(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if replaced != 0 {
            return match cleanup(&mut backup) {
                Ok(()) => Ok(None),
                Err(error) => {
                    let path = backup.path().to_owned();
                    backup.disarm();
                    Ok(Some(WriteWarning::BackupCleanupFailed {
                        path,
                        message: error.to_string(),
                    }))
                }
            };
        }

        let replace_error = io::Error::last_os_error();
        let replace_error_kind = replace_error.kind();
        restore_backup(destination, &mut backup).map_err(|restore_error| {
            io::Error::new(
                replace_error_kind,
                format!(
                    "{replace_error}; additionally failed to restore Windows replacement backup \
                     {}: {restore_error}",
                    backup.path().display()
                ),
            )
        })?;
        Err(replace_error)
    }

    #[cfg(test)]
    pub(super) fn replace_with_injected_cleanup_failure(
        destination: &Path,
        replacement: &Path,
    ) -> io::Result<Option<WriteWarning>> {
        replace_with_backup_and_cleanup(destination, replacement, |_| {
            Err(io::Error::other("injected backup cleanup failure"))
        })
    }

    fn restore_backup(destination: &Path, backup: &mut TemporaryArtifact) -> io::Result<()> {
        if !backup.path().try_exists()? {
            backup.disarm();
            return Ok(());
        }
        if destination.try_exists()? {
            return backup.cleanup();
        }
        fs::rename(backup.path(), destination)?;
        backup.disarm();
        Ok(())
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
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

    #[cfg(windows)]
    #[test]
    fn postcommit_backup_cleanup_failure_returns_warning_with_new_bytes_published() {
        use super::{WriteWarning, windows_replace};

        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let destination = directory.join("config.json5");
        let replacement = directory.join("replacement.json5");
        std::fs::write(&destination, "old").expect("write destination");
        std::fs::write(&replacement, "new").expect("write replacement");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&replacement)
            .expect("open replacement")
            .sync_all()
            .expect("sync replacement");

        let warning =
            windows_replace::replace_with_injected_cleanup_failure(&destination, &replacement)
                .expect("replacement succeeds")
                .expect("cleanup warning");

        assert_eq!(
            std::fs::read_to_string(&destination).expect("read destination"),
            "new"
        );
        let WriteWarning::BackupCleanupFailed { path, message } = warning else {
            panic!("unexpected warning: {warning:?}");
        };
        assert!(message.contains("injected backup cleanup failure"));
        assert_eq!(std::fs::read_to_string(&path).expect("read backup"), "old");
        std::fs::remove_file(path).expect("remove retained backup");
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

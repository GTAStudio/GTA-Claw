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
pub fn write_file(
    path: impl AsRef<Path>,
    snapshot: &ConfigSnapshot,
) -> Result<WriteOutcome, ConfigError> {
    let path = path.as_ref();
    let contents = to_json5(snapshot)?;
    atomic_write_bytes(path, contents.as_bytes(), || Ok(()))
        .map_err(|error| ConfigError::io(path, error))
}

fn atomic_write_bytes(
    path: &Path,
    contents: &[u8],
    precommit: impl FnOnce() -> io::Result<()>,
) -> io::Result<WriteOutcome> {
    let destination = prepare_destination(path)?;
    let existing = fs::symlink_metadata(&destination).ok();
    let (mut temporary, mut file) = TemporaryArtifact::create(&destination, "tmp")?;

    let operation = (|| {
        set_permissions(existing.as_ref(), &file)?;
        file.write_all(contents)?;
        file.flush()?;
        file.sync_all()?;
        precommit()?;
        drop(file);
        let mut warnings = Vec::new();
        if let Some(warning) =
            replace_destination(temporary.path(), &destination, existing.is_some())?
        {
            warnings.push(warning);
        }
        temporary.disarm();
        if let Err(error) = sync_parent(&destination) {
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

    fn disarm(&mut self) {
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
#[allow(unsafe_code)]
mod windows_replace {
    use std::fs;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    use super::{TemporaryArtifact, WriteWarning};

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
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::atomic_write_bytes;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn precommit_failure_preserves_destination_and_removes_temporary_file() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let path = directory.join("config.json5");
        std::fs::write(&path, "old").expect("write old file");

        let error = atomic_write_bytes(&path, b"new", || {
            Err(io::Error::other("injected precommit failure"))
        })
        .expect_err("write must fail");

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(std::fs::read_to_string(path).expect("read old file"), "old");
        let entries = std::fs::read_dir(&directory)
            .expect("read temporary directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect directory entries");
        assert_eq!(entries.len(), 1, "temporary artifacts must be removed");
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
        directory
    }

    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

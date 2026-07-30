use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
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
    /// A displaced or conditionally removed object was retained after cleanup failed.
    BackupCleanupFailed {
        /// Retained path containing the previous destination bytes.
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

/// Raw destination state observed while its stable publication lock is held.
///
/// A snapshot records absence or the exact bytes and filesystem generation of
/// one regular file. The generation token is intentionally private: callers can
/// inspect the bytes, then pass the complete snapshot back to
/// [`PublicationLock::compare_write`] or [`PublicationLock::compare_remove`]
/// without constructing a digest-only expectation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationSnapshot {
    destination: PathBuf,
    state: SnapshotState,
}

impl PublicationSnapshot {
    /// Returns the observed bytes, or `None` when the destination was absent.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        match &self.state {
            SnapshotState::Absent => None,
            SnapshotState::Present(generation) => Some(&generation.bytes),
        }
    }

    /// Returns whether the destination was absent.
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        matches!(&self.state, SnapshotState::Absent)
    }

    /// Returns whether the destination held a regular file.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        !self.is_absent()
    }

    /// Returns the canonical destination this snapshot belongs to.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SnapshotState {
    Absent,
    Present(FileGeneration),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileGeneration {
    bytes: Vec<u8>,
    identity: ObjectIdentity,
    mode: Option<u32>,
}

/// Evidence returned when a conditional publication loses its comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationConflict {
    actual: PublicationSnapshot,
    preserved_paths: Vec<PathBuf>,
    message: Option<String>,
}

impl PublicationConflict {
    /// Returns the exact state that defeated the comparison.
    #[must_use]
    pub const fn actual(&self) -> &PublicationSnapshot {
        &self.actual
    }

    /// Returns paths retained because restoring or cleaning them was unsafe.
    ///
    /// Each path names bytes that this call deliberately refused to overwrite
    /// or delete. An empty slice means the conflicting state was restored at the
    /// canonical destination or no mutation was attempted.
    #[must_use]
    pub fn preserved_paths(&self) -> &[PathBuf] {
        &self.preserved_paths
    }

    /// Returns a diagnostic when conflict restoration encountered another
    /// writer or a cleanup limitation.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

/// Result of a compare-and-publish or compare-and-remove operation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub enum CompareOutcome {
    /// The expected generation matched and the requested operation linearized.
    Applied(WriteOutcome),
    /// The expected generation did not match; foreign bytes were preserved.
    Conflict(PublicationConflict),
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
/// processes cannot rename while this operation runs. The destination and its
/// immediate parent are rejected when they are a Unix symlink or Windows
/// reparse point. Platform layout aliases above that directory are
/// canonicalized before the resolved chain is validated, but path-based
/// replacement APIs cannot close every ancestor race without a permanently
/// held directory handle.
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
/// the atomic write fails: `path` has no file name, the configuration directory
/// or destination is a symlink or Windows reparse point, the resolved ancestor
/// chain is unsafe, the destination exists but is not a regular file, the parent
/// cannot be canonicalized, no unique temporary name could be allocated in 128
/// attempts, or writing, flushing, `fsync`-ing, or publishing the temporary file
/// failed. Pre-publication failures leave the destination untouched. A failed
/// Windows `ReplaceFileW` can report an ambiguous partial state; that path fails
/// closed and preserves its exact recovery backup instead of claiming which
/// bytes are live. If removing a known temporary file also fails, its path is
/// appended to the returned message.
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
/// as [`write_file`]: a rejected path shape, a symlink or reparse point at the
/// configuration directory or destination, an unsafe resolved ancestor chain, a
/// destination that exists but is not a regular file, exhausted temporary-name
/// attempts, or a failed write, flush, `fsync`, or publication. Failures before
/// publication leave the destination untouched; ambiguous Windows replacement
/// failures preserve their recovery backup and return an explicit error.
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
    let lock = PublicationLock::acquire_io(path)?;
    lock.write_bytes_with_precommit(contents, precommit)
}

/// Stable sibling-file lock held across one target's publication transaction.
///
/// Every cooperating configuration writer uses this lock. It remains on disk
/// between calls so two processes never lock different generations of a
/// create/delete sentinel.
pub struct PublicationLock {
    destination: PathBuf,
    lock_path: PathBuf,
    file: File,
}

impl PublicationLock {
    /// Acquires the publication lock associated with `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] when the destination cannot be prepared, the
    /// stable sidecar is unsafe, or the operating-system lock cannot be acquired.
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        Self::acquire_io(path).map_err(|error| ConfigError::io(path, error))
    }

    /// Acquires a complete set of publication locks in canonical path order.
    ///
    /// Canonical aliases of the same destination are deduplicated. Every caller
    /// that may need more than one target must acquire the complete set through
    /// this method rather than nesting [`Self::acquire`] calls; sorting before
    /// the first lock is taken gives cooperating callers one deadlock-free order.
    ///
    /// The returned vector is sorted by [`Self::destination`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] when any destination cannot be prepared or
    /// any stable sidecar cannot be safely opened and locked. Locks acquired
    /// earlier in the ordered set are released before the error is returned.
    pub fn acquire_all<I, P>(paths: I) -> Result<Vec<Self>, ConfigError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut destinations = Vec::new();
        for path in paths {
            let path = path.as_ref();
            let destination =
                prepare_destination(path).map_err(|error| ConfigError::io(path, error))?;
            destinations.push(destination);
        }
        destinations.sort();
        destinations.dedup();

        let mut locks = Vec::with_capacity(destinations.len());
        for destination in destinations {
            let lock = Self::acquire_prepared_io(destination.clone())
                .map_err(|error| ConfigError::io(&destination, error))?;
            locks.push(lock);
        }
        Ok(locks)
    }

    fn acquire_io(path: &Path) -> io::Result<Self> {
        let destination = prepare_destination(path)?;
        Self::acquire_prepared_io(destination)
    }

    fn acquire_prepared_io(destination: PathBuf) -> io::Result<Self> {
        let lock_path = publication_lock_path(&destination);
        reject_lock_link_or_reparse(&lock_path)?;
        let file = atomicfs::open_lock_no_follow(&lock_path)?;
        file.lock()?;
        let lock = Self {
            destination,
            lock_path,
            file,
        };
        lock.validate()?;
        Ok(lock)
    }

    /// Returns the canonical destination protected by this guard.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Publishes bytes while retaining this guard.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] when staging, synchronization, lock
    /// validation, or atomic publication fails.
    pub fn write_bytes(&self, contents: &[u8]) -> Result<WriteOutcome, ConfigError> {
        self.write_bytes_with_precommit(contents, || Ok(()))
            .map_err(|error| ConfigError::io(&self.destination, error))
    }

    /// Reads the exact raw destination generation while this lock is held.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] if the lock sidecar changed, the destination
    /// is not a no-follow regular file, or its path changed generations while
    /// bytes were being read.
    pub fn snapshot(&self) -> Result<PublicationSnapshot, ConfigError> {
        self.validate()
            .and_then(|()| read_snapshot(&self.destination))
            .map_err(|error| ConfigError::io(&self.destination, error))
    }

    /// Writes `replacement` only if `expected` is still the destination state.
    ///
    /// Present-file comparisons bind raw bytes, filesystem object identity and
    /// Unix mode to the atomic displacement. Same-byte replacement objects are
    /// conflicts, not ABA successes. Absence uses an atomic no-replace move.
    ///
    /// On a present-state conflict, the object displaced at the linearization
    /// point is restored with no-replace operations. A still-newer writer is
    /// never overwritten; any bytes that cannot be restored safely are named by
    /// [`PublicationConflict::preserved_paths`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] when `expected` belongs to another target,
    /// staging fails, the stable lock changes, or the platform lacks the atomic
    /// displacement/no-replace primitives required to uphold the comparison.
    pub fn compare_write(
        &self,
        expected: &PublicationSnapshot,
        replacement: &[u8],
    ) -> Result<CompareOutcome, ConfigError> {
        self.compare_write_with_hooks(expected, replacement, || Ok(()), || Ok(()))
    }

    /// Removes the destination only if `expected` is still its exact state.
    ///
    /// A matching present file is atomically moved to a private sibling and
    /// validated before cleanup. A mismatching object is restored with an atomic
    /// no-replace move, so a writer that arrives during restoration remains live.
    /// A matching absence is a successful no-op.
    ///
    /// Conditional removal reports cleanup and Unix directory-sync limitations
    /// through [`WriteOutcome::warnings`] after the removal has linearized.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] when `expected` belongs to another target,
    /// the stable lock changes, or the platform cannot perform atomic no-replace
    /// moves. Unsupported targets fail closed without deleting the destination.
    pub fn compare_remove(
        &self,
        expected: &PublicationSnapshot,
    ) -> Result<CompareOutcome, ConfigError> {
        self.compare_remove_with_hook(expected, || Ok(()))
    }

    #[allow(
        clippy::cognitive_complexity,
        reason = "the guarded CAS state machine keeps every atomic topology and preservation path explicit"
    )]
    fn compare_write_with_hooks(
        &self,
        expected: &PublicationSnapshot,
        replacement: &[u8],
        before_displacement: impl FnOnce() -> io::Result<()>,
        after_displacement: impl FnOnce() -> io::Result<()>,
    ) -> Result<CompareOutcome, ConfigError> {
        self.validate_expected(expected)
            .and_then(|()| self.validate())
            .map_err(|error| ConfigError::io(&self.destination, error))?;
        let preflight = read_snapshot(&self.destination)
            .map_err(|error| ConfigError::io(&self.destination, error))?;
        if preflight != *expected {
            return Ok(CompareOutcome::Conflict(conflict_from_snapshot(preflight)));
        }

        let (mut temporary, mut file) =
            TemporaryArtifact::create(&self.destination, "compare-write")
                .map_err(|error| ConfigError::io(&self.destination, error))?;
        let staged = (|| {
            set_snapshot_permissions(expected, &file)?;
            file.write_all(replacement)?;
            file.flush()?;
            file.sync_all()?;
            let generation = generation_from_handle(
                &file,
                temporary.path(),
                replacement.to_vec(),
            )?;
            before_displacement()?;
            self.validate()?;
            temporary.verify_identity()?;
            drop(file);
            Ok(generation)
        })();
        let candidate = match staged {
            Ok(candidate) => candidate,
            Err(error) => {
                return Err(ConfigError::io(
                    &self.destination,
                    combine_cleanup_error(&mut temporary, error),
                ));
            }
        };

        match &expected.state {
            SnapshotState::Absent => {
                let outcome = match atomicfs::rename_no_replace(
                    temporary.path(),
                    &self.destination,
                ) {
                    Ok(()) => {
                        temporary.disarm();
                        after_displacement()
                            .map_err(|error| ConfigError::io(&self.destination, error))?;
                        CompareOutcome::Applied(publication_outcome(&self.destination))
                    }
                    Err(error) if is_already_exists(&error) => {
                        temporary
                            .cleanup()
                            .map_err(|cleanup| ConfigError::io(temporary.path(), cleanup))?;
                        CompareOutcome::Conflict(conflict_from_snapshot(
                            read_snapshot(&self.destination)
                                .map_err(|source| ConfigError::io(&self.destination, source))?,
                        ))
                    }
                    Err(error) => {
                        return Err(ConfigError::io(
                            &self.destination,
                            combine_cleanup_error(&mut temporary, error),
                        ));
                    }
                };
                Ok(outcome)
            }
            SnapshotState::Present(expected_generation) => {
                let displaced_path = displacement_path(temporary.path(), &self.destination)
                    .map_err(|error| ConfigError::io(&self.destination, error))?;
                if let Err(error) = atomicfs::displace_file(
                    temporary.path(),
                    &self.destination,
                    &displaced_path,
                ) {
                    return Err(ConfigError::io(
                        &self.destination,
                        guarded_displacement_error(
                            &mut temporary,
                            &displaced_path,
                            error,
                        ),
                    ));
                }
                temporary.disarm();
                after_displacement()
                    .map_err(|error| ConfigError::io(&self.destination, error))?;
                let actual = read_generation(&displaced_path)
                    .map_err(|error| ConfigError::io(&displaced_path, error))?;
                if actual == *expected_generation {
                    let mut warnings = Vec::new();
                    cleanup_published_generation(
                        &displaced_path,
                        &actual,
                        &mut warnings,
                    );
                    append_sync_warning(&self.destination, &mut warnings);
                    return Ok(CompareOutcome::Applied(WriteOutcome { warnings }));
                }
                Ok(CompareOutcome::Conflict(restore_write_conflict(
                    &self.destination,
                    &candidate,
                    &displaced_path,
                    actual,
                )))
            }
        }
    }

    fn compare_remove_with_hook(
        &self,
        expected: &PublicationSnapshot,
        after_displacement: impl FnOnce() -> io::Result<()>,
    ) -> Result<CompareOutcome, ConfigError> {
        self.validate_expected(expected)
            .and_then(|()| self.validate())
            .map_err(|error| ConfigError::io(&self.destination, error))?;

        let SnapshotState::Present(expected_generation) = &expected.state else {
            let actual = read_snapshot(&self.destination)
                .map_err(|error| ConfigError::io(&self.destination, error))?;
            return if actual.is_absent() {
                Ok(CompareOutcome::Applied(WriteOutcome::default()))
            } else {
                Ok(CompareOutcome::Conflict(conflict_from_snapshot(actual)))
            };
        };

        let Some(displaced_path) = move_destination_to_unique(
            &self.destination,
            "compare-remove",
        )
        .map_err(|error| ConfigError::io(&self.destination, error))?
        else {
            return Ok(CompareOutcome::Conflict(conflict_from_snapshot(
                absent_snapshot(&self.destination),
            )));
        };
        after_displacement()
            .map_err(|error| ConfigError::io(&self.destination, error))?;
        let actual = match read_generation(&displaced_path) {
            Ok(actual) => actual,
            Err(inspect_error) => {
                let restoration =
                    atomicfs::rename_no_replace(&displaced_path, &self.destination);
                let message = match restoration {
                    Ok(()) => format!(
                        "could not inspect the atomically displaced object: {inspect_error}; the \
                         object was restored"
                    ),
                    Err(restore_error) => {
                        let _ = protect_preserved_path(&displaced_path);
                        format!(
                            "could not inspect the atomically displaced object: {inspect_error}; \
                             restoration also failed: {restore_error}; retained object: {}",
                            displaced_path.display()
                        )
                    }
                };
                return Err(ConfigError::io(
                    &self.destination,
                    io::Error::new(inspect_error.kind(), message),
                ));
            }
        };
        if actual == *expected_generation {
            let mut warnings = Vec::new();
            cleanup_published_generation(&displaced_path, &actual, &mut warnings);
            append_sync_warning(&self.destination, &mut warnings);
            return Ok(CompareOutcome::Applied(WriteOutcome { warnings }));
        }

        let actual_snapshot = present_snapshot(&self.destination, actual);
        let restoration = atomicfs::rename_no_replace(&displaced_path, &self.destination);
        match restoration {
            Ok(()) => Ok(CompareOutcome::Conflict(PublicationConflict {
                actual: actual_snapshot,
                preserved_paths: Vec::new(),
                message: sync_conflict_message(&self.destination),
            })),
            Err(error) if is_already_exists(&error) => {
                let _ = protect_preserved_path(&displaced_path);
                Ok(CompareOutcome::Conflict(PublicationConflict {
                    actual: actual_snapshot,
                    preserved_paths: vec![displaced_path],
                    message: Some(
                        "a newer destination appeared while the mismatching object was being \
                         restored; the newer destination remains live"
                            .to_owned(),
                    ),
                }))
            }
            Err(error) => {
                let _ = protect_preserved_path(&displaced_path);
                Ok(CompareOutcome::Conflict(PublicationConflict {
                    actual: actual_snapshot,
                    preserved_paths: vec![displaced_path],
                    message: Some(format!(
                        "could not restore the mismatching object without replacement: {error}"
                    )),
                }))
            }
        }
    }

    fn validate_expected(&self, expected: &PublicationSnapshot) -> io::Result<()> {
        if expected.destination == self.destination {
            Ok(())
        } else {
            Err(unsafe_path(
                "publication snapshot belongs to a different destination",
            ))
        }
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        reject_lock_link_or_reparse(&self.lock_path)?;
        if atomicfs::identity_of_handle(&self.file)?
            != atomicfs::identity_of_path(&self.lock_path)?
        {
            return Err(unsafe_path(
                "publication lock identity changed while held",
            ));
        }
        Ok(())
    }

    pub(crate) fn write_bytes_with_precommit(
        &self,
        contents: &[u8],
        precommit: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<WriteOutcome> {
        let existing = fs::symlink_metadata(&self.destination).ok();
        let (mut temporary, mut file) = TemporaryArtifact::create(&self.destination, "tmp")?;

        let operation = (|| {
            set_permissions(existing.as_ref(), &file)?;
            file.write_all(contents)?;
            file.flush()?;
            file.sync_all()?;
            precommit()?;
            self.validate()?;
            temporary.verify_identity()?;
            drop(file);
            let mut warnings = Vec::new();
            if let Some(warning) = replace_destination(
                temporary.path(),
                &self.destination,
                existing.is_some(),
            )? {
                warnings.push(warning);
            }
            temporary.disarm();
            if let Err(error) = sync_parent(&self.destination) {
                warnings.push(WriteWarning::DirectorySyncFailed {
                    path: self
                        .destination
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
                        "{operation_error}; additionally could not safely remove temporary file \
                         {}: {cleanup_error}",
                        temporary.path().display()
                    ),
                )),
            },
        }
    }
}

impl Drop for PublicationLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn read_snapshot(destination: &Path) -> io::Result<PublicationSnapshot> {
    match read_generation(destination) {
        Ok(generation) => Ok(present_snapshot(destination, generation)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(absent_snapshot(destination))
        }
        Err(error) => Err(error),
    }
}

fn read_generation(path: &Path) -> io::Result<FileGeneration> {
    let mut file = atomicfs::open_no_follow(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(unsafe_path("publication destination is not a regular file"));
    }
    let identity = atomicfs::identity_of_handle(&file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if atomicfs::identity_of_path(path)? != identity {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "publication destination changed while it was being read",
        ));
    }
    Ok(FileGeneration {
        bytes,
        identity,
        mode: permission_mode(&metadata),
    })
}

fn generation_from_handle(
    file: &File,
    path: &Path,
    bytes: Vec<u8>,
) -> io::Result<FileGeneration> {
    let metadata = file.metadata()?;
    let identity = atomicfs::identity_of_handle(file)?;
    if atomicfs::identity_of_path(path)? != identity {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "staged publication object changed while it was written",
        ));
    }
    Ok(FileGeneration {
        bytes,
        identity,
        mode: permission_mode(&metadata),
    })
}

fn absent_snapshot(destination: &Path) -> PublicationSnapshot {
    PublicationSnapshot {
        destination: destination.to_owned(),
        state: SnapshotState::Absent,
    }
}

fn present_snapshot(
    destination: &Path,
    generation: FileGeneration,
) -> PublicationSnapshot {
    PublicationSnapshot {
        destination: destination.to_owned(),
        state: SnapshotState::Present(generation),
    }
}

fn conflict_from_snapshot(actual: PublicationSnapshot) -> PublicationConflict {
    PublicationConflict {
        actual,
        preserved_paths: Vec::new(),
        message: None,
    }
}

fn publication_outcome(destination: &Path) -> WriteOutcome {
    let mut warnings = Vec::new();
    append_sync_warning(destination, &mut warnings);
    WriteOutcome { warnings }
}

fn append_sync_warning(destination: &Path, warnings: &mut Vec<WriteWarning>) {
    if let Err(error) = sync_parent(destination) {
        warnings.push(WriteWarning::DirectorySyncFailed {
            path: destination
                .parent()
                .expect("prepared destination always has a parent")
                .to_owned(),
            message: error.to_string(),
        });
    }
}

fn cleanup_published_generation(
    path: &Path,
    expected: &FileGeneration,
    warnings: &mut Vec<WriteWarning>,
) {
    let cleanup = read_generation(path).and_then(|actual| {
        if actual != *expected {
            return Err(unsafe_path(
                "refusing to remove a retained object from another generation",
            ));
        }
        #[cfg(test)]
        if cleanup_failpoint::take() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected conditional cleanup failure",
            ));
        }
        fs::remove_file(path)
    });
    match cleanup {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            let message = protect_preserved_path(path).map_or_else(
                || error.to_string(),
                |protection| format!("{error}; {protection}"),
            );
            warnings.push(WriteWarning::BackupCleanupFailed {
                path: path.to_owned(),
                message,
            });
        }
    }
}

#[cfg(test)]
mod cleanup_failpoint {
    use std::sync::Mutex;

    static THREADS: Mutex<Vec<std::thread::ThreadId>> = Mutex::new(Vec::new());

    pub(super) struct Guard(std::thread::ThreadId);

    pub(super) fn inject() -> Guard {
        let thread = std::thread::current().id();
        THREADS
            .lock()
            .expect("lock cleanup failpoint")
            .push(thread);
        Guard(std::thread::current().id())
    }

    pub(super) fn take() -> bool {
        let mut threads = THREADS.lock().expect("lock cleanup failpoint");
        let current = std::thread::current().id();
        let Some(index) = threads.iter().position(|thread| thread == &current) else {
            return false;
        };
        threads.swap_remove(index);
        true
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            let mut threads = THREADS.lock().expect("lock cleanup failpoint");
            if let Some(index) = threads.iter().position(|thread| thread == &self.0) {
                threads.swap_remove(index);
            }
        }
    }
}

#[allow(
    clippy::cognitive_complexity,
    reason = "each branch records a distinct post-exchange topology without deleting evidence"
)]
fn restore_write_conflict(
    destination: &Path,
    candidate: &FileGeneration,
    displaced_path: &Path,
    actual: FileGeneration,
) -> PublicationConflict {
    let actual_snapshot = present_snapshot(destination, actual);
    let mut preserved_paths = Vec::new();
    let mut messages = Vec::new();
    let quarantined = match move_destination_to_unique(destination, "compare-current") {
        Ok(Some(path)) => path,
        Ok(None) => {
            preserve_path(displaced_path, &mut preserved_paths);
            return PublicationConflict {
                actual: actual_snapshot,
                preserved_paths,
                message: Some(
                    "the published candidate disappeared before conflict restoration; displaced \
                     bytes remain preserved"
                        .to_owned(),
                ),
            };
        }
        Err(error) => {
            preserve_path(displaced_path, &mut preserved_paths);
            return PublicationConflict {
                actual: actual_snapshot,
                preserved_paths,
                message: Some(format!(
                    "could not quarantine the live object before no-replace restoration: {error}"
                )),
            };
        }
    };

    let quarantined_generation = match read_generation(&quarantined) {
        Ok(generation) => generation,
        Err(error) => {
            preserve_path(displaced_path, &mut preserved_paths);
            preserve_path(&quarantined, &mut preserved_paths);
            return PublicationConflict {
                actual: actual_snapshot,
                preserved_paths,
                message: Some(format!(
                    "could not inspect the quarantined live generation: {error}"
                )),
            };
        }
    };

    if quarantined_generation == *candidate {
        match atomicfs::rename_no_replace(displaced_path, destination) {
            Ok(()) => {
                let mut cleanup_warnings = Vec::new();
                cleanup_published_generation(
                    &quarantined,
                    &quarantined_generation,
                    &mut cleanup_warnings,
                );
                for warning in cleanup_warnings {
                    let WriteWarning::BackupCleanupFailed { path, message } = warning else {
                        continue;
                    };
                    preserve_path(&path, &mut preserved_paths);
                    messages.push(message);
                }
                if let Some(message) = sync_conflict_message(destination) {
                    messages.push(message);
                }
            }
            Err(error) if is_already_exists(&error) => {
                preserve_path(displaced_path, &mut preserved_paths);
                let mut cleanup_warnings = Vec::new();
                cleanup_published_generation(
                    &quarantined,
                    &quarantined_generation,
                    &mut cleanup_warnings,
                );
                for warning in cleanup_warnings {
                    if let WriteWarning::BackupCleanupFailed { path, message } = warning {
                        preserve_path(&path, &mut preserved_paths);
                        messages.push(message);
                    }
                }
                messages.push(
                    "a newer destination appeared before the displaced object could be restored; \
                     the newer destination remains live"
                        .to_owned(),
                );
            }
            Err(error) => {
                preserve_path(displaced_path, &mut preserved_paths);
                preserve_path(&quarantined, &mut preserved_paths);
                messages.push(format!(
                    "could not restore the displaced object with a no-replace move: {error}"
                ));
            }
        }
    } else {
        match atomicfs::rename_no_replace(&quarantined, destination) {
            Ok(()) => {
                preserve_path(displaced_path, &mut preserved_paths);
                messages.push(
                    "a newer writer replaced the candidate during conflict handling; that newer \
                     generation was restored and the originally displaced object was preserved"
                        .to_owned(),
                );
                if let Some(message) = sync_conflict_message(destination) {
                    messages.push(message);
                }
            }
            Err(error) if is_already_exists(&error) => {
                preserve_path(displaced_path, &mut preserved_paths);
                preserve_path(&quarantined, &mut preserved_paths);
                messages.push(
                    "another newer writer arrived while the quarantined generation was being \
                     restored; the newest destination remains live"
                        .to_owned(),
                );
            }
            Err(error) => {
                preserve_path(displaced_path, &mut preserved_paths);
                preserve_path(&quarantined, &mut preserved_paths);
                messages.push(format!(
                    "could not restore the quarantined newer generation without replacement: \
                     {error}"
                ));
            }
        }
    }

    PublicationConflict {
        actual: actual_snapshot,
        preserved_paths,
        message: (!messages.is_empty()).then(|| messages.join("; ")),
    }
}

fn move_destination_to_unique(
    destination: &Path,
    label: &str,
) -> io::Result<Option<PathBuf>> {
    for _ in 0..128 {
        let path = unique_absent_path(destination, label)?;
        match atomicfs::rename_no_replace(destination, &path) {
            Ok(()) => return Ok(Some(path)),
            Err(error) if is_already_exists(&error) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique conditional-publication artifact",
    ))
}

fn unique_absent_path(destination: &Path, label: &str) -> io::Result<PathBuf> {
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = sibling_name(
            ".",
            destination.file_name().unwrap_or_else(|| OsStr::new("config")),
            &format!(".gta-claw.{label}.{}.{sequence}", std::process::id()),
        );
        let path = destination.with_file_name(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(path),
            Ok(_) => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate an absent conditional-publication path",
    ))
}

#[cfg(windows)]
fn displacement_path(_temporary: &Path, destination: &Path) -> io::Result<PathBuf> {
    unique_absent_path(destination, "compare-displaced")
}

#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the signature mirrors the path-allocating Windows implementation"
)]
fn displacement_path(temporary: &Path, _destination: &Path) -> io::Result<PathBuf> {
    Ok(temporary.to_owned())
}

fn preserve_path(path: &Path, preserved_paths: &mut Vec<PathBuf>) {
    if fs::symlink_metadata(path).is_ok()
        && !preserved_paths.iter().any(|preserved| preserved == path)
    {
        let _ = protect_preserved_path(path);
        preserved_paths.push(path.to_owned());
    }
}

#[cfg(windows)]
fn protect_preserved_path(path: &Path) -> Option<String> {
    atomicfs::protect_restrictive_dacl(path)
        .err()
        .map(|error| format!("could not protect retained DACL at {}: {error}", path.display()))
}

#[cfg(not(windows))]
const fn protect_preserved_path(_path: &Path) -> Option<String> {
    None
}

fn sync_conflict_message(destination: &Path) -> Option<String> {
    sync_parent(destination)
        .err()
        .map(|error| format!("directory sync failed after conflict restoration: {error}"))
}

fn is_already_exists(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AlreadyExists
        || matches!(error.raw_os_error(), Some(80 | 183))
}

fn combine_cleanup_error(
    temporary: &mut TemporaryArtifact,
    operation_error: io::Error,
) -> io::Error {
    match temporary.cleanup() {
        Ok(()) => operation_error,
        Err(cleanup_error) => io::Error::new(
            operation_error.kind(),
            format!(
                "{operation_error}; additionally could not safely remove temporary file {}: \
                 {cleanup_error}",
                temporary.path().display()
            ),
        ),
    }
}

#[cfg(windows)]
fn guarded_displacement_error(
    temporary: &mut TemporaryArtifact,
    displaced_path: &Path,
    error: io::Error,
) -> io::Error {
    let staged_path = temporary.path().to_owned();
    // `ReplaceFileW` documents partial failure states. Neither named object is
    // expendable until a later recovery pass can prove the exact topology.
    temporary.disarm();
    io::Error::new(
        error.kind(),
        format!(
            "{error}; guarded displacement outcome is uncertain; staged/replacement evidence is \
             retained at {} when present and displaced evidence is retained at {} when present",
            staged_path.display(),
            displaced_path.display()
        ),
    )
}

#[cfg(not(windows))]
fn guarded_displacement_error(
    temporary: &mut TemporaryArtifact,
    _displaced_path: &Path,
    error: io::Error,
) -> io::Error {
    combine_cleanup_error(temporary, error)
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the optional mode is part of one cross-platform generation representation"
)]
fn permission_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;

    Some(metadata.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
const fn permission_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

#[cfg(unix)]
fn set_snapshot_permissions(
    expected: &PublicationSnapshot,
    file: &File,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = match &expected.state {
        SnapshotState::Absent => 0o600,
        SnapshotState::Present(generation) => generation.mode.unwrap_or(0o600),
    };
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(windows)]
fn set_snapshot_permissions(
    expected: &PublicationSnapshot,
    file: &File,
) -> io::Result<()> {
    let SnapshotState::Present(generation) = &expected.state else {
        return Ok(());
    };
    let source = atomicfs::open_no_follow(&expected.destination)?;
    if atomicfs::identity_of_handle(&source)? != generation.identity {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "expected Windows source generation changed before DACL copy",
        ));
    }
    atomicfs::copy_restrictive_dacl(&source, file)
}

#[cfg(not(any(unix, windows)))]
#[expect(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "the signature mirrors the fallible platform permission implementations"
)]
fn set_snapshot_permissions(
    _expected: &PublicationSnapshot,
    _file: &File,
) -> io::Result<()> {
    Ok(())
}

pub(crate) fn publication_lock_path(destination: &Path) -> PathBuf {
    destination.with_file_name(sibling_name(
        ".",
        destination.file_name().unwrap_or_else(|| OsStr::new("config")),
        ".gta-claw.lock",
    ))
}

pub(crate) fn prepare_destination(path: &Path) -> io::Result<PathBuf> {
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
    let parent_metadata = fs::symlink_metadata(&absolute_parent)?;
    if is_link_or_reparse(&parent_metadata) {
        return Err(unsafe_path(
            "destination parent must not be a symlink or reparse point",
        ));
    }
    let canonical_parent = fs::canonicalize(&absolute_parent)?;
    let pinned_parent = atomicfs::identity_of_path(&canonical_parent)?;
    reject_unsafe_ancestors(&canonical_parent)?;

    let metadata = fs::symlink_metadata(&canonical_parent)?;
    if !metadata.is_dir() {
        return Err(unsafe_path("destination parent is not a directory"));
    }
    if atomicfs::identity_of_path(&canonical_parent)? != pinned_parent {
        return Err(unsafe_path(
            "destination parent identity changed during validation",
        ));
    }

    let mut destination = canonical_parent.join(file_name);
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
            destination = resolve_existing_destination(&destination)?;
            let resolved_parent = destination
                .parent()
                .ok_or_else(|| unsafe_path("resolved destination has no parent"))?;
            if atomicfs::identity_of_path(resolved_parent)? != pinned_parent {
                return Err(unsafe_path(
                    "canonical destination escaped its validated parent",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(destination)
}

#[cfg(windows)]
fn resolve_existing_destination(path: &Path) -> io::Result<PathBuf> {
    let file = atomicfs::open_no_follow(path)?;
    let identity = atomicfs::identity_of_handle(&file)?;
    let resolved = atomicfs::final_path_of_handle(&file)?;
    if atomicfs::identity_of_path(path)? != identity {
        return Err(unsafe_path(
            "Windows destination alias changed while its handle was resolved",
        ));
    }
    if atomicfs::identity_of_path(&resolved)? != identity {
        return Err(unsafe_path(
            "handle-resolved Windows destination identity changed",
        ));
    }
    Ok(resolved)
}

#[cfg(not(windows))]
fn resolve_existing_destination(path: &Path) -> io::Result<PathBuf> {
    fs::canonicalize(path)
}

fn reject_lock_link_or_reparse(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_link_or_reparse(&metadata) || !metadata.is_file() => Err(unsafe_path(
            "publication lock must be a regular file, not a symlink or reparse point",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
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

fn sibling_name(prefix: &str, file_name: &OsStr, suffix: &str) -> OsString {
    let mut name = OsString::from(prefix);
    name.push(file_name);
    name.push(suffix);
    name
}

struct TemporaryArtifact {
    path: PathBuf,
    identity: Option<ObjectIdentity>,
    armed: bool,
}

impl TemporaryArtifact {
    fn create(destination: &Path, label: &str) -> io::Result<(Self, File)> {
        for _ in 0..128 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = sibling_name(
                ".",
                destination.file_name().unwrap_or_else(|| OsStr::new("config")),
                &format!(".gta-claw.{label}.{}.{sequence}", std::process::id()),
            );
            let path = destination.with_file_name(name);
            match atomicfs::create_new_no_follow(&path) {
                Ok(file) => {
                    let identity = atomicfs::identity_of_handle(&file)?;
                    let artifact = Self {
                        path,
                        identity: Some(identity),
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

    #[cfg(windows)]
    fn reserve_path(destination: &Path, label: &str) -> io::Result<Self> {
        for _ in 0..128 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = sibling_name(
                ".",
                destination.file_name().unwrap_or_else(|| OsStr::new("config")),
                &format!(".gta-claw.{label}.{}.{sequence}", std::process::id()),
            );
            let path = destination.with_file_name(name);
            if !path.try_exists()? {
                return Ok(Self {
                    path,
                    identity: None,
                    armed: true,
                });
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

    fn verify_identity(&self) -> io::Result<()> {
        let Some(identity) = self.identity else {
            return Err(unsafe_path(
                "temporary artifact identity has not been captured",
            ));
        };
        if atomicfs::identity_of_path(&self.path)? == identity {
            Ok(())
        } else {
            Err(unsafe_path(
                "temporary artifact identity changed before publication",
            ))
        }
    }

    #[cfg(windows)]
    fn capture_identity(&mut self) -> io::Result<()> {
        self.identity = Some(atomicfs::identity_of_path(&self.path)?);
        Ok(())
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if !self.armed {
            return Ok(());
        }
        let Some(identity) = self.identity else {
            self.armed = false;
            return Err(unsafe_path(
                "refusing to remove an artifact whose identity is unknown",
            ));
        };
        match atomicfs::identity_of_path(&self.path) {
            Ok(actual) if actual != identity => {
                self.armed = false;
                return Err(unsafe_path(
                    "refusing to remove an artifact replaced by another writer",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.armed = false;
                return Ok(());
            }
            Err(error) => return Err(error),
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
        if self.armed
            && self.identity.is_some()
            && self.verify_identity().is_ok()
        {
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
#[expect(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "the signature mirrors Unix permission propagation"
)]
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
        atomicfs::rename_no_replace(temporary, destination)?;
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
    atomicfs::sync_directory(
        destination
            .parent()
            .expect("prepared destination always has a parent"),
    )
}

#[cfg(not(unix))]
#[expect(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "Windows deliberately has no supported directory flush"
)]
fn sync_parent(_destination: &Path) -> io::Result<()> {
    // Windows has no supported directory `FlushFileBuffers` equivalent. File
    // data is write-through and synchronized, but directory-entry durability
    // across sudden power loss is intentionally not claimed.
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
            if let Err(error) = backup.capture_identity() {
                let path = backup.path().to_owned();
                backup.disarm();
                return Ok(Some(WriteWarning::BackupCleanupFailed {
                    path,
                    message: format!(
                        "could not verify the retained backup identity before cleanup: {error}"
                    ),
                }));
            }
            return match cleanup(&mut backup) {
                Ok(()) => Ok(None),
                Err(cleanup_error) => {
                    let path = backup.path().to_owned();
                    let message = match crate::atomicfs::protect_restrictive_dacl(&path) {
                        Ok(()) => cleanup_error.to_string(),
                        Err(dacl_error) => format!(
                            "{cleanup_error}; additionally failed to protect the retained backup \
                             DACL: {dacl_error}"
                        ),
                    };
                    backup.disarm();
                    Ok(Some(WriteWarning::BackupCleanupFailed { path, message }))
                }
            };
        }

        let replace_error = io::Error::last_os_error();
        let replace_error_kind = replace_error.kind();
        resolve_failed_replace(destination, &mut backup).map_err(|restore_error| {
            io::Error::new(
                replace_error_kind,
                format!(
                    "{replace_error}; Windows replacement state could not be resolved safely from \
                     backup {}: {restore_error}",
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

    #[cfg(test)]
    pub(super) fn resolve_injected_partial_state(
        destination: &Path,
        backup_bytes: &[u8],
    ) -> (std::path::PathBuf, io::Result<()>) {
        let mut backup =
            TemporaryArtifact::reserve_path(destination, "partial").expect("reserve backup path");
        fs::write(backup.path(), backup_bytes).expect("write injected recovery backup");
        let path = backup.path().to_owned();
        let result = resolve_failed_replace(destination, &mut backup);
        (path, result)
    }

    #[cfg(test)]
    pub(super) fn resolve_injected_absent_dacl_state(
        destination: &Path,
        backup_bytes: &[u8],
    ) -> io::Result<(bool, bool)> {
        let mut backup = TemporaryArtifact::reserve_path(destination, "inherited-dacl")?;
        fs::write(backup.path(), backup_bytes)?;
        let backup_file = crate::atomicfs::open_no_follow(backup.path())?;
        let before = crate::atomicfs::dacl_is_protected(&backup_file)?;
        resolve_failed_replace(destination, &mut backup)?;
        let destination_file = crate::atomicfs::open_no_follow(destination)?;
        let after = crate::atomicfs::dacl_is_protected(&destination_file)?;
        Ok((before, after))
    }

    fn resolve_failed_replace(
        destination: &Path,
        backup: &mut TemporaryArtifact,
    ) -> io::Result<()> {
        let backup_path = backup.path().to_owned();
        backup.disarm();
        match fs::symlink_metadata(&backup_path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
        match crate::atomicfs::rename_no_replace(&backup_path, destination) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                crate::atomicfs::protect_restrictive_dacl(&backup_path)?;
            }
            Err(error) => {
                if let Err(dacl_error) =
                    crate::atomicfs::protect_restrictive_dacl(&backup_path)
                {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "{error}; additionally failed to protect retained backup DACL: \
                             {dacl_error}"
                        ),
                    ));
                }
                return Err(error);
            }
        }
        Err(io::Error::other(format!(
            "both destination and exact recovery backup exist; preserving the backup at {}",
            backup_path.display()
        )))
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

    use super::{
        CompareOutcome, ConfigError, PublicationLock, SnapshotState, WriteWarning,
        atomic_write_bytes, cleanup_failpoint,
    };
    use crate::atomicfs;

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
        assert_eq!(
            entries.len(),
            2,
            "only the destination and stable lock sidecar may remain"
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.file_name().to_string_lossy().ends_with(".gta-claw.lock"))
        );
        drop(cleanup);
    }

    #[test]
    fn same_bytes_from_a_new_object_are_a_guarded_write_conflict() {
        let directory = temporary_directory();
        let _cleanup = Cleanup(directory.clone());
        let path = directory.join("state.json");
        std::fs::write(&path, b"same").expect("write source");
        let lock = PublicationLock::acquire(&path).expect("acquire lock");
        let expected = lock.snapshot().expect("snapshot source");
        let source_identity = atomicfs::identity_of_path(&path).expect("source identity");
        publish_external(&path, b"same").expect("replace with same bytes");
        let replacement_identity =
            atomicfs::identity_of_path(&path).expect("replacement identity");
        assert_ne!(source_identity, replacement_identity);

        let CompareOutcome::Conflict(conflict) = lock
            .compare_write(&expected, b"candidate")
            .expect("same-byte generation conflict")
        else {
            panic!("same bytes from another object must not satisfy the expectation");
        };

        assert_eq!(conflict.actual().bytes(), Some(b"same".as_slice()));
        assert_eq!(
            atomicfs::identity_of_path(&path).expect("live identity"),
            replacement_identity
        );
    }

    #[test]
    fn compare_write_preserves_writer_before_and_after_displacement() {
        let directory = temporary_directory();
        let _cleanup = Cleanup(directory.clone());
        let path = directory.join("state.json");
        std::fs::write(&path, b"original").expect("write source");
        let lock = PublicationLock::acquire(&path).expect("acquire lock");
        let expected = lock.snapshot().expect("snapshot source");

        let CompareOutcome::Conflict(conflict) = lock
            .compare_write_with_hooks(
                &expected,
                b"candidate",
                || publish_external(&path, b"writer-b"),
                || publish_external(&path, b"writer-c"),
            )
            .expect("guarded write conflict")
        else {
            panic!("writer B must defeat the comparison");
        };

        assert_eq!(conflict.actual().bytes(), Some(b"writer-b".as_slice()));
        assert_eq!(
            std::fs::read(&path).expect("read newest live bytes"),
            b"writer-c"
        );
        assert!(
            conflict
                .preserved_paths()
                .iter()
                .any(|path| std::fs::read(path).is_ok_and(|bytes| bytes == b"writer-b"))
        );
    }

    #[test]
    fn compare_write_restores_the_object_displaced_at_cas() {
        let directory = temporary_directory();
        let _cleanup = Cleanup(directory.clone());
        let path = directory.join("state.json");
        std::fs::write(&path, b"original").expect("write source");
        let lock = PublicationLock::acquire(&path).expect("acquire lock");
        let expected = lock.snapshot().expect("snapshot source");
        let SnapshotState::Present(expected_generation) = &expected.state else {
            panic!("source snapshot must be present");
        };

        let CompareOutcome::Conflict(conflict) = lock
            .compare_write_with_hooks(
                &expected,
                b"candidate",
                || publish_external(&path, b"original"),
                || Ok(()),
            )
            .expect("guarded write conflict")
        else {
            panic!("writer B must defeat the comparison");
        };

        assert_ne!(
            atomicfs::identity_of_path(&path).expect("restored writer identity"),
            expected_generation.identity
        );
        assert_eq!(conflict.actual().bytes(), Some(b"original".as_slice()));
        assert_eq!(
            std::fs::read(&path).expect("read restored bytes"),
            b"original"
        );
        assert!(conflict.preserved_paths().is_empty());
    }

    #[test]
    fn compare_remove_never_replaces_a_writer_during_conflict_restoration() {
        let directory = temporary_directory();
        let _cleanup = Cleanup(directory.clone());
        let path = directory.join("state.json");
        std::fs::write(&path, b"original").expect("write source");
        let lock = PublicationLock::acquire(&path).expect("acquire lock");
        let expected = lock.snapshot().expect("snapshot source");
        let SnapshotState::Present(expected_generation) = &expected.state else {
            panic!("source snapshot must be present");
        };
        publish_external(&path, b"original").expect("publish same-byte writer B");
        assert_ne!(
            atomicfs::identity_of_path(&path).expect("writer B identity"),
            expected_generation.identity
        );

        let CompareOutcome::Conflict(conflict) = lock
            .compare_remove_with_hook(&expected, || publish_external(&path, b"writer-c"))
            .expect("guarded remove conflict")
        else {
            panic!("stale removal must conflict");
        };

        assert_eq!(conflict.actual().bytes(), Some(b"original".as_slice()));
        assert_eq!(
            std::fs::read(&path).expect("read newest live bytes"),
            b"writer-c"
        );
        assert!(
            conflict
                .preserved_paths()
                .iter()
                .any(|path| std::fs::read(path).is_ok_and(|bytes| bytes == b"original"))
        );
    }

    #[test]
    fn conditional_remove_surfaces_cleanup_failure_as_write_warning() {
        let directory = temporary_directory();
        let _cleanup = Cleanup(directory.clone());
        let path = directory.join("state.json");
        std::fs::write(&path, b"remove-me").expect("write source");
        let lock = PublicationLock::acquire(&path).expect("acquire lock");
        let expected = lock.snapshot().expect("snapshot source");
        let _failpoint = cleanup_failpoint::inject();

        let CompareOutcome::Applied(outcome) =
            lock.compare_remove(&expected).expect("conditional remove")
        else {
            panic!("exact generation must be removed");
        };

        assert!(!path.exists(), "destination removal already linearized");
        let [WriteWarning::BackupCleanupFailed {
            path: retained,
            message,
        }] = outcome.warnings.as_slice()
        else {
            panic!("cleanup failure must be returned in WriteOutcome");
        };
        assert!(message.contains("injected conditional cleanup failure"));
        assert_eq!(
            std::fs::read(retained).expect("read retained removed object"),
            b"remove-me"
        );
    }

    #[cfg(all(
        unix,
        not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
    ))]
    #[test]
    fn guarded_mutation_fails_closed_without_native_cas_primitives() {
        let directory = temporary_directory();
        let _cleanup = Cleanup(directory.clone());
        let path = directory.join("state.json");
        std::fs::write(&path, b"original").expect("write source");
        let lock = PublicationLock::acquire(&path).expect("acquire lock");
        let expected = lock.snapshot().expect("snapshot source");

        lock.compare_write(&expected, b"candidate")
            .expect_err("guarded write requires atomic displacement");
        assert_eq!(std::fs::read(&path).expect("source preserved"), b"original");

        lock.compare_remove(&expected)
            .expect_err("guarded removal requires atomic no-replace move");
        assert_eq!(std::fs::read(&path).expect("source preserved"), b"original");
    }

    #[cfg(not(any(unix, windows)))]
    #[test]
    fn guarded_lock_fails_closed_without_no_follow_identity_support() {
        let directory = temporary_directory();
        let _cleanup = Cleanup(directory.clone());
        let path = directory.join("state.json");
        std::fs::write(&path, b"original").expect("write source");

        let error = match PublicationLock::acquire(&path) {
            Ok(_) => panic!("unsupported platform must not approximate a guarded lock"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("not available on this platform"));
        assert_eq!(std::fs::read(&path).expect("source preserved"), b"original");
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
        let backup = crate::atomicfs::open_no_follow(&path).expect("open retained backup");
        assert!(
            crate::atomicfs::dacl_is_protected(&backup).expect("read retained backup DACL control")
        );
        drop(backup);
        std::fs::remove_file(path).expect("remove retained backup");
        drop(cleanup);
    }

    #[cfg(windows)]
    #[test]
    fn uncertain_windows_replace_preserves_backup_when_both_paths_exist() {
        use super::windows_replace;

        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let destination = directory.join("config.json5");
        std::fs::write(&destination, "live").expect("write live destination");

        let (backup, result) =
            windows_replace::resolve_injected_partial_state(&destination, b"original");
        let error = result.expect_err("ambiguous state must fail closed");

        assert!(error.to_string().contains("both destination"));
        assert_eq!(
            std::fs::read_to_string(&destination).expect("read live destination"),
            "live"
        );
        assert_eq!(
            std::fs::read_to_string(&backup).expect("read preserved backup"),
            "original"
        );
        let backup_file = crate::atomicfs::open_no_follow(&backup).expect("open preserved backup");
        assert!(
            crate::atomicfs::dacl_is_protected(&backup_file)
                .expect("read preserved backup DACL control")
        );
        drop(backup_file);
        drop(cleanup);
    }

    #[cfg(windows)]
    #[test]
    fn partial_windows_replace_restores_backup_only_when_destination_is_absent() {
        use super::windows_replace;

        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let destination = directory.join("config.json5");

        let (backup, result) =
            windows_replace::resolve_injected_partial_state(&destination, b"original");
        result.expect("an absent destination has one unambiguous restoration");

        assert!(!backup.exists());
        assert_eq!(
            std::fs::read_to_string(&destination).expect("read restored destination"),
            "original"
        );
        drop(cleanup);
    }

    #[cfg(windows)]
    #[test]
    fn existing_windows_aliases_share_handle_resolved_lock_destination() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let path = directory.join("Configuration State Long Name.json");
        std::fs::write(&path, b"state").expect("write destination");

        let normal = PublicationLock::acquire(&path).expect("lock normal path");
        let destination = normal.destination().to_owned();
        let sidecar = super::publication_lock_path(normal.destination());
        drop(normal);

        let extended = std::fs::canonicalize(&path).expect("canonical extended path");
        let canonical = PublicationLock::acquire(&extended).expect("lock extended path");
        assert_eq!(canonical.destination(), destination);
        assert_eq!(
            super::publication_lock_path(canonical.destination()),
            sidecar
        );
        drop(canonical);

        if let Ok(short) = atomicfs::short_path(&path)
            && short != path
            && short != extended
        {
            let short_lock = PublicationLock::acquire(&short).expect("lock 8.3 alias");
            assert_eq!(short_lock.destination(), destination);
            assert_eq!(
                super::publication_lock_path(short_lock.destination()),
                sidecar
            );
        }
        drop(cleanup);
    }

    #[cfg(windows)]
    #[test]
    fn multiply_linked_windows_destination_fails_closed() {
        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let path = directory.join("state.json");
        let alias = directory.join("state-hard-link.json");
        std::fs::write(&path, b"state").expect("write destination");
        std::fs::hard_link(&path, &alias).expect("create hard link");

        let error = match PublicationLock::acquire(&path) {
            Ok(_) => panic!("multiple names cannot coordinate on one sidecar safely"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("multiply linked Windows files"));
        assert_eq!(std::fs::read(&path).expect("source preserved"), b"state");
        drop(cleanup);
    }

    #[cfg(windows)]
    #[test]
    fn successful_windows_backup_restoration_preserves_inherited_dacl_control() {
        use super::windows_replace;

        let directory = temporary_directory();
        let cleanup = Cleanup(directory.clone());
        let destination = directory.join("config.json5");

        let (before, after) =
            windows_replace::resolve_injected_absent_dacl_state(&destination, b"original")
                .expect("restore absent destination");

        assert_eq!(
            after, before,
            "restoration must not convert an inherited DACL into a protected DACL"
        );
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

    fn publish_external(destination: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let staging = destination.with_file_name(format!(
            ".external-publication-{}-{sequence}",
            std::process::id()
        ));
        std::fs::write(&staging, bytes)?;
        #[cfg(windows)]
        match std::fs::remove_file(destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        std::fs::rename(staging, destination)
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

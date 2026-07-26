//! Dependency-free, scoped JSON persistence primitives.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde::de::DeserializeOwned;

static FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static SCOPE_LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();

/// A failure in the durable JSON persistence layer.
#[derive(Debug)]
pub enum PersistenceError {
    /// An operating-system operation failed.
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying operating-system error.
        source: io::Error,
    },
    /// Stored bytes were not a valid state document.
    Corrupt {
        /// State path containing the invalid bytes.
        path: PathBuf,
        /// Structural diagnostic.
        reason: String,
    },
    /// Serialization of a validated document failed.
    Serialization {
        /// Destination path for the document.
        path: PathBuf,
        /// Underlying JSON error.
        source: serde_json::Error,
    },
    /// A serialized state document exceeded its structural file bound.
    StateTooLarge {
        /// Destination path for the document.
        path: PathBuf,
        /// Serialized byte length.
        size: usize,
        /// Maximum permitted byte length.
        limit: usize,
    },
    /// A previous panic poisoned a scope lock.
    LockPoisoned,
}

impl PersistenceError {
    pub(crate) fn io(operation: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    pub(crate) fn corrupt(path: impl Into<PathBuf>, reason: impl Into<String>) -> Self {
        Self::Corrupt {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

impl Display for PersistenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} durable state {}: {source}",
                path.display()
            ),
            Self::Corrupt { path, reason } => {
                write!(
                    formatter,
                    "corrupt durable state {}: {reason}",
                    path.display()
                )
            }
            Self::Serialization { path, source } => write!(
                formatter,
                "failed to serialize durable state {}: {source}",
                path.display()
            ),
            Self::StateTooLarge { path, size, limit } => write!(
                formatter,
                "durable state {} is {size} bytes, exceeding the {limit}-byte structural limit",
                path.display()
            ),
            Self::LockPoisoned => formatter.write_str("durable state scope lock was poisoned"),
        }
    }
}

impl Error for PersistenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Serialization { source, .. } => Some(source),
            Self::Corrupt { .. } | Self::StateTooLarge { .. } | Self::LockPoisoned => None,
        }
    }
}

/// In-process and cross-process serialization for one scoped state path.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ScopeLocks;

impl ScopeLocks {
    pub(crate) fn run<T, E>(
        &self,
        path: &Path,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<PersistenceError>,
    {
        let key = absolute_lexical_path(path).map_err(E::from)?;
        let scope_lock = {
            let mut locks = SCOPE_LOCKS
                .get_or_init(|| Mutex::new(BTreeMap::new()))
                .lock()
                .map_err(|_| E::from(PersistenceError::LockPoisoned))?;
            locks.retain(|_, lock| lock.strong_count() > 0);
            match locks.get(&key).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(Mutex::new(()));
                    locks.insert(key, Arc::downgrade(&lock));
                    lock
                }
            }
        };
        let _process_guard = scope_lock
            .lock()
            .map_err(|_| E::from(PersistenceError::LockPoisoned))?;
        let _file_guard = acquire_file_lock(path).map_err(E::from)?;
        operation()
    }
}

fn acquire_file_lock(state_path: &Path) -> Result<File, PersistenceError> {
    let lock_path = state_path.with_extension("lock");
    let lock_path = prepare_lock_path(&lock_path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| PersistenceError::io("open scope lock", &lock_path, source))?;
    file.lock()
        .map_err(|source| PersistenceError::io("lock", &lock_path, source))?;
    validate_open_file(&lock_path, &file)?;
    Ok(file)
}

fn absolute_lexical_path(path: &Path) -> Result<PathBuf, PersistenceError> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|source| PersistenceError::io("resolve", path, source))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    Ok(normalized)
}

pub(crate) fn scoped_state_path(
    root: &Path,
    collection: &str,
    scope: &crate::session::SessionId,
) -> PathBuf {
    root.join(collection)
        .join(format!("{}.json", scope_key(scope)))
}

pub(crate) fn scope_key(scope: &crate::session::SessionId) -> String {
    sha256_hex(scope.as_str().as_bytes())
}

pub(crate) fn read_json<T: DeserializeOwned>(
    path: &Path,
    max_bytes: usize,
) -> Result<Option<T>, PersistenceError> {
    let path = prepare_destination(path)?;
    recover_previous_if_needed(&path)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(PersistenceError::io("inspect", &path, source)),
    };
    if is_link_or_reparse(&metadata) || has_multiple_links(&metadata) || !metadata.is_file() {
        return Err(PersistenceError::corrupt(
            &path,
            "state path is not a regular file",
        ));
    }
    let max_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    if metadata.len() > max_u64 {
        return Err(PersistenceError::corrupt(
            &path,
            format!(
                "state file is {} bytes, exceeding the {max_bytes}-byte limit",
                metadata.len()
            ),
        ));
    }

    let file = File::open(&path).map_err(|source| PersistenceError::io("open", &path, source))?;
    validate_open_file(&path, &file)?;
    let read_limit = max_u64.saturating_add(1);
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(max_bytes)
            .min(max_bytes),
    );
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| PersistenceError::io("read", &path, source))?;
    if bytes.len() > max_bytes {
        return Err(PersistenceError::corrupt(
            &path,
            format!("state file grew beyond the {max_bytes}-byte limit while being read"),
        ));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|source| PersistenceError::corrupt(&path, format!("invalid JSON: {source}")))
}

pub(crate) fn atomic_write_json<T: Serialize>(
    path: &Path,
    value: &T,
    max_bytes: usize,
) -> Result<(), PersistenceError> {
    let destination = prepare_destination(path)?;
    recover_previous_if_needed(&destination)?;
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|source| PersistenceError::Serialization {
            path: destination.clone(),
            source,
        })?;
    bytes.push(b'\n');
    if bytes.len() > max_bytes {
        return Err(PersistenceError::StateTooLarge {
            path: destination,
            size: bytes.len(),
            limit: max_bytes,
        });
    }

    let existing = match fs::symlink_metadata(&destination) {
        Ok(metadata) => Some(metadata),
        Err(source) if source.kind() == io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(PersistenceError::io(
                "inspect destination",
                &destination,
                source,
            ));
        }
    };
    let (mut temporary, mut file) = TemporaryArtifact::create(&destination, "tmp")?;
    let operation = (|| {
        set_permissions(existing.as_ref(), &file).map_err(|source| {
            PersistenceError::io("set permissions on", temporary.path(), source)
        })?;
        file.write_all(&bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|source| PersistenceError::io("write", temporary.path(), source))?;
        drop(file);
        replace_destination(temporary.path(), &destination, existing.is_some())
            .map_err(|source| PersistenceError::io("publish", &destination, source))?;
        temporary.disarm();
        sync_parent(&destination)
            .map_err(|source| PersistenceError::io("synchronize parent of", &destination, source))
    })();

    match operation {
        Ok(()) => Ok(()),
        Err(operation_error) => match temporary.cleanup() {
            Ok(()) => Err(operation_error),
            Err(cleanup_error) => Err(PersistenceError::io(
                "clean temporary file after failed write to",
                &destination,
                cleanup_error,
            )),
        },
    }
}

pub(crate) fn quarantine_corrupt_state(path: &Path) -> Result<PathBuf, PersistenceError> {
    let path = prepare_destination(path)?;
    validate_existing_file(&path)?;
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    for _ in 0..128 {
        let sequence = FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state");
        let backup = path.with_file_name(format!(
            "{file_name}.corrupt-{millis}-{}-{sequence}",
            std::process::id()
        ));
        match backup.try_exists() {
            Ok(true) => continue,
            Ok(false) => {}
            Err(source) => {
                return Err(PersistenceError::io(
                    "inspect corrupt-state backup",
                    &backup,
                    source,
                ));
            }
        }
        fs::rename(&path, &backup)
            .map_err(|source| PersistenceError::io("quarantine", &path, source))?;
        sync_parent(&path)
            .map_err(|source| PersistenceError::io("synchronize parent of", &path, source))?;
        return Ok(backup);
    }
    Err(PersistenceError::io(
        "allocate corrupt-state backup for",
        path,
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique quarantine path",
        ),
    ))
}

fn prepare_destination(path: &Path) -> Result<PathBuf, PersistenceError> {
    let path = absolute_lexical_path(path)?;
    let file_name = path.file_name().ok_or_else(|| {
        PersistenceError::io(
            "prepare",
            &path,
            io::Error::new(io::ErrorKind::InvalidInput, "destination has no file name"),
        )
    })?;
    let parent = path.parent().ok_or_else(|| {
        PersistenceError::io(
            "prepare",
            &path,
            io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent"),
        )
    })?;
    ensure_directory_chain(parent)?;
    reject_unsafe_ancestors(parent)?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|source| PersistenceError::io("canonicalize parent for", &path, source))?;
    reject_unsafe_ancestors(&canonical_parent)?;
    ensure_canonical_parent(parent, &canonical_parent)?;
    let destination = canonical_parent.join(file_name);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if is_link_or_reparse(&metadata) || has_multiple_links(&metadata) || !metadata.is_file()
            {
                return Err(PersistenceError::io(
                    "prepare",
                    &destination,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "destination must be a regular file, not a link",
                    ),
                ));
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(PersistenceError::io(
                "inspect destination",
                &destination,
                source,
            ));
        }
    }
    Ok(destination)
}

fn prepare_lock_path(path: &Path) -> Result<PathBuf, PersistenceError> {
    let path = absolute_lexical_path(path)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| {
            PersistenceError::io(
                "prepare",
                &path,
                io::Error::new(io::ErrorKind::InvalidInput, "lock path has no file name"),
            )
        })?
        .to_os_string();
    let parent = path.parent().ok_or_else(|| {
        PersistenceError::io(
            "prepare",
            &path,
            io::Error::new(io::ErrorKind::InvalidInput, "lock path has no parent"),
        )
    })?;
    ensure_directory_chain(parent)?;
    reject_unsafe_ancestors(parent)?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|source| PersistenceError::io("canonicalize parent for", &path, source))?;
    reject_unsafe_ancestors(&canonical_parent)?;
    ensure_canonical_parent(parent, &canonical_parent)?;
    Ok(canonical_parent.join(file_name))
}

fn ensure_canonical_parent(parent: &Path, canonical: &Path) -> Result<(), PersistenceError> {
    if same_path_location(parent, canonical)? {
        return Ok(());
    }
    Err(PersistenceError::io(
        "confine",
        parent,
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "state parent resolved outside its validated lexical path",
        ),
    ))
}

#[cfg(not(windows))]
fn same_path_location(left: &Path, right: &Path) -> Result<bool, PersistenceError> {
    Ok(absolute_lexical_path(left)? == absolute_lexical_path(right)?)
}

#[cfg(windows)]
fn same_path_location(left: &Path, right: &Path) -> Result<bool, PersistenceError> {
    fn normalized(path: &Path) -> String {
        let value = path.to_string_lossy().replace('/', "\\");
        if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}").to_ascii_lowercase();
        }
        value
            .strip_prefix(r"\\?\")
            .unwrap_or(&value)
            .to_ascii_lowercase()
    }

    Ok(normalized(&absolute_lexical_path(left)?) == normalized(&absolute_lexical_path(right)?))
}

fn ensure_directory_chain(path: &Path) -> Result<(), PersistenceError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if !current.is_absolute() {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if is_link_or_reparse(&metadata) || !metadata.is_dir() {
                    return Err(PersistenceError::io(
                        "prepare",
                        &current,
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "state parent chain must contain only real directories",
                        ),
                    ));
                }
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(source) => {
                        return Err(PersistenceError::io(
                            "create state directory",
                            &current,
                            source,
                        ));
                    }
                }
                let metadata = fs::symlink_metadata(&current)
                    .map_err(|source| PersistenceError::io("inspect", &current, source))?;
                if is_link_or_reparse(&metadata) || !metadata.is_dir() {
                    return Err(PersistenceError::io(
                        "prepare",
                        &current,
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "created state directory was replaced by a link",
                        ),
                    ));
                }
            }
            Err(source) => {
                return Err(PersistenceError::io("inspect", &current, source));
            }
        }
    }
    Ok(())
}

fn reject_unsafe_ancestors(path: &Path) -> Result<(), PersistenceError> {
    let mut ancestors: Vec<_> = path.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|source| PersistenceError::io("inspect ancestor", ancestor, source))?;
        if is_link_or_reparse(&metadata) || !metadata.is_dir() {
            return Err(PersistenceError::io(
                "prepare",
                ancestor,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "state parent chain must contain only real directories",
                ),
            ));
        }
    }
    Ok(())
}

fn validate_existing_file(path: &Path) -> Result<(), PersistenceError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| PersistenceError::io("inspect", path, source))?;
    if is_link_or_reparse(&metadata) || has_multiple_links(&metadata) || !metadata.is_file() {
        return Err(PersistenceError::corrupt(
            path,
            "state path is not a regular file",
        ));
    }
    reject_unsafe_ancestors(path.parent().expect("prepared path has a parent"))
}

fn validate_open_file(path: &Path, file: &File) -> Result<(), PersistenceError> {
    validate_existing_file(path)?;
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| PersistenceError::io("inspect", path, source))?;
    let file_metadata = file
        .metadata()
        .map_err(|source| PersistenceError::io("inspect open file", path, source))?;
    if !file_metadata.is_file() || !same_file(&path_metadata, &file_metadata) {
        return Err(PersistenceError::io(
            "verify",
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "state path changed while it was being opened",
            ),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn has_multiple_links(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.nlink() > 1
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn has_multiple_links(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(not(any(unix, windows)))]
fn has_multiple_links(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    left.creation_time() == right.creation_time() && left.file_size() == right.file_size()
}

#[cfg(not(any(unix, windows)))]
fn same_file(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    true
}

struct TemporaryArtifact {
    path: PathBuf,
    armed: bool,
}

impl TemporaryArtifact {
    fn create(destination: &Path, label: &str) -> Result<(Self, File), PersistenceError> {
        cleanup_stale_temporaries(destination, label)?;
        for _ in 0..128 {
            let sequence = FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let file_name = destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("state");
            let path = destination.with_file_name(format!(
                ".{file_name}.gta-claw.{label}.{}.{sequence}",
                std::process::id()
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    if let Err(error) = validate_open_file(&path, &file) {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(error);
                    }
                    return Ok((Self { path, armed: true }, file));
                }
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(PersistenceError::io(
                        "create temporary state file",
                        path,
                        source,
                    ));
                }
            }
        }
        Err(PersistenceError::io(
            "allocate temporary state file for",
            destination,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique temporary state file",
            ),
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
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                self.armed = false;
                Ok(())
            }
            Err(source) => Err(source),
        }
    }
}

fn cleanup_stale_temporaries(destination: &Path, label: &str) -> Result<(), PersistenceError> {
    let parent = destination
        .parent()
        .expect("prepared destination always has a parent");
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    let prefix = format!(".{file_name}.gta-claw.{label}.");
    let mut removed = false;
    for entry in
        fs::read_dir(parent).map_err(|source| PersistenceError::io("scan", parent, source))?
    {
        let entry =
            entry.map_err(|source| PersistenceError::io("read entry in", parent, source))?;
        if !entry.file_name().to_string_lossy().starts_with(&prefix) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| PersistenceError::io("inspect stale temporary", &path, source))?;
        if metadata.is_dir() && !is_link_or_reparse(&metadata) {
            return Err(PersistenceError::io(
                "clean stale temporary",
                path,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "temporary artifact path is a directory",
                ),
            ));
        }
        fs::remove_file(&path)
            .map_err(|source| PersistenceError::io("clean stale temporary", &path, source))?;
        removed = true;
    }
    if removed {
        sync_parent(destination).map_err(|source| {
            PersistenceError::io(
                "synchronize parent after temporary cleanup for",
                destination,
                source,
            )
        })?;
    }
    Ok(())
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

#[cfg(not(windows))]
fn replace_destination(temporary: &Path, destination: &Path, _exists: bool) -> io::Result<()> {
    fs::rename(temporary, destination)
}

#[cfg(windows)]
fn replace_destination(temporary: &Path, destination: &Path, exists: bool) -> io::Result<()> {
    if !exists {
        return fs::rename(temporary, destination);
    }
    let previous = previous_path(destination);
    let transaction = transaction_path(destination);
    remove_file_if_exists(&previous)?;
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&transaction)?;
    marker.write_all(b"replace\n")?;
    marker.flush()?;
    marker.sync_all()?;
    drop(marker);
    if let Err(move_error) = fs::rename(destination, &previous) {
        let _ = fs::remove_file(&transaction);
        return Err(move_error);
    }
    match fs::rename(temporary, destination) {
        Ok(()) => {
            fs::remove_file(&previous)?;
            fs::remove_file(&transaction)
        }
        Err(publish_error) => match fs::rename(&previous, destination) {
            Ok(()) => {
                let _ = fs::remove_file(&transaction);
                Err(publish_error)
            }
            Err(restore_error) => Err(io::Error::new(
                publish_error.kind(),
                format!(
                    "{publish_error}; additionally failed to restore {}: {restore_error}",
                    previous.display()
                ),
            )),
        },
    }
}

#[cfg(windows)]
fn previous_path(destination: &Path) -> PathBuf {
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    destination.with_file_name(format!(".{file_name}.gta-claw.previous"))
}

#[cfg(windows)]
fn transaction_path(destination: &Path) -> PathBuf {
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    destination.with_file_name(format!(".{file_name}.gta-claw.replacing"))
}

#[cfg(windows)]
fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source),
    }
}

#[cfg(windows)]
fn artifact_exists(path: &Path) -> Result<bool, PersistenceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if !is_link_or_reparse(&metadata)
                && !has_multiple_links(&metadata)
                && metadata.is_file() =>
        {
            Ok(true)
        }
        Ok(_) => Err(PersistenceError::io(
            "inspect recovery artifact",
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovery artifact must be a regular file",
            ),
        )),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(PersistenceError::io(
            "inspect recovery artifact",
            path,
            source,
        )),
    }
}

#[cfg(windows)]
fn recover_previous_if_needed(destination: &Path) -> Result<(), PersistenceError> {
    let destination_exists = artifact_exists(destination)?;
    let previous = previous_path(destination);
    let previous_exists = artifact_exists(&previous)?;
    let transaction = transaction_path(destination);
    let transaction_exists = artifact_exists(&transaction)?;

    if !transaction_exists {
        if previous_exists {
            fs::remove_file(&previous).map_err(|source| {
                PersistenceError::io("remove stale previous state", &previous, source)
            })?;
        }
        return Ok(());
    }
    if destination_exists {
        if previous_exists {
            fs::remove_file(&previous).map_err(|source| {
                PersistenceError::io("finalize previous state", &previous, source)
            })?;
        }
    } else if previous_exists {
        fs::rename(&previous, destination).map_err(|source| {
            PersistenceError::io("recover interrupted state at", destination, source)
        })?;
    }
    fs::remove_file(&transaction)
        .map_err(|source| PersistenceError::io("finish state transaction", transaction, source))
}

#[cfg(not(windows))]
fn recover_previous_if_needed(destination: &Path) -> Result<(), PersistenceError> {
    match destination.parent() {
        Some(_) => Ok(()),
        None => Err(PersistenceError::io(
            "inspect",
            destination,
            io::Error::new(io::ErrorKind::InvalidInput, "state path has no parent"),
        )),
    }
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

fn sha256_hex(bytes: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let bit_len = u64::try_from(bytes.len())
        .expect("scope identifiers fit in u64")
        .saturating_mul(8);
    let mut padded = Vec::with_capacity(bytes.len().saturating_add(72));
    padded.extend_from_slice(bytes);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(
                bytes
                    .try_into()
                    .expect("SHA-256 input words contain exactly four bytes"),
            );
        }
        for index in 16..64 {
            let small_zero = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let small_one = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(small_zero)
                .wrapping_add(words[index - 7])
                .wrapping_add(small_one);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let big_one = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temporary_one = h
                .wrapping_add(big_one)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let big_zero = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary_two = big_zero.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary_one);
            d = c;
            c = b;
            b = a;
            a = temporary_one.wrapping_add(temporary_two);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digest = String::with_capacity(64);
    for word in state {
        for byte in word.to_be_bytes() {
            digest.push(char::from(HEX[usize::from(byte >> 4)]));
            digest.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_standard_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn scoped_paths_are_stable_and_do_not_expose_the_scope() {
        let scope = crate::session::SessionId::new("private-conversation").expect("valid scope");
        let path = scoped_state_path(Path::new("state"), "memory", &scope);
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("UTF-8 file name");
        assert_eq!(file_name.len(), 69);
        assert!(file_name.ends_with(".json"));
        assert!(!file_name.contains(scope.as_str()));
    }
}

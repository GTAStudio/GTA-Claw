//! Scoped, size-bounded JSON persistence primitives.

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
use sha2::{Digest, Sha256};

static FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static SCOPE_LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();

const MAX_DIRECTORY_SCAN_ENTRIES: usize = 200_000;

/// Successful durable-write result, including non-fatal post-publication warnings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WriteOutcome {
    /// Cleanup or durability limitations observed after new bytes were published.
    pub warnings: Vec<WriteWarning>,
}

/// A non-fatal condition discovered after durable-state publication succeeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteWarning {
    /// Windows committed new bytes but could not remove replacement artifacts.
    CleanupDeferred {
        /// Artifacts intentionally retained for next-access recovery.
        artifacts: Vec<PathBuf>,
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
        /// Observed or lower-bound serialized byte length.
        size: usize,
        /// Maximum permitted byte length.
        limit: usize,
    },
    /// A directory scan reached its explicit work bound.
    DirectoryScanLimitExceeded {
        /// Directory whose entries were being inspected.
        path: PathBuf,
        /// Maximum number of entries one operation will inspect.
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
                "durable state {} is at least {size} bytes, exceeding the {limit}-byte structural limit",
                path.display()
            ),
            Self::DirectoryScanLimitExceeded { path, limit } => write!(
                formatter,
                "durable state directory {} exceeds the {limit}-entry scan limit",
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
            Self::Corrupt { .. }
            | Self::StateTooLarge { .. }
            | Self::DirectoryScanLimitExceeded { .. }
            | Self::LockPoisoned => None,
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
    let lock_path = prepare_lock_path(&state_path.with_extension("lock"))?;
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

fn has_root_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::RootDir))
}

pub(crate) fn initialize_state_root(root: &Path) -> Result<PathBuf, PersistenceError> {
    let root = absolute_lexical_path(root)?;
    let mut existing = root.as_path();
    let mut missing = Vec::new();

    loop {
        match fs::symlink_metadata(existing) {
            Ok(metadata) => {
                if missing.is_empty() && is_link_or_reparse(&metadata) {
                    return Err(PersistenceError::io(
                        "prepare",
                        &root,
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "configured durable root must not be a link",
                        ),
                    ));
                }
                let target_metadata = if is_link_or_reparse(&metadata) {
                    fs::metadata(existing).map_err(|source| {
                        PersistenceError::io("inspect ambient root ancestor", existing, source)
                    })?
                } else {
                    metadata
                };
                if !target_metadata.is_dir() {
                    return Err(PersistenceError::io(
                        "prepare",
                        existing,
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "durable root ancestor must be a directory",
                        ),
                    ));
                }
                break;
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let component = existing.file_name().ok_or_else(|| {
                    PersistenceError::io(
                        "prepare",
                        &root,
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "durable root has no existing directory ancestor",
                        ),
                    )
                })?;
                missing.push(component.to_os_string());
                existing = existing.parent().ok_or_else(|| {
                    PersistenceError::io(
                        "prepare",
                        &root,
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "durable root has no existing directory ancestor",
                        ),
                    )
                })?;
            }
            Err(source) => {
                return Err(PersistenceError::io(
                    "inspect durable root ancestor",
                    existing,
                    source,
                ));
            }
        }
    }

    let mut canonical = fs::canonicalize(existing).map_err(|source| {
        PersistenceError::io("canonicalize durable root ancestor", existing, source)
    })?;
    reject_unsafe_ancestors(&canonical)?;
    for component in missing.iter().rev() {
        canonical.push(component);
        match fs::create_dir(&canonical) {
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(PersistenceError::io(
                    "create durable state directory",
                    &canonical,
                    source,
                ));
            }
        }
        let metadata = fs::symlink_metadata(&canonical).map_err(|source| {
            PersistenceError::io("inspect durable state directory", &canonical, source)
        })?;
        if is_link_or_reparse(&metadata) || !metadata.is_dir() {
            return Err(PersistenceError::io(
                "prepare",
                &canonical,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "durable state directory must be a real directory",
                ),
            ));
        }
    }
    reject_unsafe_ancestors(&canonical)?;
    Ok(canonical)
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
    let digest = Sha256::digest(scope.as_str().as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn generated_ordinal(id: &crate::vector::RecordId, prefix: &str) -> Option<u64> {
    let encoded = id.as_str().strip_prefix(prefix)?;
    if encoded.len() != 16
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    u64::from_str_radix(encoded, 16).ok()
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
    if is_link_or_reparse(&metadata) || !metadata.is_file() || has_multiple_links(&path, &metadata)?
    {
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
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(max_bytes)
            .min(max_bytes)
            .min(8 * 1024),
    );
    file.take(max_u64.saturating_add(1))
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
) -> Result<WriteOutcome, PersistenceError> {
    let destination = prepare_destination(path)?;
    recover_previous_if_needed(&destination)?;
    let mut writer = BoundedJsonWriter::new(max_bytes);
    let serialized = serde_json::to_writer_pretty(&mut writer, value);
    if writer.overflowed {
        return Err(PersistenceError::StateTooLarge {
            path: destination,
            size: writer.attempted_size,
            limit: max_bytes,
        });
    }
    serialized.map_err(|source| PersistenceError::Serialization {
        path: destination.clone(),
        source,
    })?;
    if writer.bytes.len() >= max_bytes {
        return Err(PersistenceError::StateTooLarge {
            path: destination,
            size: writer.bytes.len().saturating_add(1),
            limit: max_bytes,
        });
    }
    writer.bytes.push(b'\n');

    let existing = match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if is_link_or_reparse(&metadata)
                || !metadata.is_file()
                || has_multiple_links(&destination, &metadata)?
            {
                return Err(PersistenceError::corrupt(
                    &destination,
                    "destination is not a single-link regular file",
                ));
            }
            Some(metadata)
        }
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
        file.write_all(&writer.bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|source| PersistenceError::io("write", temporary.path(), source))?;
        drop(file);
        let mut warnings = Vec::new();
        if let Some(warning) =
            replace_destination(temporary.path(), &destination, existing.is_some())
                .map_err(|source| PersistenceError::io("publish", &destination, source))?
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
            Err(cleanup_error) => Err(PersistenceError::io(
                "clean temporary file after failed write to",
                &destination,
                cleanup_error,
            )),
        },
    }
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
    attempted_size: usize,
    overflowed: bool,
}

impl BoundedJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(8 * 1024)),
            limit,
            attempted_size: 0,
            overflowed: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.attempted_size = self.bytes.len().saturating_add(buffer.len());
        if buffer.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.overflowed = true;
            return Err(io::Error::other("serialized JSON exceeds its byte limit"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
            if is_link_or_reparse(&metadata)
                || !metadata.is_file()
                || has_multiple_links(&destination, &metadata)?
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
            "state parent resolved outside its canonical durable root",
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
        if !has_root_component(&current) {
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
        if ancestor.as_os_str().is_empty() || !has_root_component(ancestor) {
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
    if is_link_or_reparse(&metadata) || !metadata.is_file() || has_multiple_links(path, &metadata)?
    {
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
    if is_link_or_reparse(&path_metadata)
        || !path_metadata.is_file()
        || has_multiple_links(path, &path_metadata)?
        || !file_metadata.is_file()
        || opened_file_has_multiple_links(path, file, &file_metadata)?
        || !opened_file_matches(path, &path_metadata, file, &file_metadata)?
    {
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
fn has_multiple_links(_path: &Path, metadata: &fs::Metadata) -> Result<bool, PersistenceError> {
    use std::os::unix::fs::MetadataExt;

    Ok(metadata.nlink() > 1)
}

#[cfg(unix)]
fn opened_file_has_multiple_links(
    _path: &Path,
    _file: &File,
    metadata: &fs::Metadata,
) -> Result<bool, PersistenceError> {
    use std::os::unix::fs::MetadataExt;

    Ok(metadata.nlink() > 1)
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn has_multiple_links(path: &Path, _metadata: &fs::Metadata) -> Result<bool, PersistenceError> {
    let file = File::open(path)
        .map_err(|source| PersistenceError::io("open for link check", path, source))?;
    let information = winapi_util::file::information(&file)
        .map_err(|source| PersistenceError::io("inspect link count for", path, source))?;
    Ok(information.number_of_links() > 1)
}

#[cfg(windows)]
fn opened_file_has_multiple_links(
    path: &Path,
    file: &File,
    _metadata: &fs::Metadata,
) -> Result<bool, PersistenceError> {
    let information = winapi_util::file::information(file)
        .map_err(|source| PersistenceError::io("inspect open-file link count for", path, source))?;
    Ok(information.number_of_links() > 1)
}

#[cfg(not(any(unix, windows)))]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(not(any(unix, windows)))]
fn has_multiple_links(_path: &Path, _metadata: &fs::Metadata) -> Result<bool, PersistenceError> {
    Ok(false)
}

#[cfg(not(any(unix, windows)))]
fn opened_file_has_multiple_links(
    _path: &Path,
    _file: &File,
    _metadata: &fs::Metadata,
) -> Result<bool, PersistenceError> {
    Ok(false)
}

#[cfg(unix)]
fn opened_file_matches(
    _path: &Path,
    path_metadata: &fs::Metadata,
    _file: &File,
    file_metadata: &fs::Metadata,
) -> Result<bool, PersistenceError> {
    use std::os::unix::fs::MetadataExt;

    Ok(path_metadata.dev() == file_metadata.dev() && path_metadata.ino() == file_metadata.ino())
}

#[cfg(windows)]
fn opened_file_matches(
    path: &Path,
    _path_metadata: &fs::Metadata,
    file: &File,
    _file_metadata: &fs::Metadata,
) -> Result<bool, PersistenceError> {
    let path_file = File::open(path)
        .map_err(|source| PersistenceError::io("reopen for identity check", path, source))?;
    let path_information = winapi_util::file::information(&path_file)
        .map_err(|source| PersistenceError::io("inspect path identity for", path, source))?;
    let file_information = winapi_util::file::information(file)
        .map_err(|source| PersistenceError::io("inspect open-file identity for", path, source))?;
    Ok(
        path_information.volume_serial_number() == file_information.volume_serial_number()
            && path_information.file_index() == file_information.file_index(),
    )
}

#[cfg(not(any(unix, windows)))]
fn opened_file_matches(
    _path: &Path,
    _path_metadata: &fs::Metadata,
    _file: &File,
    _file_metadata: &fs::Metadata,
) -> Result<bool, PersistenceError> {
    Ok(true)
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
    let mut scanned = 0_usize;
    for entry in
        fs::read_dir(parent).map_err(|source| PersistenceError::io("scan", parent, source))?
    {
        scanned = scanned.saturating_add(1);
        if scanned > MAX_DIRECTORY_SCAN_ENTRIES {
            return Err(PersistenceError::DirectoryScanLimitExceeded {
                path: parent.to_owned(),
                limit: MAX_DIRECTORY_SCAN_ENTRIES,
            });
        }
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
    replace_destination_with_cleanup(temporary, destination, exists, |path| fs::remove_file(path))
}

#[cfg(windows)]
fn replace_destination_with_cleanup(
    temporary: &Path,
    destination: &Path,
    exists: bool,
    mut cleanup: impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<Option<WriteWarning>> {
    if !exists {
        fs::rename(temporary, destination)?;
        return Ok(None);
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
            if let Err(error) = cleanup(&previous) {
                return Ok(Some(WriteWarning::CleanupDeferred {
                    artifacts: vec![previous, transaction],
                    message: error.to_string(),
                }));
            }
            if let Err(error) = cleanup(&transaction) {
                return Ok(Some(WriteWarning::CleanupDeferred {
                    artifacts: vec![transaction],
                    message: error.to_string(),
                }));
            }
            Ok(None)
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
        Ok(metadata) => {
            if is_link_or_reparse(&metadata)
                || !metadata.is_file()
                || has_multiple_links(path, &metadata)?
            {
                return Err(PersistenceError::io(
                    "inspect recovery artifact",
                    path,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "recovery artifact must be a single-link regular file",
                    ),
                ));
            }
            Ok(true)
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_directory(label: &str) -> Cleanup {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "claw-memory-persistence-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        Cleanup(fs::canonicalize(path).expect("canonicalize test directory"))
    }

    #[test]
    fn scope_hash_matches_the_standard_sha256_vector() {
        let scope = crate::SessionId::new("abc").expect("valid scope");
        assert_eq!(
            scope_key(&scope),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn scoped_paths_are_stable_and_do_not_expose_the_scope() {
        let scope = crate::SessionId::new("private-conversation").expect("valid scope");
        let path = scoped_state_path(Path::new("state"), "memory", &scope);
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("UTF-8 file name");
        assert_eq!(file_name.len(), 69);
        assert!(file_name.ends_with(".json"));
        assert!(!file_name.contains(scope.as_str()));
    }

    #[test]
    fn serialization_stops_at_the_configured_bound() {
        let cleanup = test_directory("bounded-write");
        let path = cleanup.0.join("state.json");
        let error = atomic_write_json(&path, &"x".repeat(1_000), 64)
            .expect_err("oversized state is rejected");
        let PersistenceError::StateTooLarge { size, limit, .. } = error else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(limit, 64);
        assert!(size > limit);
        assert!(!path.exists());
    }

    #[test]
    fn reads_reject_files_over_the_outer_bound_before_decode() {
        let cleanup = test_directory("bounded-read");
        let path = cleanup.0.join("state.json");
        fs::write(&path, br#"{"value":"too long"}"#).expect("write state");
        let error =
            read_json::<serde_json::Value>(&path, 8).expect_err("oversized input is rejected");
        assert!(matches!(error, PersistenceError::Corrupt { .. }));
    }
}

#[cfg(test)]
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::File;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use sha2::{Digest as _, Sha256};

use crate::StateError;
use crate::protected_catalog::{
    self, CatalogIdentity, METADATA_LEN, PublicationPlan, RecoveredSnapshot, SELECTOR_CELL_LEN,
    SELECTOR_LEN, SlotObservation,
};

pub(crate) const DATABASE_NAME: &str = "state.sqlite";
pub(crate) const WAL_NAME: &str = "state.sqlite-wal";
pub(crate) const WRITER_LOCK_NAME: &str = "state.writer.lock";
pub(crate) const SNAPSHOT_DATA_NAMES: [&str; 2] = ["snapshot-0.sqlite", "snapshot-1.sqlite"];
pub(crate) const SNAPSHOT_METADATA_NAMES: [&str; 2] = ["snapshot-0.meta", "snapshot-1.meta"];
pub(crate) const SELECTOR_NAME: &str = "snapshot.selector";
pub(crate) const ENTRY_NAMES: [&str; 8] = [
    DATABASE_NAME,
    WAL_NAME,
    WRITER_LOCK_NAME,
    SNAPSHOT_DATA_NAMES[0],
    SNAPSHOT_METADATA_NAMES[0],
    SNAPSHOT_DATA_NAMES[1],
    SNAPSHOT_METADATA_NAMES[1],
    SELECTOR_NAME,
];

const DATABASE_INDEX: usize = 0;
const WAL_INDEX: usize = 1;
const WRITER_LOCK_INDEX: usize = 2;
const SLOT_DATA_INDEX: [usize; 2] = [3, 5];
const SLOT_METADATA_INDEX: [usize; 2] = [4, 6];
const SELECTOR_INDEX: usize = 7;

const EXT_FAMILY_MAGIC: u64 = 0x0000_ef53;
const XFS_MAGIC: u64 = 0x5846_5342;
const BTRFS_MAGIC: u64 = 0x9123_683e;
const F2FS_MAGIC: u64 = 0xf2f5_2010;

#[cfg(test)]
static SCRUB_TEST_FAILURES: std::sync::LazyLock<Mutex<HashMap<PathBuf, usize>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
#[cfg(test)]
struct ProtectedIoTestGate {
    stage: u8,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(test)]
static PROTECTED_IO_TEST_GATES: std::sync::LazyLock<Mutex<HashMap<PathBuf, ProtectedIoTestGate>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Debug)]
pub(crate) struct LinuxProtectedSpec {
    directory: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
}

impl LinuxProtectedSpec {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(directory: PathBuf, expected_uid: u32, expected_gid: u32) -> Self {
        Self {
            directory,
            expected_uid,
            expected_gid,
        }
    }

    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    special_device: u64,
}

impl FileIdentity {
    fn capture(path: &Path, file: &File, operation: &'static str) -> Result<Self, StateError> {
        let metadata = file
            .metadata()
            .map_err(|error| file_error(operation, path, error))?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.nlink(),
            special_device: metadata.rdev(),
        })
    }
}

struct HeldEntry {
    name: &'static str,
    path: PathBuf,
    file: File,
    identity: FileIdentity,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct ProtectedNamespace {
    directory: PathBuf,
    parent: File,
    parent_identity: FileIdentity,
    entries: [HeldEntry; 8],
    expected_uid: u32,
    expected_gid: u32,
    publication_gate: Arc<tokio::sync::Mutex<()>>,
    repository_admission: Arc<tokio::sync::Semaphore>,
    observed_generation: Mutex<Option<u64>>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ProtectedNamespace {
    pub(crate) fn open(spec: &LinuxProtectedSpec) -> Result<Arc<Self>, StateError> {
        validate_spec(spec)?;
        validate_service_credentials(spec)?;
        validate_ancestors(&spec.directory)?;
        let parent = rustix::fs::open(
            &spec.directory,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            file_error(
                "open LinuxProtected directory",
                &spec.directory,
                error.into(),
            )
        })?;
        let parent_identity =
            FileIdentity::capture(&spec.directory, &parent, "inspect LinuxProtected directory")?;
        validate_parent(spec, &parent, parent_identity)?;
        validate_filesystem(&spec.directory, &parent)?;
        validate_exact_names(&spec.directory)?;

        let mut entries = Vec::with_capacity(ENTRY_NAMES.len());
        for name in ENTRY_NAMES {
            let path = spec.directory.join(name);
            let file = rustix::fs::openat(
                &parent,
                name,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .map(File::from)
            .map_err(|error| file_error("open LinuxProtected entry", &path, error.into()))?;
            let identity =
                FileIdentity::capture(&path, &file, "inspect LinuxProtected entry identity")?;
            validate_entry(spec, parent_identity.device, &path, &file, identity)?;
            entries.push(HeldEntry {
                name,
                path,
                file,
                identity,
            });
        }
        let entries: [HeldEntry; 8] = entries
            .try_into()
            .unwrap_or_else(|_| unreachable!("the fixed namespace has eight entries"));
        let mut identities = HashSet::with_capacity(entries.len());
        for entry in &entries {
            if !identities.insert((entry.identity.device, entry.identity.inode)) {
                return Err(invalid_path(
                    &entry.path,
                    "LinuxProtected entries must have distinct file identities",
                ));
            }
        }
        validate_catalog_lengths(&entries)?;

        let namespace = Arc::new(Self {
            directory: spec.directory.clone(),
            parent,
            parent_identity,
            entries,
            expected_uid: spec.expected_uid,
            expected_gid: spec.expected_gid,
            publication_gate: Arc::new(tokio::sync::Mutex::new(())),
            repository_admission: Arc::new(tokio::sync::Semaphore::new(1)),
            observed_generation: Mutex::new(None),
        });
        namespace.verify()?;
        Ok(namespace)
    }

    pub(crate) fn directory_path(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn database_path(&self) -> &Path {
        &self.entries[DATABASE_INDEX].path
    }

    pub(crate) fn writer_lock_path(&self) -> &Path {
        &self.entries[WRITER_LOCK_INDEX].path
    }

    pub(crate) fn slot_path(&self, slot: u8) -> &Path {
        &self.entries[SLOT_DATA_INDEX[usize::from(slot)]].path
    }

    pub(crate) fn selector_path(&self) -> &Path {
        &self.entries[SELECTOR_INDEX].path
    }

    pub(crate) fn clone_parent(&self) -> Result<File, StateError> {
        clone_file(
            &self.parent,
            &self.directory,
            "clone LinuxProtected directory handle",
        )
    }

    pub(crate) fn clone_database(&self) -> Result<File, StateError> {
        self.clone_entry(DATABASE_INDEX, "clone LinuxProtected database handle")
    }

    pub(crate) fn clone_writer_lock(&self) -> Result<File, StateError> {
        self.clone_entry(WRITER_LOCK_INDEX, "clone LinuxProtected writer-lock handle")
    }

    pub(crate) fn clone_slot(&self, slot: u8) -> Result<File, StateError> {
        self.clone_entry(
            SLOT_DATA_INDEX[usize::from(slot)],
            "clone LinuxProtected snapshot slot handle",
        )
    }

    pub(crate) fn writer_owner(&self) -> String {
        let database = self.entries[DATABASE_INDEX].identity;
        let writer = self.entries[WRITER_LOCK_INDEX].identity;
        format!(
            "linux-protected-v1:{}:{}:{}:{}:1",
            database.device, database.inode, writer.device, writer.inode
        )
    }

    pub(crate) fn catalog_identity(&self, writer_generation: u64) -> CatalogIdentity {
        let database = self.entries[DATABASE_INDEX].identity;
        let writer = self.entries[WRITER_LOCK_INDEX].identity;
        CatalogIdentity {
            database_device: database.device,
            database_inode: database.inode,
            writer_device: writer.device,
            writer_inode: writer.inode,
            writer_generation,
        }
    }

    pub(crate) fn publication_gate(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.publication_gate)
    }

    pub(crate) fn repository_admission(&self) -> Arc<tokio::sync::Semaphore> {
        Arc::clone(&self.repository_admission)
    }

    pub(crate) fn verify(&self) -> Result<(), StateError> {
        let spec = LinuxProtectedSpec {
            directory: self.directory.clone(),
            expected_uid: self.expected_uid,
            expected_gid: self.expected_gid,
        };
        validate_service_credentials(&spec)?;
        validate_ancestors(&self.directory)?;
        validate_parent(&spec, &self.parent, self.parent_identity)?;
        validate_filesystem(&self.directory, &self.parent)?;
        let current_parent = rustix::fs::open(
            &self.directory,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            file_error(
                "reopen LinuxProtected directory",
                &self.directory,
                error.into(),
            )
        })?;
        let current_parent_identity = FileIdentity::capture(
            &self.directory,
            &current_parent,
            "reinspect LinuxProtected directory",
        )?;
        if current_parent_identity != self.parent_identity {
            return Err(invalid_path(
                &self.directory,
                "LinuxProtected directory path no longer names the held directory",
            ));
        }
        validate_exact_names(&self.directory)?;
        let mut identities = HashSet::with_capacity(self.entries.len());
        for entry in &self.entries {
            let held = FileIdentity::capture(
                &entry.path,
                &entry.file,
                "reinspect held LinuxProtected entry",
            )?;
            if held != entry.identity {
                return Err(invalid_path(
                    &entry.path,
                    "held LinuxProtected entry identity or security changed",
                ));
            }
            validate_entry(
                &spec,
                self.parent_identity.device,
                &entry.path,
                &entry.file,
                held,
            )?;
            let reopened = rustix::fs::openat(
                &self.parent,
                entry.name,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .map(File::from)
            .map_err(|error| {
                file_error(
                    "reopen LinuxProtected entry relative to held directory",
                    &entry.path,
                    error.into(),
                )
            })?;
            let reopened_identity = FileIdentity::capture(
                &entry.path,
                &reopened,
                "reinspect LinuxProtected path identity",
            )?;
            if reopened_identity != entry.identity {
                return Err(invalid_path(
                    &entry.path,
                    "LinuxProtected entry path no longer names the held file",
                ));
            }
            if !identities.insert((held.device, held.inode)) {
                return Err(invalid_path(
                    &entry.path,
                    "LinuxProtected entries no longer have distinct identities",
                ));
            }
        }
        validate_catalog_lengths(&self.entries)?;
        let final_parent = rustix::fs::open(
            &self.directory,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            file_error(
                "finally reopen LinuxProtected directory",
                &self.directory,
                error.into(),
            )
        })?;
        if FileIdentity::capture(
            &self.directory,
            &final_parent,
            "finally reinspect LinuxProtected directory",
        )? != self.parent_identity
        {
            return Err(invalid_path(
                &self.directory,
                "LinuxProtected directory changed during namespace verification",
            ));
        }
        Ok(())
    }

    pub(crate) fn recover_catalog(
        &self,
        expected_identity: CatalogIdentity,
        cutoff: Option<Instant>,
        cancelled: Option<&std::sync::atomic::AtomicBool>,
        timeout_ms: u64,
    ) -> Result<Option<RecoveredSnapshot>, StateError> {
        self.verify()?;
        check_cutoff(self.selector_path(), cutoff, cancelled, timeout_ms)?;
        let selector =
            self.read_entry(SELECTOR_INDEX, SELECTOR_LEN, cutoff, cancelled, timeout_ms)?;
        let metadata_zero = self.read_entry(
            SLOT_METADATA_INDEX[0],
            METADATA_LEN,
            cutoff,
            cancelled,
            timeout_ms,
        )?;
        let metadata_one = self.read_entry(
            SLOT_METADATA_INDEX[1],
            METADATA_LEN,
            cutoff,
            cancelled,
            timeout_ms,
        )?;
        let slots = [
            self.slot_observation(0, cutoff, cancelled, timeout_ms)?,
            self.slot_observation(1, cutoff, cancelled, timeout_ms)?,
        ];
        let recovered = protected_catalog::recover(
            &selector,
            [&metadata_zero, &metadata_one],
            slots,
            expected_identity,
        )
        .map_err(|error| catalog_error(self.selector_path(), error.reason()))?;
        {
            let mut observed = self.observed_generation.lock().map_err(|_| {
                invalid_path(self.selector_path(), "snapshot generation lock poisoned")
            })?;
            let recovered_generation = recovered.map(|snapshot| snapshot.metadata.generation);
            if observed.is_some() && recovered_generation < *observed {
                return Err(catalog_error(
                    self.selector_path(),
                    "snapshot selector generation rolled back during the store lifetime",
                ));
            }
            if recovered_generation > *observed {
                *observed = recovered_generation;
            }
        }
        check_cutoff(self.selector_path(), cutoff, cancelled, timeout_ms)?;
        self.verify()?;
        Ok(recovered)
    }

    pub(crate) fn publication_plan(
        &self,
        current: Option<RecoveredSnapshot>,
    ) -> Result<PublicationPlan, StateError> {
        protected_catalog::publication_plan(current)
            .map_err(|error| catalog_error(self.selector_path(), error.reason()))
    }

    pub(crate) fn scrub_slot(&self, slot: u8) -> Result<(), StateError> {
        self.verify()?;
        #[cfg(test)]
        wait_at_protected_io_test_gate(&self.directory, 1);
        #[cfg(test)]
        {
            let mut failures = SCRUB_TEST_FAILURES
                .lock()
                .expect("protected scrub failure map lock poisoned");
            if let Some(remaining) = failures.get_mut(&self.directory) {
                *remaining = remaining.saturating_sub(1);
                if *remaining == 0 {
                    failures.remove(&self.directory);
                }
                return Err(file_error(
                    "scrub LinuxProtected snapshot slot",
                    self.slot_path(slot),
                    std::io::Error::other("injected protected snapshot scrub failure"),
                ));
            }
        }
        for index in [
            SLOT_DATA_INDEX[usize::from(slot)],
            SLOT_METADATA_INDEX[usize::from(slot)],
        ] {
            let entry = &self.entries[index];
            entry
                .file
                .set_len(0)
                .and_then(|()| entry.file.sync_all())
                .map_err(|error| {
                    file_error("scrub LinuxProtected snapshot slot", &entry.path, error)
                })?;
        }
        self.verify()
    }

    #[cfg(test)]
    pub(crate) fn fail_next_scrub(&self) {
        SCRUB_TEST_FAILURES
            .lock()
            .expect("protected scrub failure map lock poisoned")
            .insert(self.directory.clone(), 1);
    }

    pub(crate) fn verify_slot(
        &self,
        slot: u8,
        expected: SlotObservation,
        cutoff: Option<Instant>,
        cancelled: Option<&std::sync::atomic::AtomicBool>,
        timeout_ms: u64,
    ) -> Result<(), StateError> {
        self.verify()?;
        let observed = self.slot_observation(slot, cutoff, cancelled, timeout_ms)?;
        if observed != expected {
            return Err(catalog_error(
                self.slot_path(slot),
                "held snapshot slot failed exact byte-length and digest verification",
            ));
        }
        self.verify()
    }

    pub(crate) fn write_metadata(
        &self,
        slot: u8,
        metadata: &[u8; METADATA_LEN],
    ) -> Result<(), StateError> {
        self.verify()?;
        let index = SLOT_METADATA_INDEX[usize::from(slot)];
        let entry = &self.entries[index];
        entry
            .file
            .set_len(0)
            .map_err(|error| file_error("truncate snapshot metadata", &entry.path, error))?;
        #[cfg(test)]
        wait_at_protected_io_test_gate(&self.directory, 2);
        write_all_at(&entry.file, metadata, 0)
            .and_then(|()| entry.file.sync_all())
            .map_err(|error| file_error("write and sync snapshot metadata", &entry.path, error))?;
        let reread = self.read_entry(index, METADATA_LEN, None, None, 0)?;
        if reread.as_slice() != metadata {
            return Err(catalog_error(
                &entry.path,
                "snapshot metadata failed exact held-handle reread",
            ));
        }
        self.verify()
    }

    pub(crate) fn commit_selector_cell(
        &self,
        cell: u8,
        encoded: &[u8; SELECTOR_CELL_LEN],
    ) -> Result<(), StateError> {
        self.verify()?;
        let entry = &self.entries[SELECTOR_INDEX];
        if entry
            .file
            .metadata()
            .map_err(|error| file_error("inspect snapshot selector", &entry.path, error))?
            .len()
            != SELECTOR_LEN as u64
        {
            return Err(catalog_error(
                &entry.path,
                "snapshot selector changed from its fixed length before commit",
            ));
        }
        let offset = u64::from(cell) * SELECTOR_CELL_LEN as u64;
        write_all_at(&entry.file, encoded, offset)
            .and_then(|()| entry.file.sync_all())
            .map_err(|error| file_error("commit snapshot selector cell", &entry.path, error))?;
        self.verify()
    }

    fn clone_entry(&self, index: usize, operation: &'static str) -> Result<File, StateError> {
        clone_file(
            &self.entries[index].file,
            &self.entries[index].path,
            operation,
        )
    }

    fn read_entry(
        &self,
        index: usize,
        maximum: usize,
        cutoff: Option<Instant>,
        cancelled: Option<&std::sync::atomic::AtomicBool>,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, StateError> {
        let entry = &self.entries[index];
        let length = entry
            .file
            .metadata()
            .map_err(|error| file_error("inspect LinuxProtected entry length", &entry.path, error))?
            .len();
        let length = usize::try_from(length).map_err(|_| {
            catalog_error(
                &entry.path,
                "LinuxProtected entry length does not fit memory bounds",
            )
        })?;
        if length > maximum {
            return Err(catalog_error(
                &entry.path,
                "LinuxProtected entry exceeds its fixed format bound",
            ));
        }
        let mut bytes = vec![0_u8; length];
        read_exact_at(
            &entry.file,
            &mut bytes,
            0,
            &entry.path,
            cutoff,
            cancelled,
            timeout_ms,
        )?;
        if entry
            .file
            .metadata()
            .map_err(|error| {
                file_error("reinspect LinuxProtected entry length", &entry.path, error)
            })?
            .len()
            != length as u64
        {
            return Err(catalog_error(
                &entry.path,
                "LinuxProtected entry length changed during held-handle read",
            ));
        }
        Ok(bytes)
    }

    fn slot_observation(
        &self,
        slot: u8,
        cutoff: Option<Instant>,
        cancelled: Option<&std::sync::atomic::AtomicBool>,
        timeout_ms: u64,
    ) -> Result<SlotObservation, StateError> {
        let entry = &self.entries[SLOT_DATA_INDEX[usize::from(slot)]];
        let length = entry
            .file
            .metadata()
            .map_err(|error| file_error("inspect snapshot slot length", &entry.path, error))?
            .len();
        if length > protected_catalog::MAX_SNAPSHOT_BYTES {
            return Err(catalog_error(
                &entry.path,
                "snapshot slot exceeds the bounded catalog size",
            ));
        }
        let mut hasher = Sha256::new();
        let mut offset = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        while offset < length {
            check_cutoff(&entry.path, cutoff, cancelled, timeout_ms)?;
            let remaining = usize::try_from((length - offset).min(buffer.len() as u64))
                .expect("bounded read length fits usize");
            let read = entry
                .file
                .read_at(&mut buffer[..remaining], offset)
                .map_err(|error| file_error("read held snapshot slot", &entry.path, error))?;
            if read == 0 {
                return Err(catalog_error(
                    &entry.path,
                    "snapshot slot ended before its held length",
                ));
            }
            hasher.update(&buffer[..read]);
            offset = offset.checked_add(read as u64).ok_or_else(|| {
                catalog_error(&entry.path, "snapshot slot digest offset overflowed")
            })?;
        }
        if entry
            .file
            .metadata()
            .map_err(|error| file_error("reinspect snapshot slot length", &entry.path, error))?
            .len()
            != length
        {
            return Err(catalog_error(
                &entry.path,
                "snapshot slot length changed during digest verification",
            ));
        }
        Ok(SlotObservation {
            byte_length: length,
            digest: hasher.finalize().into(),
        })
    }
}

pub(crate) const fn filesystem_magic_allowed(magic: u64) -> bool {
    matches!(
        magic,
        EXT_FAMILY_MAGIC | XFS_MAGIC | BTRFS_MAGIC | F2FS_MAGIC
    )
}

#[cfg(test)]
fn wait_at_protected_io_test_gate(directory: &Path, stage: u8) {
    let gate = PROTECTED_IO_TEST_GATES
        .lock()
        .expect("protected I/O test gate map lock poisoned")
        .get(directory)
        .filter(|gate| gate.stage == stage)
        .map(|gate| (Arc::clone(&gate.entered), Arc::clone(&gate.release)));
    let Some((entered, release)) = gate else {
        return;
    };
    entered.notify_one();
    while !release.load(std::sync::atomic::Ordering::Acquire) {
        std::thread::yield_now();
    }
    PROTECTED_IO_TEST_GATES
        .lock()
        .expect("protected I/O test gate map lock poisoned")
        .remove(directory);
}

fn validate_spec(spec: &LinuxProtectedSpec) -> Result<(), StateError> {
    if spec.expected_uid == 0 || spec.expected_gid == 0 {
        return Err(invalid_path(
            &spec.directory,
            "LinuxProtected service UID and GID must both be nonzero",
        ));
    }
    if !spec.directory.is_absolute() {
        return Err(invalid_path(
            &spec.directory,
            "LinuxProtected directory must be absolute",
        ));
    }
    if spec
        .directory
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid_path(
            &spec.directory,
            "LinuxProtected directory must not contain dot, parent, or prefix components",
        ));
    }
    Ok(())
}

fn validate_service_credentials(spec: &LinuxProtectedSpec) -> Result<(), StateError> {
    if rustix::process::getuid().as_raw() != spec.expected_uid
        || rustix::process::geteuid().as_raw() != spec.expected_uid
        || rustix::process::getgid().as_raw() != spec.expected_gid
        || rustix::process::getegid().as_raw() != spec.expected_gid
        || !rustix::process::getgroups()
            .map_err(|error| {
                file_error(
                    "inspect LinuxProtected supplementary groups",
                    &spec.directory,
                    error.into(),
                )
            })?
            .is_empty()
    {
        return Err(invalid_path(
            &spec.directory,
            "LinuxProtected expected service credentials do not match the process",
        ));
    }
    Ok(())
}

fn validate_parent(
    spec: &LinuxProtectedSpec,
    parent: &File,
    identity: FileIdentity,
) -> Result<(), StateError> {
    let is_directory = parent
        .metadata()
        .map_err(|error| {
            file_error(
                "inspect LinuxProtected directory type",
                &spec.directory,
                error,
            )
        })?
        .file_type()
        .is_dir();
    if !parent_identity_matches(spec, identity, is_directory) {
        return Err(invalid_path(
            &spec.directory,
            "LinuxProtected directory must be a root-owned, service-group mode 0750 directory",
        ));
    }
    if !claw_sqlite_file_control::unix_file_has_trivial_acl(parent).map_err(|_| {
        invalid_path(
            &spec.directory,
            "LinuxProtected directory ACL could not be validated",
        )
    })? {
        return Err(invalid_path(
            &spec.directory,
            "LinuxProtected directory must have a trivial ACL",
        ));
    }
    Ok(())
}

fn validate_ancestors(directory: &Path) -> Result<(), StateError> {
    for ancestor in directory.ancestors().skip(1) {
        let file = rustix::fs::open(
            ancestor,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| file_error("open LinuxProtected ancestor", ancestor, error.into()))?;
        let metadata = file
            .metadata()
            .map_err(|error| file_error("inspect LinuxProtected ancestor", ancestor, error))?;
        let mode = metadata.mode();
        if !metadata.file_type().is_dir()
            || metadata.uid() != 0
            || mode & 0o022 != 0
            || mode & 0o1000 != 0
        {
            return Err(invalid_path(
                ancestor,
                "LinuxProtected ancestors must be root-owned directories without group/other write or sticky bits",
            ));
        }
    }
    Ok(())
}

fn validate_filesystem(path: &Path, parent: &File) -> Result<(), StateError> {
    let filesystem = rustix::fs::fstatfs(parent)
        .map_err(|error| file_error("inspect LinuxProtected filesystem", path, error.into()))?;
    if !filesystem_magic_allowed(filesystem.f_type as u64) {
        return Err(invalid_path(
            path,
            "LinuxProtected filesystem type is not in the ext/XFS/Btrfs/F2FS allowlist",
        ));
    }
    Ok(())
}

fn validate_exact_names(directory: &Path) -> Result<(), StateError> {
    let mut names = std::fs::read_dir(directory)
        .map_err(|error| file_error("enumerate LinuxProtected directory", directory, error))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|error| file_error("read LinuxProtected entry name", directory, error))
        })
        .collect::<Result<Vec<OsString>, StateError>>()?;
    names.sort();
    let mut expected = ENTRY_NAMES.iter().map(OsString::from).collect::<Vec<_>>();
    expected.sort();
    if names != expected {
        return Err(invalid_path(
            directory,
            "LinuxProtected directory must contain exactly the eight fixed entries",
        ));
    }
    Ok(())
}

fn validate_entry(
    spec: &LinuxProtectedSpec,
    parent_device: u64,
    path: &Path,
    file: &File,
    identity: FileIdentity,
) -> Result<(), StateError> {
    let is_regular = file
        .metadata()
        .map_err(|error| file_error("inspect LinuxProtected entry type", path, error))?
        .file_type()
        .is_file();
    if !entry_identity_matches(spec, parent_device, identity, is_regular) {
        return Err(invalid_path(
            path,
            "LinuxProtected entries must be distinct same-device service-owned mode 0600 single-link regular files",
        ));
    }
    if !claw_sqlite_file_control::unix_file_is_service_private(file, spec.expected_uid, 0o600)
        .map_err(|_| invalid_path(path, "LinuxProtected entry ACL could not be validated"))?
    {
        return Err(invalid_path(
            path,
            "LinuxProtected entry must have a trivial service-private ACL",
        ));
    }
    Ok(())
}

fn parent_identity_matches(
    spec: &LinuxProtectedSpec,
    identity: FileIdentity,
    is_directory: bool,
) -> bool {
    is_directory
        && identity.uid == 0
        && identity.gid == spec.expected_gid
        && identity.mode & 0o7777 == 0o750
}

fn entry_identity_matches(
    spec: &LinuxProtectedSpec,
    parent_device: u64,
    identity: FileIdentity,
    is_regular: bool,
) -> bool {
    is_regular
        && identity.device == parent_device
        && identity.uid == spec.expected_uid
        && identity.gid == spec.expected_gid
        && identity.mode & 0o7777 == 0o600
        && identity.links == 1
}

fn validate_catalog_lengths(entries: &[HeldEntry; 8]) -> Result<(), StateError> {
    let database_length = entries[DATABASE_INDEX]
        .file
        .metadata()
        .map_err(|error| {
            file_error(
                "inspect preprovisioned database length",
                &entries[DATABASE_INDEX].path,
                error,
            )
        })?
        .len();
    if database_length == 0 {
        return Err(invalid_path(
            &entries[DATABASE_INDEX].path,
            "LinuxProtected database must be initialized offline before runtime open",
        ));
    }
    let writer_length = entries[WRITER_LOCK_INDEX]
        .file
        .metadata()
        .map_err(|error| {
            file_error(
                "inspect fixed writer lock length",
                &entries[WRITER_LOCK_INDEX].path,
                error,
            )
        })?
        .len();
    if writer_length != 0 {
        return Err(invalid_path(
            &entries[WRITER_LOCK_INDEX].path,
            "LinuxProtected fixed writer lock must have empty immutable identity contents",
        ));
    }

    let selector_length = entries[SELECTOR_INDEX]
        .file
        .metadata()
        .map_err(|error| {
            file_error(
                "inspect fixed selector length",
                &entries[SELECTOR_INDEX].path,
                error,
            )
        })?
        .len();
    if selector_length != SELECTOR_LEN as u64 {
        return Err(invalid_path(
            &entries[SELECTOR_INDEX].path,
            "LinuxProtected selector must be preprovisioned to its exact fixed length",
        ));
    }
    for index in SLOT_METADATA_INDEX {
        let length = entries[index]
            .file
            .metadata()
            .map_err(|error| {
                file_error(
                    "inspect snapshot metadata length",
                    &entries[index].path,
                    error,
                )
            })?
            .len();
        if length > METADATA_LEN as u64 {
            return Err(invalid_path(
                &entries[index].path,
                "LinuxProtected snapshot metadata exceeds its fixed format bound",
            ));
        }
    }
    for index in SLOT_DATA_INDEX {
        if entries[index]
            .file
            .metadata()
            .map_err(|error| {
                file_error("inspect snapshot slot length", &entries[index].path, error)
            })?
            .len()
            > protected_catalog::MAX_SNAPSHOT_BYTES
        {
            return Err(invalid_path(
                &entries[index].path,
                "LinuxProtected snapshot slot exceeds its fixed size bound",
            ));
        }
    }
    let _ = &entries[WAL_INDEX];
    Ok(())
}

fn read_exact_at(
    file: &File,
    mut output: &mut [u8],
    mut offset: u64,
    path: &Path,
    cutoff: Option<Instant>,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
    timeout_ms: u64,
) -> Result<(), StateError> {
    while !output.is_empty() {
        check_cutoff(path, cutoff, cancelled, timeout_ms)?;
        let read = file
            .read_at(output, offset)
            .map_err(|error| file_error("read LinuxProtected held file", path, error))?;
        if read == 0 {
            return Err(catalog_error(
                path,
                "LinuxProtected held file ended before its captured length",
            ));
        }
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| catalog_error(path, "LinuxProtected held-file offset overflowed"))?;
        output = &mut output[read..];
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn write_all_at(file: &File, mut bytes: &[u8], mut offset: u64) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let written = file.write_at(bytes, offset)?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "held-file write returned zero",
            ));
        }
        offset = offset
            .checked_add(written as u64)
            .ok_or_else(|| std::io::Error::other("held-file write offset overflowed"))?;
        bytes = &bytes[written..];
    }
    Ok(())
}

fn check_cutoff(
    path: &Path,
    cutoff: Option<Instant>,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
    timeout_ms: u64,
) -> Result<(), StateError> {
    if cancelled.is_some_and(|cancelled| cancelled.load(std::sync::atomic::Ordering::Acquire))
        || cutoff.is_some_and(|cutoff| Instant::now() >= cutoff)
    {
        return Err(StateError::OperationTimedOut {
            operation: "LinuxProtected snapshot catalog",
            timeout_ms,
        });
    }
    let _ = path;
    Ok(())
}

fn clone_file(file: &File, path: &Path, operation: &'static str) -> Result<File, StateError> {
    file.try_clone()
        .map_err(|error| file_error(operation, path, error))
}

fn invalid_path(path: &Path, reason: &'static str) -> StateError {
    StateError::InvalidPath {
        path: path.to_owned(),
        reason,
    }
}

fn catalog_error(path: &Path, reason: &'static str) -> StateError {
    StateError::InvalidBackup {
        path: path.to_owned(),
        reason: reason.to_owned(),
    }
}

fn file_error(operation: &'static str, path: &Path, error: std::io::Error) -> StateError {
    StateError::FileSystem {
        operation,
        path: path.to_owned(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{PermissionsExt as _, chown};
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Child, Command};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime};

    use claw_domain::SessionId;
    use sqlx::sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqliteSynchronous,
    };
    use sqlx::{Connection as _, SqliteConnection};

    use crate::repository::test_support as repository_test_support;
    use crate::store::test_support;
    use crate::{SessionRecord, StateStore, StoreConfig, TimestampMs, WriteOutcome};

    const ROOT_DRIVER_ENV: &str = "GTA_CLAW_LP2_ROOT_DRIVER";
    const SERVICE_CHILD_ENV: &str = "GTA_CLAW_LP2_SERVICE_CHILD";
    const NAMESPACE_ENV: &str = "GTA_CLAW_LP2_NAMESPACE";
    const READY_ENV: &str = "GTA_CLAW_LP2_READY";
    const CONTROL_ENV: &str = "GTA_CLAW_LP2_CONTROL";
    const NORMAL_CHILD: &str = "normal";
    const CRASH_CHILD: &str = "crash";
    const LOCK_PROBE_CHILD: &str = "lock-probe";
    const RECOVERY_CHILD: &str = "recovery";
    const RUNTIME_DROP_CHILD: &str = "runtime-drop";
    const GROUP_MISMATCH_CHILD: &str = "group-mismatch";
    const DEADLINE_CHILD: &str = "deadline";
    const REPOSITORY_OUTCOME_CHILD: &str = "repository-outcome";
    const REPOSITORY_TEMP_MARKER: &str = "lp2_post_fence_marker";
    const ROOT_TEST_NAME: &str =
        "linux_protected::tests::linux_protected_root_lifecycle_and_catalog";
    const SERVICE_UID: u32 = 65_534;
    const SERVICE_GID: u32 = 65_534;

    struct RootFixture {
        outer: PathBuf,
        namespace: PathBuf,
        ready: PathBuf,
        control: PathBuf,
    }

    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn new(child: Child) -> Self {
            Self(Some(child))
        }

        fn kill_and_wait(&mut self) {
            let mut child = self.0.take().expect("protected child remains owned");
            child.kill().expect("send SIGKILL to protected child");
            let status = child.wait().expect("reap protected child");
            assert_eq!(status.signal(), Some(9));
        }

        fn wait_success(&mut self, operation: &str) {
            let mut child = self.0.take().expect("protected child remains owned");
            let status = child.wait().expect("wait for protected child");
            assert!(status.success(), "{operation} failed with {status}");
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    impl Drop for RootFixture {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.outer, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.outer);
        }
    }

    fn exact_names(path: &Path) -> Vec<OsString> {
        let mut names = fs::read_dir(path)
            .expect("enumerate protected namespace fixture")
            .map(|entry| {
                entry
                    .expect("read protected namespace fixture entry")
                    .file_name()
            })
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn expected_names() -> Vec<OsString> {
        let mut names = ENTRY_NAMES.iter().map(OsString::from).collect::<Vec<_>>();
        names.sort();
        names
    }

    fn nontrivial_posix_acl(owner_permissions: u16, group_permissions: u16) -> Vec<u8> {
        let mut acl = 2_u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in [
            (0x01_u16, owner_permissions, u32::MAX),
            (0x02_u16, 0o4, 1),
            (0x04_u16, group_permissions, u32::MAX),
            (0x10_u16, group_permissions.max(0o4), u32::MAX),
            (0x20_u16, 0, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permissions.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        acl
    }

    fn entry_identities(path: &Path) -> Vec<(OsString, u64, u64)> {
        let mut identities = ENTRY_NAMES
            .iter()
            .map(|name| {
                let metadata = fs::symlink_metadata(path.join(name))
                    .unwrap_or_else(|error| panic!("inspect protected {name}: {error}"));
                (OsString::from(name), metadata.dev(), metadata.ino())
            })
            .collect::<Vec<_>>();
        identities.sort_by(|left, right| left.0.cmp(&right.0));
        identities
    }

    fn held_fixture_entries(path: &Path) -> [HeldEntry; 8] {
        ENTRY_NAMES.map(|name| {
            let entry_path = path.join(name);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&entry_path)
                .unwrap_or_else(|error| panic!("open fixture {name}: {error}"));
            let identity = FileIdentity::capture(&entry_path, &file, "inspect held fixture entry")
                .unwrap_or_else(|error| panic!("inspect fixture {name}: {error}"));
            HeldEntry {
                name,
                path: entry_path,
                file,
                identity,
            }
        })
    }

    fn install_protected_io_gate(
        namespace: &Path,
        stage: u8,
    ) -> (Arc<tokio::sync::Notify>, Arc<std::sync::atomic::AtomicBool>) {
        assert!((1..=2).contains(&stage));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let previous = PROTECTED_IO_TEST_GATES
            .lock()
            .expect("protected I/O test gate map lock poisoned")
            .insert(
                namespace.to_owned(),
                ProtectedIoTestGate {
                    stage,
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                },
            );
        assert!(previous.is_none(), "protected I/O gate is installed once");
        (entered, release)
    }

    fn assert_snapshot_receipt(namespace: &Path, receipt: &crate::store::ProtectedSnapshotReceipt) {
        let slot = usize::from(receipt.slot);
        let bytes = fs::read(namespace.join(SNAPSHOT_DATA_NAMES[slot]))
            .expect("read committed snapshot slot");
        assert_eq!(bytes.len() as u64, receipt.byte_count);
        assert_eq!(protected_catalog::digest(&bytes), receipt.digest);
        let metadata_bytes = fs::read(namespace.join(SNAPSHOT_METADATA_NAMES[slot]))
            .expect("read committed snapshot metadata");
        let metadata = protected_catalog::decode_metadata(&metadata_bytes)
            .expect("decode committed snapshot metadata")
            .expect("committed snapshot metadata is populated");
        assert_eq!(metadata.generation, receipt.generation);
        assert_eq!(metadata.slot, receipt.slot);
        assert_eq!(metadata.byte_length, receipt.byte_count);
        assert_eq!(metadata.digest, receipt.digest);
        let selector =
            fs::read(namespace.join(SELECTOR_NAME)).expect("read committed snapshot selector");
        let cell =
            usize::try_from((receipt.generation - 1) & 1).expect("selector cell parity fits usize");
        let start = cell * SELECTOR_CELL_LEN;
        let selector = protected_catalog::decode_selector_cell(
            &selector[start..start + SELECTOR_CELL_LEN],
            cell as u8,
        )
        .expect("decode committed selector cell")
        .expect("committed selector cell is populated");
        assert_eq!(selector.generation, receipt.generation);
        assert_eq!(selector.slot, receipt.slot);
        assert_eq!(
            selector.metadata_digest,
            protected_catalog::digest(&metadata_bytes)
        );
    }

    fn expect_permission_denied<T>(result: std::io::Result<T>, operation: &str) {
        match result {
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => panic!("{operation} failed with the wrong error: {error}"),
            Ok(value) => {
                drop(value);
                panic!("{operation} unexpectedly succeeded");
            }
        }
    }

    fn assert_service_credentials() {
        assert_eq!(rustix::process::getuid().as_raw(), SERVICE_UID);
        assert_eq!(rustix::process::geteuid().as_raw(), SERVICE_UID);
        assert_eq!(rustix::process::getgid().as_raw(), SERVICE_GID);
        assert_eq!(rustix::process::getegid().as_raw(), SERVICE_GID);
        assert!(
            rustix::process::getgroups()
                .expect("read service supplementary groups")
                .is_empty(),
            "LinuxProtected service child must have no supplementary groups"
        );
    }

    fn protected_options(database: &Path) -> SqliteConnectOptions {
        SqliteConnectOptions::new()
            .filename(database)
            .create_if_missing(true)
            .vfs("unix-excl")
            .locking_mode(SqliteLockingMode::Exclusive)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(2))
    }

    async fn provision_root_fixture() -> RootFixture {
        assert!(
            rustix::process::getuid().is_root() && rustix::process::geteuid().is_root(),
            "LinuxProtected root fixture requires real and effective UID 0"
        );
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time follows Unix epoch")
            .as_nanos();
        let outer = PathBuf::from(format!(
            "/var/lib/gta-claw-lp2-{}-{nonce}",
            std::process::id()
        ));
        let namespace = outer.join("state");
        fs::create_dir(&outer).expect("create root-owned fixture ancestor");
        chown(&outer, Some(0), Some(0)).expect("own fixture ancestor as root");
        fs::set_permissions(&outer, fs::Permissions::from_mode(0o755))
            .expect("secure fixture ancestor");
        fs::create_dir(&namespace).expect("create protected namespace fixture");

        let database = namespace.join(DATABASE_NAME);
        let mut connection = SqliteConnection::connect_with(&protected_options(&database))
            .await
            .expect("provision unix-excl protected database");
        assert_eq!(
            claw_sqlite_file_control::main_database_vfs_name(&mut connection)
                .await
                .expect("query provisioned VFS"),
            "unix-excl"
        );
        claw_sqlite_file_control::enable_persistent_wal(&mut connection)
            .await
            .expect("enable persistent protected WAL");
        sqlx::raw_sql(
            "CREATE TABLE gta_claw_lp2_provisioning(value INTEGER);
             DROP TABLE gta_claw_lp2_provisioning;",
        )
        .execute(&mut connection)
        .await
        .expect("materialize protected database and WAL");
        connection
            .close()
            .await
            .expect("close protected provisioner");
        assert_eq!(
            exact_names(&namespace),
            [OsString::from(DATABASE_NAME), OsString::from(WAL_NAME)]
        );
        let provisioned_database =
            fs::metadata(&database).expect("inspect provisioned database identity");
        let wal = namespace.join(WAL_NAME);
        let provisioned_wal = fs::metadata(&wal).expect("inspect provisioned WAL identity");
        assert!(provisioned_database.len() > 0);
        let provisioned_identities = [
            (provisioned_database.dev(), provisioned_database.ino()),
            (provisioned_wal.dev(), provisioned_wal.ino()),
        ];

        for name in ENTRY_NAMES.iter().skip(2) {
            let file = File::create(namespace.join(name))
                .unwrap_or_else(|error| panic!("preprovision {name}: {error}"));
            if *name == SELECTOR_NAME {
                file.set_len(SELECTOR_LEN as u64)
                    .expect("preallocate fixed selector cells");
            }
        }
        for name in ENTRY_NAMES {
            let path = namespace.join(name);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .unwrap_or_else(|error| panic!("secure {name}: {error}"));
            chown(&path, Some(SERVICE_UID), Some(SERVICE_GID))
                .unwrap_or_else(|error| panic!("assign {name} to service: {error}"));
        }
        chown(&namespace, Some(0), Some(SERVICE_GID))
            .expect("assign protected namespace service group");
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o750))
            .expect("secure protected namespace parent");
        assert_eq!(exact_names(&namespace), expected_names());
        let locked_database = fs::metadata(&database).expect("reinspect locked database identity");
        let locked_wal = fs::metadata(&wal).expect("reinspect locked WAL identity");
        assert_eq!(
            [
                (locked_database.dev(), locked_database.ino()),
                (locked_wal.dev(), locked_wal.ino()),
            ],
            provisioned_identities
        );
        let ready = outer.join("service.ready");
        let control = outer.join("service.control");
        for path in [&ready, &control] {
            File::create(path).expect("precreate service control file");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("secure service control file");
            chown(path, Some(SERVICE_UID), Some(SERVICE_GID))
                .expect("assign control file to service");
        }
        RootFixture {
            outer,
            namespace,
            ready,
            control,
        }
    }

    fn service_child_command(
        namespace: &Path,
        ready: &Path,
        control: &Path,
        mode: &str,
    ) -> Command {
        let mut command = Command::new("/usr/bin/setpriv");
        command
            .arg(format!("--reuid={SERVICE_UID}"))
            .arg(format!("--regid={SERVICE_GID}"));
        if mode == GROUP_MISMATCH_CHILD {
            command.arg("--groups=0");
        } else {
            command.arg("--clear-groups");
        }
        command
            .arg("--")
            .arg(std::env::current_exe().expect("resolve LP2 test executable"))
            .arg("--exact")
            .arg(ROOT_TEST_NAME)
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(SERVICE_CHILD_ENV, mode)
            .env(NAMESPACE_ENV, namespace)
            .env(READY_ENV, ready)
            .env(CONTROL_ENV, control)
            .env_remove(ROOT_DRIVER_ENV);
        command
    }

    fn run_root_driver() -> bool {
        if rustix::process::getuid().is_root() && rustix::process::geteuid().is_root() {
            return false;
        }
        assert!(
            std::env::var_os(ROOT_DRIVER_ENV).is_none(),
            "sudo root driver did not acquire real/effective UID 0"
        );
        let output = Command::new("/usr/bin/sudo")
            .arg("-n")
            .arg("/usr/bin/env")
            .arg(format!("{ROOT_DRIVER_ENV}=1"))
            .arg(std::env::current_exe().expect("resolve LP2 test executable"))
            .arg("--exact")
            .arg(ROOT_TEST_NAME)
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env_remove(SERVICE_CHILD_ENV)
            .env_remove(NAMESPACE_ENV)
            .env_remove(READY_ENV)
            .env_remove(CONTROL_ENV)
            .output()
            .expect("passwordless sudo -n is required for LinuxProtected acceptance");
        assert!(
            output.status.success(),
            "LinuxProtected root driver failed: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    async fn assert_wrong_connection_profiles_are_terminally_rejected(namespace: &Path) {
        let protected = ProtectedNamespace::open(&LinuxProtectedSpec::new(
            namespace.to_owned(),
            SERVICE_UID,
            SERVICE_GID,
        ))
        .expect("hold protected namespace for connection rejection probes");
        let temporary = tempfile::tempdir().expect("create wrong-profile connection directory");
        let wrong_vfs_path = temporary.path().join("wrong-vfs.sqlite");
        let wrong_vfs = SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .filename(&wrong_vfs_path)
                .create_if_missing(true),
        )
        .await
        .expect("open wrong-VFS connection");
        let error = test_support::reject_protected_connection_and_close(
            Arc::clone(&protected),
            wrong_vfs,
            false,
        )
        .await;
        assert!(error.contains("unix-excl"), "wrong VFS diagnostic: {error}");

        let wrong_persist_path = temporary.path().join("wrong-persist.sqlite");
        let wrong_persist = SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .filename(&wrong_persist_path)
                .create_if_missing(true)
                .vfs("unix-excl")
                .locking_mode(SqliteLockingMode::Exclusive)
                .journal_mode(SqliteJournalMode::Wal),
        )
        .await
        .expect("open PERSIST_WAL rejection connection");
        let error =
            test_support::reject_protected_connection_and_close(protected, wrong_persist, true)
                .await;
        assert!(
            error.contains("PERSIST_WAL"),
            "wrong PERSIST_WAL diagnostic: {error}"
        );
    }

    async fn cancel_protected_worker_then_publish(
        store: &Arc<StateStore>,
        namespace: &Path,
        stage: u8,
    ) -> crate::store::ProtectedSnapshotReceipt {
        let (entered, release) = install_protected_io_gate(namespace, stage);
        let cancelled_store = Arc::clone(store);
        let cancelled =
            tokio::spawn(async move { cancelled_store.publish_linux_protected_snapshot().await });
        tokio::time::timeout(Duration::from_secs(10), entered.notified())
            .await
            .expect("protected worker reaches its cancellation gate");
        cancelled.abort();
        assert!(
            cancelled
                .await
                .expect_err("protected publication task is cancelled")
                .is_cancelled()
        );

        let competing_store = Arc::clone(store);
        let competing =
            tokio::spawn(async move { competing_store.publish_linux_protected_snapshot().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !competing.is_finished(),
            "competing publication must retain serialization until worker cleanup"
        );
        release.store(true, std::sync::atomic::Ordering::Release);
        competing
            .await
            .expect("competing publication task joins")
            .expect("competing publication succeeds after retained cleanup")
    }

    async fn exercise_service_store(namespace: &Path) {
        assert_service_credentials();
        let database = namespace.join(DATABASE_NAME);
        let original_identities = entry_identities(namespace);
        expect_permission_denied(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(namespace.join("unknown")),
            "create unknown protected entry",
        );
        assert_wrong_connection_profiles_are_terminally_rejected(namespace).await;
        let config = StoreConfig::new(&database)
            .with_operation_timeout(Duration::from_secs(10))
            .with_close_timeout(Duration::from_millis(1_500));
        let store = StateStore::open_linux_protected(
            config.clone(),
            namespace.to_owned(),
            SERVICE_UID,
            SERVICE_GID,
        )
        .await
        .expect("open LinuxProtected state store");
        let fixed_owner = test_support::owner(&store).to_owned();
        assert!(fixed_owner.starts_with("linux-protected-v1:"));
        let settings = store.settings().await.expect("read protected settings");
        assert_eq!(settings.max_connections, 1);
        assert_eq!(settings.journal_mode, "wal");
        store.health().await.expect("validate protected health");
        let session = SessionRecord::new(
            SessionId::new("lp2-clean-session").expect("valid protected session id"),
            TimestampMs::new(1).expect("valid protected session timestamp"),
        );
        store
            .sessions()
            .create(&session)
            .await
            .expect("create protected session");
        assert_eq!(
            store
                .sessions()
                .get(&session.id)
                .await
                .expect("read protected session"),
            Some(session.clone())
        );
        let rejected_session = SessionRecord::new(
            SessionId::new("lp2-rejected-session").expect("valid rejected session id"),
            TimestampMs::new(2).expect("valid rejected session timestamp"),
        );
        let metadata_path = namespace.join(SNAPSHOT_METADATA_NAMES[0]);
        fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o640))
            .expect("inject protected identity mismatch");
        let rejected = store.sessions().create(&rejected_session).await;
        assert!(
            rejected.is_err(),
            "protected identity mismatch must veto repository writes"
        );
        fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o600))
            .expect("restore protected identity");
        assert!(
            store
                .sessions()
                .get(&rejected_session.id)
                .await
                .expect("read rejected protected session")
                .is_none()
        );
        let checkpoint = store.checkpoint().await.expect("checkpoint protected WAL");
        assert_eq!(checkpoint.busy, 0);
        assert_eq!(exact_names(namespace), expected_names());
        assert_eq!(entry_identities(namespace), original_identities);

        let first = store
            .publish_linux_protected_snapshot()
            .await
            .expect("publish first protected snapshot");
        assert_eq!((first.generation, first.slot), (1, 0));
        assert_snapshot_receipt(namespace, &first);
        let second = store
            .publish_linux_protected_snapshot()
            .await
            .expect("publish second protected snapshot");
        assert_eq!((second.generation, second.slot), (2, 1));
        assert_snapshot_receipt(namespace, &second);

        test_support::fail_protected_snapshot_at(&database, 1);
        assert!(matches!(
            store.publish_linux_protected_snapshot().await,
            Err(StateError::OperationTimedOut { .. })
        ));
        assert_eq!(
            fs::metadata(namespace.join(SNAPSHOT_DATA_NAMES[0]))
                .expect("inspect scrubbed data slot")
                .len(),
            0
        );
        assert_eq!(
            fs::metadata(namespace.join(SNAPSHOT_METADATA_NAMES[0]))
                .expect("inspect scrubbed metadata slot")
                .len(),
            0
        );
        test_support::fail_protected_snapshot_at(&database, 2);
        assert!(store.publish_linux_protected_snapshot().await.is_err());
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let data_length = fs::metadata(namespace.join(SNAPSHOT_DATA_NAMES[0]))
                    .expect("inspect retained-cleanup data slot")
                    .len();
                let metadata_length = fs::metadata(namespace.join(SNAPSHOT_METADATA_NAMES[0]))
                    .expect("inspect retained-cleanup metadata slot")
                    .len();
                if data_length == 0 && metadata_length == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retained cleanup retries the injected scrub failure");
        let third = store
            .publish_linux_protected_snapshot()
            .await
            .expect("publish after precommit cleanup");
        assert_eq!((third.generation, third.slot), (3, 0));
        assert_snapshot_receipt(namespace, &third);

        test_support::fail_protected_snapshot_at(&database, 3);
        assert!(matches!(
            store.publish_linux_protected_snapshot().await,
            Err(StateError::PublicationUncertain { .. })
        ));
        let fifth = store
            .publish_linux_protected_snapshot()
            .await
            .expect("recover committed uncertain selector");
        assert_eq!((fifth.generation, fifth.slot), (5, 0));
        assert_snapshot_receipt(namespace, &fifth);

        let (left, right) = tokio::join!(
            store.publish_linux_protected_snapshot(),
            store.publish_linux_protected_snapshot()
        );
        let mut concurrent = [
            left.expect("first concurrent publication"),
            right.expect("second concurrent publication"),
        ];
        concurrent.sort_by_key(|receipt| receipt.generation);
        assert_eq!(
            concurrent
                .iter()
                .map(|receipt| (receipt.generation, receipt.slot))
                .collect::<Vec<_>>(),
            vec![(6, 1), (7, 0)]
        );
        for receipt in &concurrent {
            assert_snapshot_receipt(namespace, receipt);
        }
        let store = Arc::new(store);
        let eighth = cancel_protected_worker_then_publish(&store, namespace, 1).await;
        assert_eq!((eighth.generation, eighth.slot), (8, 1));
        assert_snapshot_receipt(namespace, &eighth);
        let ninth = cancel_protected_worker_then_publish(&store, namespace, 2).await;
        assert_eq!((ninth.generation, ninth.slot), (9, 0));
        assert_snapshot_receipt(namespace, &ninth);
        let (entered, _release, cancelled_slot) =
            test_support::install_protected_snapshot_gate(&database);
        let publication_store = Arc::clone(&store);
        let publication =
            tokio::spawn(async move { publication_store.publish_linux_protected_snapshot().await });
        tokio::time::timeout(Duration::from_secs(10), entered.notified())
            .await
            .expect("cancelled publication reaches the held-slot gate");
        let slot = cancelled_slot.load(std::sync::atomic::Ordering::Acquire);
        assert!((1..=2).contains(&slot));
        publication.abort();
        assert!(
            publication
                .await
                .expect_err("publication task is cancelled")
                .is_cancelled()
        );
        test_support::clear_protected_snapshot_gate(&database);
        let slot = usize::from(slot - 1);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let data_length = fs::metadata(namespace.join(SNAPSHOT_DATA_NAMES[slot]))
                    .expect("inspect cancelled snapshot data")
                    .len();
                let metadata_length = fs::metadata(namespace.join(SNAPSHOT_METADATA_NAMES[slot]))
                    .expect("inspect cancelled snapshot metadata")
                    .len();
                if data_length == 0 && metadata_length == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("runtime-independent cancellation cleanup scrubs the inactive slot");
        let tenth = store
            .publish_linux_protected_snapshot()
            .await
            .expect("publish after cancelled detached cleanup");
        assert_eq!((tenth.generation, tenth.slot), (10, 1));
        assert_snapshot_receipt(namespace, &tenth);
        assert!(matches!(
            store.backup_to(namespace.join("forbidden")).await,
            Err(StateError::InvalidPath {
                reason: "LinuxProtected snapshots use only the fixed internal catalog",
                ..
            })
        ));
        assert_eq!(exact_names(namespace), expected_names());
        assert_eq!(entry_identities(namespace), original_identities);
        let (close_entered, close_release) = install_protected_io_gate(namespace, 1);
        let closing_publication_store = Arc::clone(&store);
        let closing_publication = tokio::spawn(async move {
            closing_publication_store
                .publish_linux_protected_snapshot()
                .await
        });
        tokio::time::timeout(Duration::from_secs(10), close_entered.notified())
            .await
            .expect("closing publication reaches retained prepare worker");
        closing_publication.abort();
        assert!(
            closing_publication
                .await
                .expect_err("closing publication task is cancelled")
                .is_cancelled()
        );
        let store = Arc::try_unwrap(store)
            .unwrap_or_else(|_| panic!("cancelled publication releases its store reference"));
        let close = tokio::spawn(async move { store.close().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !close.is_finished(),
            "LinuxProtected close must wait for detached publication workers"
        );
        close_release.store(true, std::sync::atomic::Ordering::Release);
        close
            .await
            .expect("protected close task joins")
            .expect("close protected store after worker retirement");
        assert_eq!(exact_names(namespace), expected_names());
        assert_eq!(entry_identities(namespace), original_identities);

        let reopened = StateStore::open_linux_protected(
            config,
            namespace.to_owned(),
            SERVICE_UID,
            SERVICE_GID,
        )
        .await
        .expect("reopen protected store and recover catalog");
        assert_eq!(test_support::owner(&reopened), fixed_owner);
        assert_eq!(
            reopened
                .sessions()
                .get(&session.id)
                .await
                .expect("read protected session after reopen"),
            Some(session)
        );
        let eleventh = reopened
            .publish_linux_protected_snapshot()
            .await
            .expect("publish after catalog recovery");
        assert_eq!((eleventh.generation, eleventh.slot), (11, 0));
        assert_snapshot_receipt(namespace, &eleventh);
        reopened.close().await.expect("close recovered store");
        let torn_metadata = namespace.join(SNAPSHOT_METADATA_NAMES[1]);
        let torn_metadata_file = OpenOptions::new()
            .write(true)
            .open(&torn_metadata)
            .expect("open inactive metadata tear fixture");
        torn_metadata_file
            .set_len(1)
            .and_then(|()| torn_metadata_file.sync_all())
            .expect("persist torn inactive metadata prefix");

        let protected = ProtectedNamespace::open(&LinuxProtectedSpec::new(
            namespace.to_owned(),
            SERVICE_UID,
            SERVICE_GID,
        ))
        .expect("open namespace for rollback rejection");
        let identity = protected.catalog_identity(1);
        assert_eq!(
            protected
                .recover_catalog(identity, None, None, 0)
                .expect("recover current generation")
                .expect("current generation exists")
                .metadata
                .generation,
            11
        );
        let selector_path = namespace.join(SELECTOR_NAME);
        let selector_bytes = fs::read(&selector_path).expect("capture rollback selector");
        let selector = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&selector_path)
            .expect("open selector rollback fixture");
        write_all_at(&selector, &[0; SELECTOR_CELL_LEN], 0)
            .and_then(|()| selector.sync_all())
            .expect("inject selector rollback");
        assert!(protected.recover_catalog(identity, None, None, 0).is_err());
        write_all_at(&selector, &selector_bytes, 0)
            .and_then(|()| selector.sync_all())
            .expect("restore selector after rollback probe");
        assert_eq!(
            protected
                .recover_catalog(identity, None, None, 0)
                .expect("recover restored generation")
                .expect("restored generation exists")
                .metadata
                .generation,
            11
        );
        drop(protected);

        expect_permission_denied(
            fs::remove_file(namespace.join(WAL_NAME)),
            "unlink protected WAL",
        );
        expect_permission_denied(
            fs::rename(namespace.join(DATABASE_NAME), namespace.join("renamed")),
            "rename protected database",
        );
        expect_permission_denied(
            fs::hard_link(namespace.join(DATABASE_NAME), namespace.join("hard-link")),
            "hard-link protected database",
        );
        expect_permission_denied(
            fs::set_permissions(namespace, fs::Permissions::from_mode(0o770)),
            "chmod protected namespace",
        );
        expect_permission_denied(
            chown(namespace, Some(SERVICE_UID), Some(SERVICE_GID)),
            "chown protected namespace",
        );
        assert_eq!(exact_names(namespace), expected_names());
        assert_eq!(entry_identities(namespace), original_identities);
    }

    fn service_config(namespace: &Path) -> StoreConfig {
        StoreConfig::new(namespace.join(DATABASE_NAME))
            .with_operation_timeout(Duration::from_secs(10))
            .with_close_timeout(Duration::from_millis(1_500))
    }

    async fn run_crash_service(namespace: &Path, ready: &Path) {
        assert_service_credentials();
        let store = StateStore::open_linux_protected(
            service_config(namespace),
            namespace.to_owned(),
            SERVICE_UID,
            SERVICE_GID,
        )
        .await
        .expect("open hard-death LinuxProtected store");
        let session = SessionRecord::new(
            SessionId::new("lp2-hard-death-session").expect("valid hard-death session id"),
            TimestampMs::new(2).expect("valid hard-death timestamp"),
        );
        store
            .sessions()
            .create(&session)
            .await
            .expect("commit hard-death session");
        let mut ready = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(ready)
            .expect("open preprovisioned readiness file");
        std::io::Write::write_all(&mut ready, b"ready").expect("signal hard-death readiness");
        ready.sync_all().expect("sync hard-death readiness");
        std::future::pending::<()>().await;
        unreachable!("hard-death service must be killed");
    }

    async fn run_lock_probe_service(namespace: &Path) {
        assert_service_credentials();
        match StateStore::open_linux_protected(
            service_config(namespace),
            namespace.to_owned(),
            SERVICE_UID,
            SERVICE_GID,
        )
        .await
        {
            Err(StateError::StoreLocked { .. }) => {}
            Err(error) => panic!("concurrent protected open failed incorrectly: {error}"),
            Ok(store) => {
                drop(store);
                panic!("concurrent protected writer unexpectedly opened");
            }
        }
    }

    async fn run_group_mismatch_service(namespace: &Path) {
        assert_eq!(rustix::process::getuid().as_raw(), SERVICE_UID);
        assert_eq!(rustix::process::geteuid().as_raw(), SERVICE_UID);
        assert_eq!(rustix::process::getgid().as_raw(), SERVICE_GID);
        assert_eq!(rustix::process::getegid().as_raw(), SERVICE_GID);
        assert!(
            !rustix::process::getgroups()
                .expect("read mismatched supplementary groups")
                .is_empty()
        );
        assert!(matches!(
            StateStore::open_linux_protected(
                service_config(namespace),
                namespace.to_owned(),
                SERVICE_UID,
                SERVICE_GID,
            )
            .await,
            Err(StateError::InvalidPath {
                reason: "LinuxProtected expected service credentials do not match the process",
                ..
            })
        ));
    }

    async fn run_recovery_service(namespace: &Path) {
        assert_service_credentials();
        let store = StateStore::open_linux_protected(
            service_config(namespace),
            namespace.to_owned(),
            SERVICE_UID,
            SERVICE_GID,
        )
        .await
        .expect("recover hard-death LinuxProtected store");
        let session_id =
            SessionId::new("lp2-hard-death-session").expect("valid hard-death session id");
        assert!(
            store
                .sessions()
                .get(&session_id)
                .await
                .expect("read recovered hard-death session")
                .is_some()
        );
        assert_eq!(
            store
                .checkpoint()
                .await
                .expect("checkpoint recovered hard-death WAL")
                .busy,
            0
        );
        store
            .close()
            .await
            .expect("close recovered hard-death store");
    }

    fn run_runtime_drop_service(namespace: &Path) {
        assert_service_credentials();
        let namespace = namespace.to_owned();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("build disposable snapshot runtime");
            let store = Arc::new(
                runtime
                    .block_on(StateStore::open_linux_protected(
                        service_config(&namespace),
                        namespace.clone(),
                        SERVICE_UID,
                        SERVICE_GID,
                    ))
                    .expect("open runtime-drop LinuxProtected store"),
            );
            let database = namespace.join(DATABASE_NAME);
            let (entered, _release, dropped_slot) =
                test_support::install_protected_snapshot_gate(&database);
            let publication_store = Arc::clone(&store);
            runtime.spawn(async move {
                let _ = publication_store.publish_linux_protected_snapshot().await;
            });
            runtime
                .block_on(async {
                    tokio::time::timeout(Duration::from_secs(10), entered.notified()).await
                })
                .expect("runtime-drop publication reaches held-slot gate");
            let slot = dropped_slot.load(std::sync::atomic::Ordering::Acquire);
            assert!((1..=2).contains(&slot));
            drop(runtime);
            test_support::clear_protected_snapshot_gate(&database);

            let slot = usize::from(slot - 1);
            let cleanup_deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let data_length = fs::metadata(namespace.join(SNAPSHOT_DATA_NAMES[slot]))
                    .expect("inspect runtime-drop snapshot data")
                    .len();
                let metadata_length = fs::metadata(namespace.join(SNAPSHOT_METADATA_NAMES[slot]))
                    .expect("inspect runtime-drop snapshot metadata")
                    .len();
                if data_length == 0 && metadata_length == 0 {
                    break;
                }
                assert!(
                    Instant::now() < cleanup_deadline,
                    "runtime-independent cleanup did not scrub after runtime destruction"
                );
                std::thread::yield_now();
            }

            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build successor snapshot runtime");
            let receipt = runtime
                .block_on(store.publish_linux_protected_snapshot())
                .expect("publish after caller runtime destruction");
            assert_eq!((receipt.generation, receipt.slot), (12, 1));
            assert_snapshot_receipt(&namespace, &receipt);
            let store = Arc::try_unwrap(store)
                .unwrap_or_else(|_| panic!("runtime-drop task releases its store reference"));
            runtime
                .block_on(store.close())
                .expect("close runtime-drop protected store");
        })
        .join()
        .expect("runtime-drop service thread completes");
    }

    async fn run_deadline_service(namespace: &Path) {
        assert_service_credentials();
        let config = service_config(namespace).with_operation_timeout(Duration::from_millis(500));
        let store = StateStore::open_linux_protected(
            config,
            namespace.to_owned(),
            SERVICE_UID,
            SERVICE_GID,
        )
        .await
        .expect("open deadline LinuxProtected store");
        let database = namespace.join(DATABASE_NAME);
        let (_entered, _release, timed_out_slot) =
            test_support::install_protected_snapshot_gate(&database);
        let started = Instant::now();
        let error = store
            .publish_linux_protected_snapshot()
            .await
            .expect_err("deadline-bound publication must fail before selector commit");
        assert!(
            error.to_string().contains("timed out"),
            "deadline failure must remain timeout-shaped: {error:?}"
        );
        assert!(!matches!(error, StateError::PublicationUncertain { .. }));
        assert!(started.elapsed() >= Duration::from_millis(450));
        let slot = timed_out_slot.load(std::sync::atomic::Ordering::Acquire);
        assert!((1..=2).contains(&slot));
        let slot = usize::from(slot - 1);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let data_length = fs::metadata(namespace.join(SNAPSHOT_DATA_NAMES[slot]))
                    .expect("inspect deadline-cleaned snapshot data")
                    .len();
                let metadata_length = fs::metadata(namespace.join(SNAPSHOT_METADATA_NAMES[slot]))
                    .expect("inspect deadline-cleaned snapshot metadata")
                    .len();
                if data_length == 0 && metadata_length == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("deadline cleanup scrubs the inactive snapshot slot");
        store.close().await.expect("close deadline protected store");
    }

    async fn install_repository_temp_marker(store: &StateStore) {
        let mut connection = test_support::pool(store)
            .acquire()
            .await
            .expect("acquire sole connection for TEMP marker");
        sqlx::query("CREATE TEMP TABLE lp2_post_fence_marker(value INTEGER)")
            .execute(&mut *connection)
            .await
            .expect("create TEMP marker on sole protected connection");
    }

    async fn assert_repository_pool_blocked(store: &StateStore) {
        match tokio::time::timeout(
            Duration::from_millis(100),
            test_support::pool(store).acquire(),
        )
        .await
        {
            Err(_) => {}
            Ok(Err(error)) => panic!("blocked protected acquire failed early: {error}"),
            Ok(Ok(mut connection)) => {
                let marker = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM sqlite_temp_master
                     WHERE type = 'table' AND name = ?",
                )
                .bind(REPOSITORY_TEMP_MARKER)
                .fetch_one(&mut *connection)
                .await
                .expect("inspect unexpectedly reacquired TEMP marker");
                panic!("protected post-fence released its sole connection early; marker={marker}");
            }
        }
    }

    async fn assert_replacement_connection(store: &StateStore) {
        let mut replacement =
            tokio::time::timeout(Duration::from_secs(5), test_support::pool(store).acquire())
                .await
                .expect("replacement protected connection acquire remains bounded")
                .expect("acquire replacement protected connection");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_temp_master
                 WHERE type = 'table' AND name = ?",
            )
            .bind(REPOSITORY_TEMP_MARKER)
            .fetch_one(&mut *replacement)
            .await
            .expect("inspect replacement TEMP schema"),
            0,
            "terminally discarded connection cannot carry its TEMP marker into replacement",
        );
        assert_repository_pool_blocked(store).await;
        drop(replacement);
        tokio::time::timeout(Duration::from_secs(5), async {
            while test_support::pool(store).num_idle() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replacement returns exactly one idle protected connection");
        assert_eq!(test_support::pool(store).size(), 1);
        assert_eq!(test_support::pool(store).num_idle(), 1);
    }

    fn write_control_value(path: &Path, value: &str) {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .expect("open preprovisioned repository control file");
        std::io::Write::write_all(&mut file, value.as_bytes())
            .expect("write repository control value");
        file.sync_all().expect("sync repository control value");
    }

    fn read_control_value(path: &Path) -> String {
        fs::read_to_string(path)
            .expect("read repository control value")
            .trim()
            .to_owned()
    }

    async fn request_root_repository_action(
        ready: &Path,
        control: &Path,
        request: &str,
        acknowledgement: &str,
    ) {
        write_control_value(ready, request);
        tokio::time::timeout(Duration::from_secs(10), async {
            while read_control_value(control) != acknowledgement {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("root did not acknowledge repository action {request} as {acknowledgement}")
        });
    }

    async fn run_repository_outcome_service(namespace: &Path, ready: &Path, control: &Path) {
        assert_service_credentials();
        let config = service_config(namespace).with_operation_timeout(Duration::from_millis(500));
        let store = Arc::new(
            StateStore::open_linux_protected(
                config,
                namespace.to_owned(),
                SERVICE_UID,
                SERVICE_GID,
            )
            .await
            .expect("open protected repository outcome store"),
        );
        let owner = test_support::owner(&store).to_owned();
        let original_identities = entry_identities(namespace);

        let read_session = SessionRecord::new(
            SessionId::new("lp2-protected-read-deadline").expect("valid read deadline session id"),
            TimestampMs::new(20).expect("valid read deadline timestamp"),
        );
        store
            .sessions()
            .create(&read_session)
            .await
            .expect("seed protected read deadline record");
        install_repository_temp_marker(&store).await;
        let (read_entered, read_release) =
            repository_test_support::set_protected_read_post_barrier();
        let read_store = Arc::clone(&store);
        let read_id = read_session.id.clone();
        let read = tokio::spawn(async move { read_store.sessions().get(&read_id).await });
        tokio::time::timeout(Duration::from_secs(5), read_entered.notified())
            .await
            .expect("protected read reaches post-read identity barrier");
        assert_repository_pool_blocked(&store).await;
        request_root_repository_action(ready, control, "read-tamper", "read-tampered").await;
        read_release.notify_one();
        assert!(matches!(
            read.await
                .expect("protected identity read task joins")
                .expect_err("protected post-read identity mismatch must fail"),
            StateError::InvalidPath { .. }
        ));
        request_root_repository_action(ready, control, "read-restore", "read-restored").await;
        assert_replacement_connection(&store).await;

        install_repository_temp_marker(&store).await;
        let (read_entered, read_release) =
            repository_test_support::set_protected_read_post_barrier();
        let read_store = Arc::clone(&store);
        let read_id = read_session.id.clone();
        let read = tokio::spawn(async move { read_store.sessions().get(&read_id).await });
        tokio::time::timeout(Duration::from_secs(5), read_entered.notified())
            .await
            .expect("protected read reaches post-read deadline barrier");
        assert_repository_pool_blocked(&store).await;
        tokio::time::sleep(Duration::from_millis(550)).await;
        read_release.notify_one();
        assert!(matches!(
            read.await
                .expect("protected read task joins")
                .expect_err("protected post-read deadline must expire"),
            StateError::OperationTimedOut { .. }
        ));
        assert_replacement_connection(&store).await;

        let identity_session = SessionRecord::new(
            SessionId::new("lp2-protected-committed-identity")
                .expect("valid committed identity session id"),
            TimestampMs::new(21).expect("valid committed identity timestamp"),
        );
        let (commit_entered, commit_release) =
            repository_test_support::set_post_commit_barrier(&owner);
        install_repository_temp_marker(&store).await;
        let identity_store = Arc::clone(&store);
        let identity_record = identity_session.clone();
        let identity_write =
            tokio::spawn(async move { identity_store.sessions().create(&identity_record).await });
        tokio::time::timeout(Duration::from_secs(5), commit_entered.notified())
            .await
            .expect("protected write reaches post-commit identity barrier");
        assert_repository_pool_blocked(&store).await;
        request_root_repository_action(ready, control, "commit-tamper", "commit-tampered").await;
        commit_release.notify_one();
        let error = identity_write
            .await
            .expect("post-commit identity task joins")
            .expect_err("post-commit identity mismatch must be reported");
        assert!(matches!(
            error,
            StateError::CommittedWithCleanupFailure { .. }
        ));
        assert_eq!(error.write_outcome(), WriteOutcome::Committed);
        request_root_repository_action(ready, control, "commit-restore", "commit-restored").await;
        assert_replacement_connection(&store).await;
        assert_eq!(
            store
                .sessions()
                .get(&identity_session.id)
                .await
                .expect("read identity-mismatch committed record"),
            Some(identity_session)
        );

        let deadline_session = SessionRecord::new(
            SessionId::new("lp2-protected-committed-deadline")
                .expect("valid committed deadline session id"),
            TimestampMs::new(22).expect("valid committed deadline timestamp"),
        );
        let (commit_entered, commit_release) =
            repository_test_support::set_post_commit_barrier(&owner);
        install_repository_temp_marker(&store).await;
        let deadline_store = Arc::clone(&store);
        let deadline_record = deadline_session.clone();
        let deadline_write =
            tokio::spawn(async move { deadline_store.sessions().create(&deadline_record).await });
        tokio::time::timeout(Duration::from_secs(5), commit_entered.notified())
            .await
            .expect("protected write reaches post-commit deadline barrier");
        assert_repository_pool_blocked(&store).await;
        tokio::time::sleep(Duration::from_millis(550)).await;
        commit_release.notify_one();
        let error = deadline_write
            .await
            .expect("post-commit deadline task joins")
            .expect_err("late protected commit delivery must be reported");
        assert!(matches!(error, StateError::CommittedAfterDeadline { .. }));
        assert_eq!(error.write_outcome(), WriteOutcome::Committed);
        assert_replacement_connection(&store).await;
        assert_eq!(
            store
                .sessions()
                .get(&deadline_session.id)
                .await
                .expect("read deadline-committed record"),
            Some(deadline_session)
        );

        let rollback_session = SessionRecord::new(
            SessionId::new("lp2-protected-rolled-back-identity")
                .expect("valid rollback identity session id"),
            TimestampMs::new(24).expect("valid rollback identity timestamp"),
        );
        install_repository_temp_marker(&store).await;
        let (write_entered, write_release) = repository_test_support::set_write_barrier(&owner);
        let rollback_store = Arc::clone(&store);
        let rollback_record = rollback_session.clone();
        let rollback_write =
            tokio::spawn(async move { rollback_store.sessions().create(&rollback_record).await });
        tokio::time::timeout(Duration::from_secs(5), write_entered.notified())
            .await
            .expect("protected write reaches pre-commit rollback barrier");
        assert_repository_pool_blocked(&store).await;
        request_root_repository_action(ready, control, "rollback-tamper", "rollback-tampered")
            .await;
        write_release.notify_one();
        let error = rollback_write
            .await
            .expect("protected rollback task joins")
            .expect_err("pre-commit protected identity mismatch must rollback");
        assert!(
            matches!(error, StateError::InvalidPath { .. }),
            "protected rollback must preserve the exact identity failure: {error:?}"
        );
        assert_eq!(error.write_outcome(), WriteOutcome::NotCommitted);
        request_root_repository_action(ready, control, "rollback-restore", "rollback-restored")
            .await;
        assert_replacement_connection(&store).await;
        assert!(
            store
                .sessions()
                .get(&rollback_session.id)
                .await
                .expect("read rolled-back protected record")
                .is_none()
        );

        let rollback_deadline_session = SessionRecord::new(
            SessionId::new("lp2-protected-rolled-back-deadline")
                .expect("valid rollback deadline session id"),
            TimestampMs::new(25).expect("valid rollback deadline timestamp"),
        );
        install_repository_temp_marker(&store).await;
        let (commit_entered, commit_release) = repository_test_support::set_commit_barrier(&owner);
        let rollback_deadline_store = Arc::clone(&store);
        let rollback_deadline_record = rollback_deadline_session.clone();
        let rollback_deadline_write = tokio::spawn(async move {
            rollback_deadline_store
                .sessions()
                .create(&rollback_deadline_record)
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), commit_entered.notified())
            .await
            .expect("protected write reaches pre-commit deadline barrier");
        assert_repository_pool_blocked(&store).await;
        tokio::time::sleep(Duration::from_millis(550)).await;
        commit_release.notify_one();
        let error = rollback_deadline_write
            .await
            .expect("protected deadline rollback task joins")
            .expect_err("pre-commit protected deadline must rollback");
        assert!(matches!(error, StateError::OperationTimedOut { .. }));
        assert_eq!(error.write_outcome(), WriteOutcome::NotCommitted);
        assert_replacement_connection(&store).await;
        assert!(
            store
                .sessions()
                .get(&rollback_deadline_session.id)
                .await
                .expect("read deadline-rolled-back protected record")
                .is_none()
        );

        install_repository_temp_marker(&store).await;
        let (read_entered, _read_release) =
            repository_test_support::set_protected_read_post_barrier();
        let cancelled_read_store = Arc::clone(&store);
        let cancelled_read_id = read_session.id.clone();
        let cancelled_read = tokio::spawn(async move {
            cancelled_read_store
                .sessions()
                .get(&cancelled_read_id)
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), read_entered.notified())
            .await
            .expect("cancelled protected read reaches post-read barrier");
        assert_repository_pool_blocked(&store).await;
        cancelled_read.abort();
        assert!(
            cancelled_read
                .await
                .expect_err("protected read task is cancelled")
                .is_cancelled()
        );
        repository_test_support::clear_protected_read_post_barrier();
        assert_replacement_connection(&store).await;

        let cancelled_session = SessionRecord::new(
            SessionId::new("lp2-protected-committed-cancelled")
                .expect("valid cancelled commit session id"),
            TimestampMs::new(23).expect("valid cancelled commit timestamp"),
        );
        install_repository_temp_marker(&store).await;
        let (commit_entered, _commit_release) =
            repository_test_support::set_post_commit_barrier(&owner);
        let cancelled_write_store = Arc::clone(&store);
        let cancelled_record = cancelled_session.clone();
        let cancelled_write = tokio::spawn(async move {
            cancelled_write_store
                .sessions()
                .create(&cancelled_record)
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), commit_entered.notified())
            .await
            .expect("cancelled protected write reaches post-commit barrier");
        assert_repository_pool_blocked(&store).await;
        cancelled_write.abort();
        assert!(
            cancelled_write
                .await
                .expect_err("protected write task is cancelled")
                .is_cancelled()
        );
        repository_test_support::clear_post_commit_barrier(&owner);
        assert_replacement_connection(&store).await;
        assert_eq!(
            store
                .sessions()
                .get(&cancelled_session.id)
                .await
                .expect("read caller-cancelled committed record"),
            Some(cancelled_session)
        );

        install_repository_temp_marker(&store).await;
        let (runtime_entered, _runtime_release) =
            repository_test_support::set_protected_read_post_barrier();
        let runtime_store = Arc::clone(&store);
        let runtime_read_id = read_session.id.clone();
        let (drop_runtime_tx, drop_runtime_rx) = std::sync::mpsc::sync_channel(0);
        let runtime_thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("build protected read disposable runtime");
            runtime.spawn(async move {
                let _ = runtime_store.sessions().get(&runtime_read_id).await;
            });
            drop_runtime_rx
                .recv()
                .expect("receive protected runtime drop command");
            drop(runtime);
        });
        tokio::time::timeout(Duration::from_secs(5), runtime_entered.notified())
            .await
            .expect("runtime-dropped protected read reaches post-read barrier");
        assert_repository_pool_blocked(&store).await;
        drop_runtime_tx
            .send(())
            .expect("request protected caller runtime destruction");
        runtime_thread
            .join()
            .expect("protected caller runtime thread joins");
        repository_test_support::clear_protected_read_post_barrier();
        assert_replacement_connection(&store).await;

        assert_eq!(exact_names(namespace), expected_names());
        assert_eq!(entry_identities(namespace), original_identities);
        Arc::try_unwrap(store)
            .unwrap_or_else(|_| panic!("repository outcome tasks release store references"))
            .close()
            .await
            .expect("close protected repository outcome store");
    }

    fn assert_child_success(output: std::process::Output, operation: &str) {
        assert!(
            output.status.success(),
            "{operation} failed: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn wait_for_control_value(path: &Path, expected: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while read_control_value(path) != expected {
            assert!(
                Instant::now() < deadline,
                "repository control did not reach {expected}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn exercise_repository_outcome_root(fixture: &RootFixture) {
        write_control_value(&fixture.ready, "");
        write_control_value(&fixture.control, "");
        let child = service_child_command(
            &fixture.namespace,
            &fixture.ready,
            &fixture.control,
            REPOSITORY_OUTCOME_CHILD,
        )
        .spawn()
        .expect("start protected repository outcome child");
        let mut child = ChildGuard::new(child);
        let metadata = fixture.namespace.join(SNAPSHOT_METADATA_NAMES[0]);
        for (request, mode, acknowledgement) in [
            ("read-tamper", 0o640, "read-tampered"),
            ("read-restore", 0o600, "read-restored"),
            ("commit-tamper", 0o640, "commit-tampered"),
            ("commit-restore", 0o600, "commit-restored"),
            ("rollback-tamper", 0o640, "rollback-tampered"),
            ("rollback-restore", 0o600, "rollback-restored"),
        ] {
            wait_for_control_value(&fixture.ready, request);
            fs::set_permissions(&metadata, fs::Permissions::from_mode(mode))
                .unwrap_or_else(|error| panic!("apply root repository action {request}: {error}"));
            write_control_value(&fixture.control, acknowledgement);
        }
        child.wait_success("LinuxProtected repository outcome lifecycle");
        assert_eq!(
            fs::metadata(metadata)
                .expect("inspect restored repository metadata")
                .mode()
                & 0o7777,
            0o600
        );
    }

    fn exercise_hard_death_root(fixture: &RootFixture) {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&fixture.ready)
            .expect("reset hard-death readiness file")
            .sync_all()
            .expect("sync reset readiness file");
        let identities = entry_identities(&fixture.namespace);
        let child = service_child_command(
            &fixture.namespace,
            &fixture.ready,
            &fixture.control,
            CRASH_CHILD,
        )
        .spawn()
        .expect("start hard-death protected child");
        let mut child = ChildGuard::new(child);
        let deadline = Instant::now() + Duration::from_secs(15);
        while fs::metadata(&fixture.ready)
            .expect("inspect hard-death readiness")
            .len()
            == 0
        {
            assert!(
                Instant::now() < deadline,
                "hard-death protected child did not become ready"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_child_success(
            service_child_command(
                &fixture.namespace,
                &fixture.ready,
                &fixture.control,
                LOCK_PROBE_CHILD,
            )
            .output()
            .expect("run protected process-exclusion probe"),
            "protected process-exclusion probe",
        );
        child.kill_and_wait();
        assert_eq!(exact_names(&fixture.namespace), expected_names());
        assert_eq!(entry_identities(&fixture.namespace), identities);
        assert_child_success(
            service_child_command(
                &fixture.namespace,
                &fixture.ready,
                &fixture.control,
                RECOVERY_CHILD,
            )
            .output()
            .expect("run protected hard-death recovery"),
            "protected hard-death recovery",
        );
        assert_eq!(exact_names(&fixture.namespace), expected_names());
        assert_eq!(entry_identities(&fixture.namespace), identities);
    }

    fn assert_root_negative_namespace_cases(fixture: &RootFixture) {
        let unknown = fixture.namespace.join("state.sqlite-shm");
        File::create(&unknown).expect("inject forbidden namespace entry");
        assert!(validate_exact_names(&fixture.namespace).is_err());
        fs::remove_file(&unknown).expect("remove forbidden namespace entry");

        let database = fixture.namespace.join(DATABASE_NAME);
        let linked = fixture.outer.join("database-link");
        fs::hard_link(&database, &linked).expect("inject database hard link");
        let database_file = File::open(&database).expect("open hard-linked database");
        let identity =
            FileIdentity::capture(&database, &database_file, "inspect hard-link fixture")
                .expect("capture hard-link fixture identity");
        let spec = LinuxProtectedSpec::new(fixture.namespace.clone(), SERVICE_UID, SERVICE_GID);
        let parent_device = fs::metadata(&fixture.namespace)
            .expect("inspect fixture parent")
            .dev();
        assert!(validate_entry(&spec, parent_device, &database, &database_file, identity).is_err());
        fs::remove_file(&linked).expect("remove database hard link");

        fs::set_permissions(&database, fs::Permissions::from_mode(0o640))
            .expect("inject database mode mismatch");
        let database_file = File::open(&database).expect("open mode-mismatched database");
        let identity =
            FileIdentity::capture(&database, &database_file, "inspect mode-mismatch fixture")
                .expect("capture mode-mismatch identity");
        assert!(validate_entry(&spec, parent_device, &database, &database_file, identity).is_err());
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
            .expect("restore database mode");

        chown(&database, Some(0), Some(SERVICE_GID)).expect("inject database UID mismatch");
        let database_file = File::open(&database).expect("open UID-mismatched database");
        let identity =
            FileIdentity::capture(&database, &database_file, "inspect UID-mismatch fixture")
                .expect("capture UID-mismatch identity");
        assert!(validate_entry(&spec, parent_device, &database, &database_file, identity).is_err());
        chown(&database, Some(SERVICE_UID), Some(0)).expect("inject database GID mismatch");
        let database_file = File::open(&database).expect("open GID-mismatched database");
        let identity =
            FileIdentity::capture(&database, &database_file, "inspect GID-mismatch fixture")
                .expect("capture GID-mismatch identity");
        assert!(validate_entry(&spec, parent_device, &database, &database_file, identity).is_err());
        chown(&database, Some(SERVICE_UID), Some(SERVICE_GID)).expect("restore database ownership");
        {
            use xattr::FileExt as _;

            let database_file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&database)
                .expect("open database ACL fixture");
            database_file
                .set_xattr("system.posix_acl_access", &nontrivial_posix_acl(0o6, 0))
                .expect("inject nontrivial database ACL");
            fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
                .expect("preserve database mode after ACL injection");
            let identity =
                FileIdentity::capture(&database, &database_file, "inspect database ACL fixture")
                    .expect("capture database ACL identity");
            assert!(
                validate_entry(&spec, parent_device, &database, &database_file, identity).is_err()
            );
            database_file
                .remove_xattr("system.posix_acl_access")
                .expect("remove nontrivial database ACL");
            fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
                .expect("restore database mode after ACL removal");
        }

        fs::set_permissions(&fixture.namespace, fs::Permissions::from_mode(0o770))
            .expect("inject writable protected parent");
        let parent_file = File::open(&fixture.namespace).expect("open writable parent fixture");
        let parent_identity = FileIdentity::capture(
            &fixture.namespace,
            &parent_file,
            "inspect writable parent fixture",
        )
        .expect("capture writable parent fixture");
        assert!(validate_parent(&spec, &parent_file, parent_identity).is_err());
        fs::set_permissions(&fixture.namespace, fs::Permissions::from_mode(0o750))
            .expect("restore protected parent");
        chown(&fixture.namespace, Some(SERVICE_UID), Some(SERVICE_GID))
            .expect("inject protected parent UID mismatch");
        let parent_file = File::open(&fixture.namespace).expect("open UID-mismatched parent");
        let parent_identity = FileIdentity::capture(
            &fixture.namespace,
            &parent_file,
            "inspect UID-mismatched parent",
        )
        .expect("capture UID-mismatched parent identity");
        assert!(validate_parent(&spec, &parent_file, parent_identity).is_err());
        chown(&fixture.namespace, Some(0), Some(0)).expect("inject protected parent GID mismatch");
        let parent_file = File::open(&fixture.namespace).expect("open GID-mismatched parent");
        let parent_identity = FileIdentity::capture(
            &fixture.namespace,
            &parent_file,
            "inspect GID-mismatched parent",
        )
        .expect("capture GID-mismatched parent identity");
        assert!(validate_parent(&spec, &parent_file, parent_identity).is_err());
        chown(&fixture.namespace, Some(0), Some(SERVICE_GID))
            .expect("restore protected parent ownership");
        {
            use xattr::FileExt as _;

            let parent_file = File::open(&fixture.namespace).expect("open parent ACL fixture");
            parent_file
                .set_xattr("system.posix_acl_access", &nontrivial_posix_acl(0o7, 0o5))
                .expect("inject nontrivial parent ACL");
            fs::set_permissions(&fixture.namespace, fs::Permissions::from_mode(0o750))
                .expect("preserve parent mode after ACL injection");
            let parent_identity = FileIdentity::capture(
                &fixture.namespace,
                &parent_file,
                "inspect parent ACL fixture",
            )
            .expect("capture parent ACL identity");
            assert!(validate_parent(&spec, &parent_file, parent_identity).is_err());
            parent_file
                .remove_xattr("system.posix_acl_access")
                .expect("remove nontrivial parent ACL");
            fs::set_permissions(&fixture.namespace, fs::Permissions::from_mode(0o750))
                .expect("restore parent mode after ACL removal");
        }

        fs::set_permissions(&fixture.outer, fs::Permissions::from_mode(0o777))
            .expect("inject writable ancestor");
        assert!(validate_ancestors(&fixture.namespace).is_err());
        fs::set_permissions(&fixture.outer, fs::Permissions::from_mode(0o755))
            .expect("restore protected ancestor");

        let slot = fixture.namespace.join(SNAPSHOT_DATA_NAMES[0]);
        let held = fixture.outer.join("held-slot");
        fs::rename(&slot, &held).expect("move slot for symlink fixture");
        std::os::unix::fs::symlink(&held, &slot).expect("inject slot symlink");
        assert!(
            rustix::fs::open(
                &slot,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .is_err()
        );
        fs::remove_file(&slot).expect("remove slot symlink");
        fs::rename(&held, &slot).expect("restore held slot");

        let writer = fixture.namespace.join(WRITER_LOCK_NAME);
        fs::write(&writer, b"x").expect("inject nonempty fixed writer lock");
        assert!(validate_catalog_lengths(&held_fixture_entries(&fixture.namespace)).is_err());
        File::options()
            .write(true)
            .open(&writer)
            .expect("open fixed writer lock for restoration")
            .set_len(0)
            .expect("restore empty fixed writer lock");

        let selector = fixture.namespace.join(SELECTOR_NAME);
        let selector_bytes = fs::read(&selector).expect("capture selector bytes");
        File::options()
            .write(true)
            .open(&selector)
            .expect("open selector length fixture")
            .set_len((SELECTOR_LEN - 1) as u64)
            .expect("inject malformed selector length");
        assert!(validate_catalog_lengths(&held_fixture_entries(&fixture.namespace)).is_err());
        fs::write(&selector, selector_bytes).expect("restore fixed selector bytes");

        let metadata = fixture.namespace.join(SNAPSHOT_METADATA_NAMES[0]);
        let metadata_bytes = fs::read(&metadata).expect("capture metadata bytes");
        File::options()
            .write(true)
            .open(&metadata)
            .expect("open metadata length fixture")
            .set_len(1)
            .expect("inject torn metadata length");
        assert!(validate_catalog_lengths(&held_fixture_entries(&fixture.namespace)).is_ok());
        File::options()
            .write(true)
            .open(&metadata)
            .expect("open oversized metadata fixture")
            .set_len((METADATA_LEN + 1) as u64)
            .expect("inject oversized metadata length");
        assert!(validate_catalog_lengths(&held_fixture_entries(&fixture.namespace)).is_err());
        fs::write(&metadata, metadata_bytes).expect("restore metadata bytes");

        let slot_bytes = fs::read(&slot).expect("capture snapshot slot bytes");
        File::options()
            .write(true)
            .open(&slot)
            .expect("open oversized slot fixture")
            .set_len(protected_catalog::MAX_SNAPSHOT_BYTES + 1)
            .expect("inject oversized snapshot slot");
        assert!(validate_catalog_lengths(&held_fixture_entries(&fixture.namespace)).is_err());
        fs::write(&slot, slot_bytes).expect("restore snapshot slot bytes");

        let database_bytes = fs::read(&database).expect("capture database bytes");
        File::options()
            .write(true)
            .open(&database)
            .expect("open empty database fixture")
            .set_len(0)
            .expect("inject empty protected database");
        assert!(validate_catalog_lengths(&held_fixture_entries(&fixture.namespace)).is_err());
        fs::write(&database, database_bytes).expect("restore protected database bytes");
        assert_eq!(exact_names(&fixture.namespace), expected_names());
    }

    #[test]
    fn filesystem_magic_allowlist_is_conservative() {
        for allowed in [EXT_FAMILY_MAGIC, XFS_MAGIC, BTRFS_MAGIC, F2FS_MAGIC] {
            assert!(filesystem_magic_allowed(allowed));
        }
        for rejected in [
            0x0102_1997,
            0x6969,
            0xff53_4d42,
            0xfe53_4d42,
            0x6573_5546,
            0x794c_7630,
            0x9fa0,
            0x5346_544e,
            0,
            u64::MAX,
        ] {
            assert!(!filesystem_magic_allowed(rejected));
        }
    }

    #[test]
    fn namespace_contract_names_are_exact_and_stable() {
        assert_eq!(
            ENTRY_NAMES,
            [
                "state.sqlite",
                "state.sqlite-wal",
                "state.writer.lock",
                "snapshot-0.sqlite",
                "snapshot-0.meta",
                "snapshot-1.sqlite",
                "snapshot-1.meta",
                "snapshot.selector",
            ]
        );
        assert_eq!(
            ENTRY_NAMES.iter().collect::<HashSet<_>>().len(),
            ENTRY_NAMES.len()
        );
        assert_eq!(
            std::ffi::OsStr::new(ENTRY_NAMES[DATABASE_INDEX]),
            "state.sqlite"
        );
    }

    #[test]
    fn namespace_identity_predicates_reject_every_security_field_mismatch() {
        let spec = LinuxProtectedSpec::new(
            PathBuf::from("/var/lib/gta-claw/state"),
            SERVICE_UID,
            SERVICE_GID,
        );
        let parent = FileIdentity {
            device: 11,
            inode: 12,
            mode: 0o040750,
            uid: 0,
            gid: SERVICE_GID,
            links: 2,
            special_device: 0,
        };
        assert!(parent_identity_matches(&spec, parent, true));
        for mismatch in [
            FileIdentity { uid: 1, ..parent },
            FileIdentity { gid: 1, ..parent },
            FileIdentity {
                mode: 0o040700,
                ..parent
            },
            FileIdentity {
                mode: 0o040770,
                ..parent
            },
        ] {
            assert!(!parent_identity_matches(&spec, mismatch, true));
        }
        assert!(!parent_identity_matches(&spec, parent, false));

        let entry = FileIdentity {
            device: parent.device,
            inode: 21,
            mode: 0o100600,
            uid: SERVICE_UID,
            gid: SERVICE_GID,
            links: 1,
            special_device: 0,
        };
        assert!(entry_identity_matches(&spec, parent.device, entry, true));
        for mismatch in [
            FileIdentity {
                device: parent.device + 1,
                ..entry
            },
            FileIdentity { uid: 1, ..entry },
            FileIdentity { gid: 1, ..entry },
            FileIdentity {
                mode: 0o100640,
                ..entry
            },
            FileIdentity { links: 2, ..entry },
        ] {
            assert!(!entry_identity_matches(
                &spec,
                parent.device,
                mismatch,
                true
            ));
        }
        assert!(!entry_identity_matches(&spec, parent.device, entry, false));
    }

    #[test]
    fn namespace_spec_rejects_zero_identity_and_noncanonical_paths() {
        for spec in [
            LinuxProtectedSpec::new(PathBuf::from("/var/lib/gta-claw/state"), 0, SERVICE_GID),
            LinuxProtectedSpec::new(PathBuf::from("/var/lib/gta-claw/state"), SERVICE_UID, 0),
            LinuxProtectedSpec::new(PathBuf::from("relative/state"), SERVICE_UID, SERVICE_GID),
            LinuxProtectedSpec::new(
                PathBuf::from("/var/lib/../gta-claw/state"),
                SERVICE_UID,
                SERVICE_GID,
            ),
        ] {
            assert!(validate_spec(&spec).is_err());
        }
    }

    #[test]
    fn linux_protected_rejects_mnt_c_filesystem() {
        let os_release =
            fs::read_to_string("/proc/sys/kernel/osrelease").expect("read Linux kernel release");
        if !os_release.to_ascii_lowercase().contains("microsoft") {
            return;
        }
        let path = Path::new("/mnt/c");
        assert!(
            path.try_exists()
                .expect("inspect whether the WSL /mnt/c rejection target exists"),
            "WSL rejection gate requires its standard /mnt/c mount"
        );
        let mount = File::open(path).expect("WSL /mnt/c must exist for the DrvFS rejection gate");
        let magic = rustix::fs::fstatfs(&mount)
            .expect("inspect WSL /mnt/c filesystem")
            .f_type as u64;
        assert!(!filesystem_magic_allowed(magic));
        assert!(validate_filesystem(path, &mount).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn linux_protected_root_lifecycle_and_catalog() {
        if let Some(mode) = std::env::var_os(SERVICE_CHILD_ENV) {
            let namespace = PathBuf::from(
                std::env::var_os(NAMESPACE_ENV)
                    .expect("service child receives protected namespace"),
            );
            let ready = PathBuf::from(
                std::env::var_os(READY_ENV).expect("service child receives readiness path"),
            );
            let control = PathBuf::from(
                std::env::var_os(CONTROL_ENV).expect("service child receives control path"),
            );
            match mode.to_str().expect("service child mode is UTF-8") {
                NORMAL_CHILD => exercise_service_store(&namespace).await,
                CRASH_CHILD => run_crash_service(&namespace, &ready).await,
                LOCK_PROBE_CHILD => run_lock_probe_service(&namespace).await,
                RECOVERY_CHILD => run_recovery_service(&namespace).await,
                RUNTIME_DROP_CHILD => run_runtime_drop_service(&namespace),
                GROUP_MISMATCH_CHILD => run_group_mismatch_service(&namespace).await,
                DEADLINE_CHILD => run_deadline_service(&namespace).await,
                REPOSITORY_OUTCOME_CHILD => {
                    run_repository_outcome_service(&namespace, &ready, &control).await
                }
                other => panic!("unknown LinuxProtected service child mode: {other}"),
            }
            return;
        }
        if run_root_driver() {
            return;
        }
        assert!(
            rustix::process::getuid().is_root() && rustix::process::geteuid().is_root(),
            "LinuxProtected acceptance requires a real/effective root driver"
        );
        let fixture = provision_root_fixture().await;
        let original_identities = entry_identities(&fixture.namespace);
        assert_child_success(
            service_child_command(
                &fixture.namespace,
                &fixture.ready,
                &fixture.control,
                GROUP_MISMATCH_CHILD,
            )
            .output()
            .expect("run supplementary-group rejection child"),
            "LinuxProtected supplementary-group rejection",
        );
        assert_child_success(
            service_child_command(
                &fixture.namespace,
                &fixture.ready,
                &fixture.control,
                NORMAL_CHILD,
            )
            .output()
            .expect("run LinuxProtected service child"),
            "LinuxProtected service lifecycle",
        );
        assert_eq!(exact_names(&fixture.namespace), expected_names());
        assert_eq!(entry_identities(&fixture.namespace), original_identities);
        exercise_repository_outcome_root(&fixture);
        assert_eq!(exact_names(&fixture.namespace), expected_names());
        assert_eq!(entry_identities(&fixture.namespace), original_identities);
        assert_child_success(
            service_child_command(
                &fixture.namespace,
                &fixture.ready,
                &fixture.control,
                RUNTIME_DROP_CHILD,
            )
            .output()
            .expect("run LinuxProtected runtime-drop child"),
            "LinuxProtected runtime-drop lifecycle",
        );
        assert_eq!(exact_names(&fixture.namespace), expected_names());
        assert_eq!(entry_identities(&fixture.namespace), original_identities);
        assert_child_success(
            service_child_command(
                &fixture.namespace,
                &fixture.ready,
                &fixture.control,
                DEADLINE_CHILD,
            )
            .output()
            .expect("run LinuxProtected deadline child"),
            "LinuxProtected immutable deadline lifecycle",
        );
        assert_eq!(exact_names(&fixture.namespace), expected_names());
        assert_eq!(entry_identities(&fixture.namespace), original_identities);
        exercise_hard_death_root(&fixture);
        let parent = fs::symlink_metadata(&fixture.namespace)
            .expect("inspect protected namespace after service lifecycle");
        assert_eq!(parent.uid(), 0);
        assert_eq!(parent.gid(), SERVICE_GID);
        assert_eq!(parent.mode() & 0o7777, 0o750);
        for name in ENTRY_NAMES {
            let metadata = fs::symlink_metadata(fixture.namespace.join(name))
                .unwrap_or_else(|error| panic!("inspect protected {name}: {error}"));
            assert!(metadata.file_type().is_file());
            assert_eq!(metadata.uid(), SERVICE_UID);
            assert_eq!(metadata.gid(), SERVICE_GID);
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        assert_root_negative_namespace_cases(&fixture);
        assert_eq!(exact_names(&fixture.namespace), expected_names());
        assert_eq!(entry_identities(&fixture.namespace), original_identities);
    }
}

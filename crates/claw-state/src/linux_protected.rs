use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqliteLockingMode, SqliteSynchronous};
use sqlx::{Connection as _, SqliteConnection};

use crate::StateError;
use crate::error::{database, database_code};
use crate::protected_catalog::{
    self, CatalogIdentity, METADATA_LEN, PublicationPlan, RecoveredSnapshot, SELECTOR_CELL_LEN,
    SELECTOR_LEN, SlotObservation,
};
use crate::protected_layout::{DATABASE_NAME, ENTRY_NAMES, WRITER_LOCK_NAME};
#[cfg(test)]
use crate::protected_layout::{
    SELECTOR_NAME, SNAPSHOT_DATA_NAMES, SNAPSHOT_METADATA_NAMES, WAL_NAME,
};
use crate::provision::LinuxProtectedInitialization;

const DATABASE_INDEX: usize = 0;
const WAL_INDEX: usize = 1;
const WRITER_LOCK_INDEX: usize = 2;
const SLOT_DATA_INDEX: [usize; 2] = [3, 5];
const SLOT_METADATA_INDEX: [usize; 2] = [4, 6];
const PREP_RECORD_INDEX: usize = SLOT_METADATA_INDEX[1];
const SELECTOR_INDEX: usize = 7;
const PREP_RECORD_LEN: usize = 128;
const PREP_RECORD_MAGIC: &[u8; 16] = b"CLAW-INIT-PREP01";
const SQLITE_PENDING_BYTE: u64 = 0x4000_0000;
const MAX_RAW_SCHEMA_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_RAW_INDEX_KEY_BYTES: usize = 4 * 1024;
const MAX_RAW_APPLICATION_ROW_BYTES: usize = 64 * 1024 * 1024;
const MAX_RAW_TEXT_FIELD_BYTES: usize = MAX_RAW_APPLICATION_ROW_BYTES;
const MAX_RAW_ID_BYTES: usize = 128;
// Offline verification is deliberately bounded by the fixed protected-catalog
// publication ceiling rather than trusting page/frame counts from service-owned bytes.
const MAX_OFFLINE_DATABASE_BYTES: u64 = protected_catalog::MAX_SNAPSHOT_BYTES;
const MAX_OFFLINE_WAL_BYTES: u64 = 2 * protected_catalog::MAX_SNAPSHOT_BYTES;
const MAX_OFFLINE_WAL_FRAMES: usize = 262_144;
const MAX_OFFLINE_SCHEMA_ROWS: usize = 32;
const MAX_OFFLINE_APPLICATION_ROWS: u64 = 262_144;
const MAX_OFFLINE_BTREE_CELLS: u64 = 1_000_000;
const MAX_OFFLINE_FREELIST_PAGES: u32 = 65_536;

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
#[cfg(test)]
static OFFLINE_INITIALIZER_TEST_FAULT: std::sync::LazyLock<
    Mutex<Vec<OfflineInitializerTestStage>>,
> = std::sync::LazyLock::new(|| Mutex::new(Vec::new()));
#[cfg(test)]
static OFFLINE_INITIALIZER_TEST_CLASSIFICATION_SNAPSHOT: std::sync::LazyLock<
    Mutex<Option<Vec<Vec<u8>>>>,
> = std::sync::LazyLock::new(|| Mutex::new(None));
#[cfg(test)]
static OFFLINE_INITIALIZER_TEST_RETAINED_NAMESPACES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OfflineInitializerReaperTestState {
    worker_transitioned: bool,
    caller_handoff: bool,
    release_worker: bool,
    classifier_failed: bool,
    namespace_retained: bool,
}
#[cfg(test)]
struct OfflineInitializerReaperTestGate {
    state: Mutex<OfflineInitializerReaperTestState>,
    changed: std::sync::Condvar,
}
#[cfg(test)]
static OFFLINE_INITIALIZER_REAPER_TEST_GATE: std::sync::LazyLock<
    Mutex<Option<Arc<OfflineInitializerReaperTestGate>>>,
> = std::sync::LazyLock::new(|| Mutex::new(None));

#[cfg(test)]
impl OfflineInitializerReaperTestGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(OfflineInitializerReaperTestState::default()),
            changed: std::sync::Condvar::new(),
        }
    }

    fn wait_for(&self, observe: fn(OfflineInitializerReaperTestState) -> bool, operation: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut state = self
            .state
            .lock()
            .expect("offline initializer reaper test gate lock poisoned");
        while !observe(*state) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "{operation} timed out");
            let (next, wait) = self
                .changed
                .wait_timeout(state, remaining)
                .expect("offline initializer reaper test gate lock poisoned");
            state = next;
            assert!(
                !wait.timed_out() || observe(*state),
                "{operation} timed out"
            );
        }
    }

    fn record_worker_transition_and_wait(&self) {
        let mut state = self
            .state
            .lock()
            .expect("offline initializer reaper test gate lock poisoned");
        state.worker_transitioned = true;
        self.changed.notify_all();
        while !state.release_worker {
            state = self
                .changed
                .wait(state)
                .expect("offline initializer reaper test gate lock poisoned");
        }
    }

    fn record_caller_handoff(&self) {
        let mut state = self
            .state
            .lock()
            .expect("offline initializer reaper test gate lock poisoned");
        state.caller_handoff = true;
        self.changed.notify_all();
    }

    fn release_worker(&self) {
        let mut state = self
            .state
            .lock()
            .expect("offline initializer reaper test gate lock poisoned");
        state.release_worker = true;
        self.changed.notify_all();
    }

    fn record_classifier_failure(&self) {
        let mut state = self
            .state
            .lock()
            .expect("offline initializer reaper test gate lock poisoned");
        state.classifier_failed = true;
        self.changed.notify_all();
    }

    fn record_namespace_retention(&self) {
        let mut state = self
            .state
            .lock()
            .expect("offline initializer reaper test gate lock poisoned");
        state.namespace_retained = true;
        self.changed.notify_all();
    }

    fn snapshot(&self) -> OfflineInitializerReaperTestState {
        *self
            .state
            .lock()
            .expect("offline initializer reaper test gate lock poisoned")
    }
}

#[cfg(test)]
fn offline_initializer_reaper_test_gate() -> Option<Arc<OfflineInitializerReaperTestGate>> {
    OFFLINE_INITIALIZER_REAPER_TEST_GATE
        .lock()
        .expect("offline initializer reaper test gate registry lock poisoned")
        .clone()
}

#[cfg(test)]
fn install_offline_initializer_reaper_test_gate() -> Arc<OfflineInitializerReaperTestGate> {
    let gate = Arc::new(OfflineInitializerReaperTestGate::new());
    let previous = OFFLINE_INITIALIZER_REAPER_TEST_GATE
        .lock()
        .expect("offline initializer reaper test gate registry lock poisoned")
        .replace(Arc::clone(&gate));
    assert!(
        previous.is_none(),
        "offline initializer reaper test gate is single-use"
    );
    gate
}

#[cfg(test)]
fn remove_offline_initializer_reaper_test_gate(gate: &Arc<OfflineInitializerReaperTestGate>) {
    let installed = OFFLINE_INITIALIZER_REAPER_TEST_GATE
        .lock()
        .expect("offline initializer reaper test gate registry lock poisoned")
        .take()
        .expect("offline initializer reaper test gate remains installed");
    assert!(Arc::ptr_eq(&installed, gate));
}

#[cfg(test)]
fn record_offline_initializer_reaper_classifier_failure() {
    if let Some(gate) = offline_initializer_reaper_test_gate() {
        gate.record_classifier_failure();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OfflineInitializerTestStage {
    PrepPrefix,
    PrepWrite,
    PrepSync,
    DeathAfterPrep,
    TransitionBeforeWal,
    Transition,
    Identity,
    HandlerCleanup,
    Close,
    WalSync,
    DatabaseSync,
    Deadline,
    RawValidation,
    SelectorData,
    SelectorWrite,
    SelectorPartialWrite,
    SelectorSync,
    SelectorParentSync,
    MarkerCleanup,
    FinalValidation,
    #[cfg(test)]
    RecoveryClassification,
    RollbackTruncate,
    RollbackEntrySyncFailure,
    RollbackSync,
}

#[cfg(test)]
impl OfflineInitializerTestStage {
    const fn failure_reason(self) -> &'static str {
        match self {
            Self::SelectorSync => "injected SelectorSync stage failure",
            Self::SelectorParentSync => "injected SelectorParentSync stage failure",
            Self::MarkerCleanup => "injected MarkerCleanup stage failure",
            Self::FinalValidation => "injected FinalValidation stage failure",
            Self::RecoveryClassification => "injected RecoveryClassification stage failure",
            Self::RollbackEntrySyncFailure => "injected RollbackEntrySyncFailure stage failure",
            _ => "injected private offline initializer stage failure",
        }
    }
}

#[cfg(test)]
fn fail_offline_initializer_stage(
    stage: OfflineInitializerTestStage,
    path: &Path,
) -> Result<(), StateError> {
    let mut scheduled = OFFLINE_INITIALIZER_TEST_FAULT
        .lock()
        .expect("offline initializer fault schedule lock poisoned");
    if scheduled.first() == Some(&stage) {
        scheduled.remove(0);
        Err(invalid_path(path, stage.failure_reason()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn offline_initializer_fault_is_next(stage: OfflineInitializerTestStage) -> bool {
    OFFLINE_INITIALIZER_TEST_FAULT
        .lock()
        .expect("offline initializer fault schedule lock poisoned")
        .first()
        == Some(&stage)
}

#[cfg(not(test))]
fn fail_offline_initializer_stage(
    _stage: OfflineInitializerTestStage,
    _path: &Path,
) -> Result<(), StateError> {
    Ok(())
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamespacePurpose {
    RuntimeService,
    OfflineRoot,
}

enum SelectorPublicationFailure {
    Precommit(StateError),
    Uncertain(StateError),
    Committed(StateError),
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

pub(crate) struct OfflineNamespacePreflight {
    database_path: PathBuf,
    database: File,
    database_identity: FileIdentity,
    writer_lock_path: PathBuf,
    writer_lock: File,
    writer_lock_identity: FileIdentity,
}

impl OfflineNamespacePreflight {
    pub(crate) fn open(spec: &LinuxProtectedSpec) -> Result<Self, StateError> {
        validate_root_credentials()?;
        validate_spec(spec)?;
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
                "open LinuxProtected directory for offline lock",
                &spec.directory,
                error.into(),
            )
        })?;
        let parent_identity = FileIdentity::capture(
            &spec.directory,
            &parent,
            "inspect LinuxProtected directory for offline lock",
        )?;
        validate_filesystem(&spec.directory, &parent)?;
        validate_ancestors(&spec.directory)?;
        validate_offline_ancestor_acls(&spec.directory)?;
        validate_parent(spec, &parent, parent_identity)?;

        let open_entry = |name: &'static str| -> Result<(PathBuf, File, FileIdentity), StateError> {
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
            .map_err(|error| {
                file_error(
                    "open LinuxProtected offline lock entry",
                    &path,
                    error.into(),
                )
            })?;
            let identity =
                FileIdentity::capture(&path, &file, "inspect LinuxProtected offline lock entry")?;
            validate_entry(spec, parent_identity.device, &path, &file, identity)?;
            Ok((path, file, identity))
        };
        let (database_path, database, database_identity) = open_entry(DATABASE_NAME)?;
        let (writer_lock_path, writer_lock, writer_identity) = open_entry(WRITER_LOCK_NAME)?;
        if (database_identity.device, database_identity.inode)
            == (writer_identity.device, writer_identity.inode)
        {
            return Err(invalid_path(
                &writer_lock_path,
                "LinuxProtected database and writer lock must have distinct identities",
            ));
        }
        if writer_lock
            .metadata()
            .map_err(|error| {
                file_error(
                    "inspect offline fixed writer lock length",
                    &writer_lock_path,
                    error,
                )
            })?
            .len()
            != 0
        {
            return Err(invalid_path(
                &writer_lock_path,
                "LinuxProtected fixed writer lock must be empty during offline initialization",
            ));
        }
        Ok(Self {
            database_path,
            database,
            database_identity,
            writer_lock_path,
            writer_lock,
            writer_lock_identity: writer_identity,
        })
    }

    pub(crate) fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub(crate) fn writer_lock_path(&self) -> &Path {
        &self.writer_lock_path
    }

    pub(crate) fn clone_database(&self) -> Result<File, StateError> {
        clone_file(
            &self.database,
            &self.database_path,
            "clone offline LinuxProtected database handle",
        )
    }

    pub(crate) fn clone_writer_lock(&self) -> Result<File, StateError> {
        clone_file(
            &self.writer_lock,
            &self.writer_lock_path,
            "clone offline LinuxProtected writer-lock handle",
        )
    }

    fn verify_locked_namespace(&self, namespace: &ProtectedNamespace) -> Result<(), StateError> {
        if namespace.entries[DATABASE_INDEX].identity != self.database_identity
            || namespace.entries[WRITER_LOCK_INDEX].identity != self.writer_lock_identity
        {
            return Err(invalid_path(
                &namespace.directory,
                "offline writer lock and held namespace do not name the same database identities",
            ));
        }
        Ok(())
    }
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
    purpose: NamespacePurpose,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ProtectedNamespace {
    pub(crate) fn open(spec: &LinuxProtectedSpec) -> Result<Arc<Self>, StateError> {
        Self::open_with_purpose(spec, NamespacePurpose::RuntimeService)
    }

    fn open_for_offline_initialization(spec: &LinuxProtectedSpec) -> Result<Arc<Self>, StateError> {
        Self::open_with_purpose(spec, NamespacePurpose::OfflineRoot)
    }

    fn open_with_purpose(
        spec: &LinuxProtectedSpec,
        purpose: NamespacePurpose,
    ) -> Result<Arc<Self>, StateError> {
        if purpose == NamespacePurpose::OfflineRoot {
            validate_root_credentials()?;
        }
        validate_spec(spec)?;
        if purpose == NamespacePurpose::RuntimeService {
            validate_service_credentials(spec)?;
            validate_ancestors(&spec.directory)?;
        }
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
        match purpose {
            NamespacePurpose::RuntimeService => {
                validate_parent(spec, &parent, parent_identity)?;
                validate_filesystem(&spec.directory, &parent)?;
            }
            NamespacePurpose::OfflineRoot => {
                validate_filesystem(&spec.directory, &parent)?;
                validate_ancestors(&spec.directory)?;
                validate_offline_ancestor_acls(&spec.directory)?;
                validate_parent(spec, &parent, parent_identity)?;
            }
        }
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
        if purpose == NamespacePurpose::RuntimeService {
            validate_catalog_lengths(&entries)?;
        }

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
            purpose,
        });
        match purpose {
            NamespacePurpose::RuntimeService => namespace.verify()?,
            NamespacePurpose::OfflineRoot => namespace.verify_security()?,
        }
        Ok(namespace)
    }

    pub(crate) fn directory_path(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn database_path(&self) -> &Path {
        &self.entries[DATABASE_INDEX].path
    }

    fn held_offline_database_path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            self.parent.as_raw_fd(),
            DATABASE_NAME
        ))
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
        self.verify_inner(true)
    }

    pub(crate) fn verify_security(&self) -> Result<(), StateError> {
        self.verify_inner(false)
    }

    fn verify_inner(&self, validate_catalog: bool) -> Result<(), StateError> {
        let spec = LinuxProtectedSpec {
            directory: self.directory.clone(),
            expected_uid: self.expected_uid,
            expected_gid: self.expected_gid,
        };
        validate_credentials(&spec, self.purpose)?;
        validate_ancestors(&self.directory)?;
        if self.purpose == NamespacePurpose::OfflineRoot {
            validate_offline_ancestor_acls(&self.directory)?;
        }
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
        if validate_catalog {
            match self.purpose {
                NamespacePurpose::RuntimeService => validate_catalog_lengths(&self.entries)?,
                NamespacePurpose::OfflineRoot => validate_offline_catalog_bounds(&self.entries)?,
            }
        }
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
        let mut bytes = try_zeroed_vec(
            &entry.path,
            length,
            "allocate bounded LinuxProtected entry buffer failed",
        )?;
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

    fn offline_state(
        &self,
        cutoff: Instant,
        timeout_ms: u64,
    ) -> Result<OfflineNamespaceState, StateError> {
        self.verify_security()?;
        let mut lengths = [0_u64; ENTRY_NAMES.len()];
        for (length, entry) in lengths.iter_mut().zip(&self.entries) {
            *length = entry
                .file
                .metadata()
                .map(|metadata| metadata.len())
                .map_err(|error| {
                    file_error(
                        "inspect offline LinuxProtected entry length",
                        &entry.path,
                        error,
                    )
                })?;
        }
        if lengths.iter().all(|length| *length == 0) {
            return Ok(OfflineNamespaceState::Fresh);
        }
        if lengths[WRITER_LOCK_INDEX] != 0 {
            return Err(invalid_path(
                &self.directory,
                "LinuxProtected namespace is partial rather than exactly fresh or initialized",
            ));
        }
        let selector =
            self.read_entry(SELECTOR_INDEX, SELECTOR_LEN, Some(cutoff), None, timeout_ms)?;
        let prep = self.read_entry(
            PREP_RECORD_INDEX,
            METADATA_LEN,
            Some(cutoff),
            None,
            timeout_ms,
        )?;
        let expected_prep = self.initializer_prep_record();
        let prep_prefix =
            prep.len() <= PREP_RECORD_LEN && prep.as_slice() == &expected_prep[..prep.len()];
        let other_initializer_catalog_empty = SLOT_DATA_INDEX
            .into_iter()
            .chain([SLOT_METADATA_INDEX[0]])
            .all(|index| lengths[index] == 0);

        if prep_prefix && !prep.is_empty() {
            if !other_initializer_catalog_empty
                || lengths[WAL_INDEX] != 0
                || selector.iter().any(|byte| *byte != 0)
            {
                return Err(invalid_path(
                    &self.directory,
                    "LinuxProtected initializer prep record accompanies unknown state",
                ));
            }
            if prep.len() < PREP_RECORD_LEN {
                if lengths[DATABASE_INDEX] != 0 || !selector.is_empty() {
                    return Err(invalid_path(
                        &self.directory,
                        "partial LinuxProtected prep record accompanies touched state",
                    ));
                }
                return Ok(OfflineNamespaceState::PreparingFresh);
            }
            if lengths[DATABASE_INDEX] == 0 {
                if !selector.is_empty() {
                    return Err(invalid_path(
                        self.selector_path(),
                        "pre-transition LinuxProtected selector is not empty",
                    ));
                }
                return Ok(OfflineNamespaceState::PreparedFresh);
            }
            self.validate_prepared_fresh_sqlite(cutoff, timeout_ms)?;
            return if selector.len() == SELECTOR_LEN {
                Ok(OfflineNamespaceState::InitializedFresh)
            } else {
                Ok(OfflineNamespaceState::TransitionedFresh)
            };
        }
        if selector.len() < SELECTOR_LEN
            || lengths[DATABASE_INDEX] == 0
            || lengths[SELECTOR_INDEX] != SELECTOR_LEN as u64
        {
            return Err(invalid_path(
                &self.directory,
                "LinuxProtected namespace is neither resumable nor initialized",
            ));
        }
        self.validate_initialized_sqlite_files(cutoff, timeout_ms)?;
        self.recover_catalog(self.catalog_identity(1), Some(cutoff), None, timeout_ms)?;
        Ok(OfflineNamespaceState::Initialized)
    }

    fn captured_identities(&self) -> [FileIdentity; 8] {
        std::array::from_fn(|index| self.entries[index].identity)
    }

    fn initializer_prep_record(&self) -> [u8; PREP_RECORD_LEN] {
        let mut record = [0_u8; PREP_RECORD_LEN];
        record[..16].copy_from_slice(PREP_RECORD_MAGIC);
        record[16..20].copy_from_slice(&1_u32.to_be_bytes());
        record[20..24].copy_from_slice(&(PREP_RECORD_LEN as u32).to_be_bytes());
        record[24..28].copy_from_slice(&(SELECTOR_LEN as u32).to_be_bytes());
        record[28..32].copy_from_slice(&(ENTRY_NAMES.len() as u32).to_be_bytes());
        record[32..40].copy_from_slice(&1_u64.to_be_bytes());
        let mut identities = Sha256::new();
        for entry in &self.entries {
            identities.update((entry.name.len() as u64).to_be_bytes());
            identities.update(entry.name.as_bytes());
            identities.update(entry.identity.device.to_be_bytes());
            identities.update(entry.identity.inode.to_be_bytes());
            identities.update(entry.identity.mode.to_be_bytes());
            identities.update(entry.identity.uid.to_be_bytes());
            identities.update(entry.identity.gid.to_be_bytes());
            identities.update(entry.identity.links.to_be_bytes());
            identities.update(entry.identity.special_device.to_be_bytes());
        }
        record[40..72].copy_from_slice(&identities.finalize());
        let checksum = Sha256::digest(&record[..96]);
        record[96..].copy_from_slice(&checksum);
        record
    }

    fn initialize_prep_record(&self) -> Result<(), StateError> {
        let entry = &self.entries[PREP_RECORD_INDEX];
        let expected = self.initializer_prep_record();
        let length = entry
            .file
            .metadata()
            .map_err(|error| {
                file_error(
                    "inspect LinuxProtected initializer prep record",
                    &entry.path,
                    error,
                )
            })?
            .len();
        if length > PREP_RECORD_LEN as u64 {
            return Err(invalid_path(
                &entry.path,
                "LinuxProtected initializer prep record exceeds its fixed length",
            ));
        }
        let existing = self.read_entry(PREP_RECORD_INDEX, PREP_RECORD_LEN, None, None, 0)?;
        if existing.as_slice() != &expected[..existing.len()] {
            return Err(invalid_path(
                &entry.path,
                "LinuxProtected initializer prep record prefix is invalid",
            ));
        }
        if existing.is_empty()
            && let Err(error) =
                fail_offline_initializer_stage(OfflineInitializerTestStage::PrepPrefix, &entry.path)
        {
            write_all_at(&entry.file, &expected[..32], 0)
                .and_then(|()| entry.file.sync_all())
                .map_err(|cleanup| StateError::OperationCleanupFailed {
                    operation: "inject LinuxProtected prep prefix",
                    primary: Box::new(invalid_path(
                        &entry.path,
                        "injected private offline initializer stage failure",
                    )),
                    cleanup: cleanup.to_string(),
                })?;
            return Err(error);
        }
        fail_offline_initializer_stage(OfflineInitializerTestStage::PrepWrite, &entry.path)?;
        write_all_at(&entry.file, &expected[existing.len()..], length).map_err(|error| {
            file_error(
                "write LinuxProtected initializer prep record",
                &entry.path,
                error,
            )
        })?;
        fail_offline_initializer_stage(OfflineInitializerTestStage::PrepSync, &entry.path)?;
        entry.file.sync_all().map_err(|error| {
            file_error(
                "sync LinuxProtected initializer prep record",
                &entry.path,
                error,
            )
        })?;
        self.parent.sync_all().map_err(|error| {
            file_error(
                "sync LinuxProtected namespace after prep record",
                &self.directory,
                error,
            )
        })?;
        let reread = self.read_entry(PREP_RECORD_INDEX, PREP_RECORD_LEN, None, None, 0)?;
        if reread.as_slice() != expected {
            return Err(invalid_path(
                &entry.path,
                "LinuxProtected initializer prep record failed exact reread",
            ));
        }
        Ok(())
    }

    fn cleanup_prep_record(&self) -> Result<(), StateError> {
        let entry = &self.entries[PREP_RECORD_INDEX];
        fail_offline_initializer_stage(OfflineInitializerTestStage::MarkerCleanup, &entry.path)?;
        entry
            .file
            .set_len(0)
            .and_then(|()| entry.file.sync_all())
            .map_err(|error| {
                file_error(
                    "remove LinuxProtected initializer prep record",
                    &entry.path,
                    error,
                )
            })?;
        self.parent.sync_all().map_err(|error| {
            file_error(
                "sync LinuxProtected namespace after prep cleanup",
                &self.directory,
                error,
            )
        })?;
        Ok(())
    }

    fn verify_captured_identities(&self, expected: [FileIdentity; 8]) -> Result<(), StateError> {
        self.verify_security()?;
        for (entry, expected) in self.entries.iter().zip(expected) {
            let current = FileIdentity::capture(
                &entry.path,
                &entry.file,
                "verify offline LinuxProtected entry identity",
            )?;
            if current != expected {
                return Err(invalid_path(
                    &entry.path,
                    "LinuxProtected entry identity changed during offline initialization",
                ));
            }
        }
        Ok(())
    }

    fn initialize_empty_selector(&self) -> Result<(), SelectorPublicationFailure> {
        let selector = &self.entries[SELECTOR_INDEX];
        let length = selector
            .file
            .metadata()
            .map_err(|error| {
                SelectorPublicationFailure::Precommit(file_error(
                    "inspect fresh LinuxProtected selector",
                    &selector.path,
                    error,
                ))
            })?
            .len();
        if length > SELECTOR_LEN as u64 {
            return Err(SelectorPublicationFailure::Precommit(invalid_path(
                &selector.path,
                "prepared LinuxProtected selector exceeds its fixed commit length",
            )));
        }
        let existing = self
            .read_entry(SELECTOR_INDEX, SELECTOR_LEN, None, None, 0)
            .map_err(SelectorPublicationFailure::Precommit)?;
        if existing.iter().any(|byte| *byte != 0) {
            return Err(SelectorPublicationFailure::Precommit(invalid_path(
                &selector.path,
                "prepared LinuxProtected selector contains nonzero bytes",
            )));
        }
        fail_offline_initializer_stage(OfflineInitializerTestStage::SelectorData, &selector.path)
            .map_err(SelectorPublicationFailure::Precommit)?;
        let offset = usize::try_from(length).expect("bounded selector length fits usize");
        fail_offline_initializer_stage(OfflineInitializerTestStage::SelectorWrite, &selector.path)
            .map_err(SelectorPublicationFailure::Precommit)?;
        if let Err(error) = fail_offline_initializer_stage(
            OfflineInitializerTestStage::SelectorPartialWrite,
            &selector.path,
        ) {
            let partial = offset + (SELECTOR_LEN - offset).div_ceil(2);
            write_all_at(
                &selector.file,
                &[0_u8; SELECTOR_LEN][offset..partial],
                length,
            )
            .and_then(|()| selector.file.sync_all())
            .map_err(|cleanup| {
                SelectorPublicationFailure::Precommit(StateError::OperationCleanupFailed {
                    operation: "inject partial LinuxProtected selector commit",
                    primary: Box::new(invalid_path(
                        &selector.path,
                        "injected private offline initializer stage failure",
                    )),
                    cleanup: cleanup.to_string(),
                })
            })?;
            return Err(SelectorPublicationFailure::Precommit(error));
        }
        if let Err(error) = write_all_at(&selector.file, &[0_u8; SELECTOR_LEN][offset..], length) {
            let primary = file_error(
                "initialize fixed LinuxProtected selector",
                &selector.path,
                error,
            );
            let full_length = selector.file.metadata().map(|metadata| metadata.len());
            return Err(match full_length {
                Ok(length) if length < SELECTOR_LEN as u64 => {
                    SelectorPublicationFailure::Precommit(primary)
                }
                _ => SelectorPublicationFailure::Uncertain(primary),
            });
        }
        fail_offline_initializer_stage(OfflineInitializerTestStage::SelectorSync, &selector.path)
            .map_err(SelectorPublicationFailure::Uncertain)?;
        selector.file.sync_all().map_err(|error| {
            SelectorPublicationFailure::Uncertain(file_error(
                "sync fixed LinuxProtected selector",
                &selector.path,
                error,
            ))
        })?;
        fail_offline_initializer_stage(
            OfflineInitializerTestStage::SelectorParentSync,
            &self.directory,
        )
        .map_err(SelectorPublicationFailure::Committed)?;
        self.parent.sync_all().map_err(|error| {
            SelectorPublicationFailure::Committed(file_error(
                "sync LinuxProtected namespace after selector initialization",
                &self.directory,
                error,
            ))
        })?;
        validate_catalog_lengths(&self.entries).map_err(SelectorPublicationFailure::Committed)
    }

    fn wal_length(&self) -> Result<u64, StateError> {
        self.entries[WAL_INDEX]
            .file
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(|error| {
                file_error(
                    "inspect offline LinuxProtected WAL length",
                    &self.entries[WAL_INDEX].path,
                    error,
                )
            })
    }

    fn validate_prepared_fresh_sqlite(
        &self,
        cutoff: Instant,
        timeout_ms: u64,
    ) -> Result<(), StateError> {
        check_initializer_deadline(cutoff, timeout_ms)?;
        self.verify_security()?;
        self.validate_initialized_sqlite_files(cutoff, timeout_ms)?;
        if self.wal_length()? != 0 {
            return Err(invalid_path(
                &self.entries[WAL_INDEX].path,
                "fresh LinuxProtected handoff must leave the precreated WAL at zero length",
            ));
        }
        let database = &self.entries[DATABASE_INDEX];
        let length = database
            .file
            .metadata()
            .map_err(|error| {
                file_error(
                    "inspect prepared LinuxProtected database length",
                    &database.path,
                    error,
                )
            })?
            .len();
        if length != 4096 {
            return Err(invalid_path(
                &database.path,
                "prepared LinuxProtected database is not the exact minimal handoff image",
            ));
        }
        let mut page = [0_u8; 4096];
        read_exact_at(
            &database.file,
            &mut page,
            0,
            &database.path,
            Some(cutoff),
            None,
            timeout_ms,
        )?;
        if !minimal_fresh_handoff_page(&page) {
            return Err(invalid_path(
                &database.path,
                "prepared LinuxProtected database bytes do not match the minimal empty-schema handoff",
            ));
        }
        check_initializer_deadline(cutoff, timeout_ms)
    }

    #[cfg(test)]
    fn fail_recovery_classification_for_test(&self) -> Result<(), StateError> {
        if !offline_initializer_fault_is_next(OfflineInitializerTestStage::RecoveryClassification) {
            return Ok(());
        }
        let snapshot = self
            .entries
            .iter()
            .map(|entry| {
                std::fs::read(&entry.path).map_err(|error| {
                    file_error(
                        "capture LinuxProtected classifier-error test snapshot",
                        &entry.path,
                        error,
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let previous = OFFLINE_INITIALIZER_TEST_CLASSIFICATION_SNAPSHOT
            .lock()
            .expect("offline initializer classification snapshot lock poisoned")
            .replace(snapshot);
        assert!(
            previous.is_none(),
            "offline initializer classification snapshot is single-use"
        );
        record_offline_initializer_reaper_classifier_failure();
        fail_offline_initializer_stage(
            OfflineInitializerTestStage::RecoveryClassification,
            &self.directory,
        )
    }

    fn recovery_fresh_state(&self) -> Result<OfflineNamespaceState, StateError> {
        self.verify_security()?;
        #[cfg(test)]
        self.fail_recovery_classification_for_test()?;
        let mut lengths = [0_u64; ENTRY_NAMES.len()];
        for (length, entry) in lengths.iter_mut().zip(&self.entries) {
            *length = entry
                .file
                .metadata()
                .map_err(|error| {
                    file_error(
                        "inspect recoverable LinuxProtected initializer state",
                        &entry.path,
                        error,
                    )
                })?
                .len();
        }
        if lengths.iter().all(|length| *length == 0) {
            return Ok(OfflineNamespaceState::Fresh);
        }
        let other_catalog_empty = SLOT_DATA_INDEX
            .into_iter()
            .chain([SLOT_METADATA_INDEX[0]])
            .all(|index| lengths[index] == 0);
        if lengths[WAL_INDEX] != 0
            || lengths[WRITER_LOCK_INDEX] != 0
            || lengths[SELECTOR_INDEX] > SELECTOR_LEN as u64
            || !other_catalog_empty
        {
            return Err(invalid_path(
                &self.directory,
                "failed fresh initialization is not safely recoverable",
            ));
        }
        let prep = self.read_entry(PREP_RECORD_INDEX, PREP_RECORD_LEN, None, None, 0)?;
        let expected = self.initializer_prep_record();
        if prep.is_empty() {
            if lengths[DATABASE_INDEX] == 4096 && lengths[SELECTOR_INDEX] == SELECTOR_LEN as u64 {
                let mut database = [0_u8; 4096];
                read_exact_at(
                    &self.entries[DATABASE_INDEX].file,
                    &mut database,
                    0,
                    &self.entries[DATABASE_INDEX].path,
                    None,
                    None,
                    0,
                )?;
                let selector = self.read_entry(SELECTOR_INDEX, SELECTOR_LEN, None, None, 0)?;
                if minimal_fresh_handoff_page(&database)
                    && selector.len() == SELECTOR_LEN
                    && selector.iter().all(|byte| *byte == 0)
                {
                    return Ok(OfflineNamespaceState::Initialized);
                }
            }
            return Err(invalid_path(
                &self.directory,
                "touched fresh initialization has no prep record",
            ));
        }
        if prep.as_slice() != &expected[..prep.len()] {
            return Err(invalid_path(
                &self.entries[PREP_RECORD_INDEX].path,
                "failed fresh initialization prep record is invalid",
            ));
        }
        if prep.len() < PREP_RECORD_LEN {
            if lengths[DATABASE_INDEX] == 0 && lengths[SELECTOR_INDEX] == 0 {
                return Ok(OfflineNamespaceState::PreparingFresh);
            }
            return Err(invalid_path(
                &self.directory,
                "partial prep record accompanies touched initializer state",
            ));
        }
        if lengths[DATABASE_INDEX] == 0 {
            if lengths[SELECTOR_INDEX] == 0 {
                return Ok(OfflineNamespaceState::PreparedFresh);
            }
            return Err(invalid_path(
                &self.directory,
                "pre-transition prep record accompanies selector bytes",
            ));
        }
        if lengths[DATABASE_INDEX] != 4096 {
            return Err(invalid_path(
                &self.directory,
                "failed fresh initialization database is not the minimal handoff",
            ));
        }
        let mut database = [0_u8; 4096];
        read_exact_at(
            &self.entries[DATABASE_INDEX].file,
            &mut database,
            0,
            &self.entries[DATABASE_INDEX].path,
            None,
            None,
            0,
        )?;
        let selector = self.read_entry(SELECTOR_INDEX, SELECTOR_LEN, None, None, 0)?;
        if !minimal_fresh_handoff_page(&database) || selector.iter().any(|byte| *byte != 0) {
            return Err(invalid_path(
                &self.directory,
                "failed fresh initialization does not match the exact resumable image",
            ));
        }
        if selector.len() == SELECTOR_LEN {
            Ok(OfflineNamespaceState::InitializedFresh)
        } else {
            Ok(OfflineNamespaceState::TransitionedFresh)
        }
    }

    fn restore_exact_fresh(
        &self,
        expected: [FileIdentity; ENTRY_NAMES.len()],
    ) -> Result<(), StateError> {
        self.verify_captured_identities(expected)?;
        fail_offline_initializer_stage(
            OfflineInitializerTestStage::RollbackTruncate,
            &self.directory,
        )?;
        let mut first_error = None;
        for index in [
            WAL_INDEX,
            DATABASE_INDEX,
            SLOT_DATA_INDEX[0],
            SLOT_METADATA_INDEX[0],
            SLOT_DATA_INDEX[1],
            SELECTOR_INDEX,
        ] {
            let entry = &self.entries[index];
            if let Err(error) = entry.file.set_len(0) {
                first_error = Some(file_error(
                    "truncate fresh LinuxProtected entry during failed initialization",
                    &entry.path,
                    error,
                ));
                continue;
            }
            if index == DATABASE_INDEX
                && first_error.is_none()
                && let Err(error) = fail_offline_initializer_stage(
                    OfflineInitializerTestStage::RollbackEntrySyncFailure,
                    &entry.path,
                )
            {
                first_error = Some(error);
                continue;
            }
            if let Err(error) = entry.file.sync_all()
                && first_error.is_none()
            {
                first_error = Some(file_error(
                    "sync fresh LinuxProtected entry during failed initialization",
                    &entry.path,
                    error,
                ));
            }
        }
        if first_error.is_none() {
            fail_offline_initializer_stage(
                OfflineInitializerTestStage::RollbackSync,
                &self.directory,
            )?;
            let prep = &self.entries[PREP_RECORD_INDEX];
            if let Err(error) = prep.file.set_len(0).and_then(|()| prep.file.sync_all()) {
                first_error = Some(file_error(
                    "remove LinuxProtected prep record after fresh rollback",
                    &prep.path,
                    error,
                ));
            }
            if first_error.is_none()
                && let Err(error) = self.parent.sync_all()
            {
                first_error = Some(file_error(
                    "sync LinuxProtected namespace after fresh rollback",
                    &self.directory,
                    error,
                ));
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        self.verify_captured_identities(expected)?;
        for entry in &self.entries {
            if entry
                .file
                .metadata()
                .map_err(|error| {
                    file_error(
                        "verify restored fresh LinuxProtected entry",
                        &entry.path,
                        error,
                    )
                })?
                .len()
                != 0
            {
                return Err(invalid_path(
                    &entry.path,
                    "failed initialization did not restore exact fresh bytes",
                ));
            }
        }
        Ok(())
    }

    fn validate_runtime_layout(&self, cutoff: Instant, timeout_ms: u64) -> Result<(), StateError> {
        check_initializer_deadline(cutoff, timeout_ms)?;
        self.verify()?;
        check_initializer_deadline(cutoff, timeout_ms)?;
        validate_catalog_lengths(&self.entries)?;
        self.recover_catalog(self.catalog_identity(1), Some(cutoff), None, timeout_ms)?;
        check_initializer_deadline(cutoff, timeout_ms)?;
        Ok(())
    }

    fn validate_initialized_sqlite_files(
        &self,
        cutoff: Instant,
        timeout_ms: u64,
    ) -> Result<(), StateError> {
        let database = &self.entries[DATABASE_INDEX];
        let database_length = database
            .file
            .metadata()
            .map_err(|error| {
                file_error(
                    "inspect initialized LinuxProtected database length",
                    &database.path,
                    error,
                )
            })?
            .len();
        if database_length > MAX_OFFLINE_DATABASE_BYTES {
            return Err(offline_resource_error(
                "initialized LinuxProtected database exceeds the offline verification bound",
            ));
        }
        if database_length < 100 {
            return Err(invalid_path(
                &database.path,
                "initialized LinuxProtected database has a truncated SQLite header",
            ));
        }
        let mut header = [0_u8; 100];
        read_exact_at(
            &database.file,
            &mut header,
            0,
            &database.path,
            Some(cutoff),
            None,
            timeout_ms,
        )?;
        if !header.starts_with(b"SQLite format 3\0") || header[18] != 2 || header[19] != 2 {
            return Err(invalid_path(
                &database.path,
                "initialized LinuxProtected database header is not a WAL-mode SQLite database",
            ));
        }
        let encoded_page_size = u16::from_be_bytes([header[16], header[17]]);
        let page_size = if encoded_page_size == 1 {
            65_536_u64
        } else {
            u64::from(encoded_page_size)
        };
        if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
            return Err(invalid_path(
                &database.path,
                "initialized LinuxProtected database page size is invalid",
            ));
        }
        if database_length < page_size || database_length % page_size != 0 {
            return Err(invalid_path(
                &database.path,
                "initialized LinuxProtected database does not contain complete SQLite pages",
            ));
        }
        let physical_pages = database_length / page_size;
        let page_size =
            usize::try_from(page_size).expect("validated SQLite page size fits this platform");
        let mut page_one = try_zeroed_vec(
            &database.path,
            page_size,
            "allocate bounded SQLite page-one buffer failed",
        )?;
        read_exact_at(
            &database.file,
            &mut page_one,
            0,
            &database.path,
            Some(cutoff),
            None,
            timeout_ms,
        )?;
        if database
            .file
            .metadata()
            .map_err(|error| {
                file_error(
                    "reinspect initialized LinuxProtected database length",
                    &database.path,
                    error,
                )
            })?
            .len()
            != database_length
        {
            return Err(invalid_path(
                &database.path,
                "initialized LinuxProtected database length changed during verification",
            ));
        }
        let wal = validate_offline_wal(
            &self.entries[WAL_INDEX],
            page_size as u64,
            cutoff,
            timeout_ms,
        )?;
        let effective_page_one = wal.page_one.as_deref().unwrap_or(&page_one);
        let header = parse_sqlite_header(
            &database.path,
            effective_page_one,
            page_size,
            physical_pages,
            wal.committed_pages,
        )?;
        let image = DatabaseImage {
            database,
            wal: &self.entries[WAL_INDEX],
            wal_frames: &wal.frames,
            page_size,
            usable_size: page_size - usize::from(header.reserved_bytes),
            physical_pages,
            logical_pages: header.logical_pages,
            cutoff,
            timeout_ms,
        };
        validate_database_image(&image, effective_page_one, header)
    }
}

struct WalObservation {
    committed_pages: Option<u32>,
    page_one: Option<Vec<u8>>,
    frames: HashMap<u32, u64>,
}

#[derive(Clone, Copy)]
struct SqliteHeader {
    logical_pages: u32,
    reserved_bytes: u8,
    freelist_trunk: u32,
    freelist_pages: u32,
    schema_format: u32,
    encoding: u32,
    user_version: u32,
    application_id: u32,
}

fn parse_sqlite_header(
    path: &Path,
    page_one: &[u8],
    expected_page_size: usize,
    physical_pages: u64,
    committed_wal_pages: Option<u32>,
) -> Result<SqliteHeader, StateError> {
    if page_one.len() != expected_page_size
        || !page_one.starts_with(b"SQLite format 3\0")
        || page_one[18] != 2
        || page_one[19] != 2
        || page_one[21] != 64
        || page_one[22] != 32
        || page_one[23] != 32
    {
        return Err(invalid_path(
            path,
            "initialized LinuxProtected database header is invalid",
        ));
    }
    let encoded_page_size = u16::from_be_bytes([page_one[16], page_one[17]]);
    let page_size = if encoded_page_size == 1 {
        65_536
    } else {
        usize::from(encoded_page_size)
    };
    if page_size != expected_page_size {
        return Err(invalid_path(
            path,
            "effective SQLite page one changes the database page size",
        ));
    }
    let reserved_bytes = page_one[20];
    let usable_size = page_size.saturating_sub(usize::from(reserved_bytes));
    if usable_size < 480 {
        return Err(invalid_path(
            path,
            "initialized LinuxProtected database usable page size is invalid",
        ));
    }
    if page_one[72..92].iter().any(|byte| *byte != 0) {
        return Err(invalid_path(
            path,
            "initialized LinuxProtected database reserved header bytes are nonzero",
        ));
    }
    let schema_format = read_be_u32(page_one, 44);
    let encoding = read_be_u32(page_one, 56);
    if schema_format > 4 || encoding > 3 || (schema_format == 0) != (encoding == 0) {
        return Err(invalid_path(
            path,
            "initialized LinuxProtected database schema format or encoding is invalid",
        ));
    }
    if read_be_u32(page_one, 52) != 0 || read_be_u32(page_one, 64) != 0 {
        return Err(invalid_path(
            path,
            "LinuxProtected offline verification does not accept auto-vacuum databases",
        ));
    }
    let change_counter = read_be_u32(page_one, 24);
    let version_valid_for = read_be_u32(page_one, 92);
    let header_pages = read_be_u32(page_one, 28);
    let physical_pages = u32::try_from(physical_pages).map_err(|_| {
        invalid_path(
            path,
            "initialized LinuxProtected database page count exceeds SQLite bounds",
        )
    })?;
    let logical_pages = committed_wal_pages.unwrap_or({
        if header_pages != 0 && change_counter == version_valid_for {
            header_pages
        } else {
            physical_pages
        }
    });
    if logical_pages == 0 {
        return Err(invalid_path(
            path,
            "initialized LinuxProtected database has zero logical pages",
        ));
    }
    let logical_bytes = u64::from(logical_pages)
        .checked_mul(expected_page_size as u64)
        .ok_or_else(|| invalid_path(path, "SQLite logical database size overflowed"))?;
    if logical_bytes > MAX_OFFLINE_DATABASE_BYTES {
        return Err(offline_resource_error(
            "SQLite logical database exceeds the offline verification bound",
        ));
    }
    let freelist_pages = read_be_u32(page_one, 36);
    if freelist_pages > MAX_OFFLINE_FREELIST_PAGES {
        return Err(offline_resource_error(
            "SQLite freelist exceeds the offline verification bound",
        ));
    }
    Ok(SqliteHeader {
        logical_pages,
        reserved_bytes,
        freelist_trunk: read_be_u32(page_one, 32),
        freelist_pages,
        schema_format,
        encoding,
        user_version: read_be_u32(page_one, 60),
        application_id: read_be_u32(page_one, 68),
    })
}

struct DatabaseImage<'namespace> {
    database: &'namespace HeldEntry,
    wal: &'namespace HeldEntry,
    wal_frames: &'namespace HashMap<u32, u64>,
    page_size: usize,
    usable_size: usize,
    physical_pages: u64,
    logical_pages: u32,
    cutoff: Instant,
    timeout_ms: u64,
}

impl DatabaseImage<'_> {
    fn read_page(&self, page_number: u32) -> Result<Vec<u8>, StateError> {
        if page_number == 0 || page_number > self.logical_pages {
            return Err(invalid_path(
                &self.database.path,
                "SQLite page reference is outside the logical database",
            ));
        }
        let mut page = try_zeroed_vec(
            &self.database.path,
            self.page_size,
            "allocate bounded SQLite page buffer failed",
        )?;
        if let Some(offset) = self.wal_frames.get(&page_number) {
            read_exact_at(
                &self.wal.file,
                &mut page,
                *offset,
                &self.wal.path,
                Some(self.cutoff),
                None,
                self.timeout_ms,
            )?;
        } else {
            if u64::from(page_number) > self.physical_pages {
                return Err(invalid_path(
                    &self.database.path,
                    "logical SQLite page is absent from both main database and WAL",
                ));
            }
            let offset = u64::from(page_number - 1)
                .checked_mul(self.page_size as u64)
                .ok_or_else(|| {
                    invalid_path(&self.database.path, "SQLite page offset overflowed")
                })?;
            read_exact_at(
                &self.database.file,
                &mut page,
                offset,
                &self.database.path,
                Some(self.cutoff),
                None,
                self.timeout_ms,
            )?;
        }
        Ok(page)
    }

    fn claim_page(
        &self,
        claimed: &mut HashSet<u32>,
        page_number: u32,
        reason: &'static str,
    ) -> Result<(), StateError> {
        if page_number == 0 || page_number > self.logical_pages || claimed.contains(&page_number) {
            return Err(invalid_path(&self.database.path, reason));
        }
        claimed
            .try_reserve(1)
            .map_err(|_| offline_resource_error("allocate bounded SQLite page-claim set failed"))?;
        claimed.insert(page_number);
        Ok(())
    }

    fn pending_byte_page(&self) -> u32 {
        u32::try_from(SQLITE_PENDING_BYTE / self.page_size as u64 + 1)
            .expect("SQLite pending-byte page fits u32")
    }
}

fn validate_database_image(
    image: &DatabaseImage<'_>,
    _page_one: &[u8],
    header: SqliteHeader,
) -> Result<(), StateError> {
    let mut claimed = HashSet::new();
    claimed
        .try_reserve(usize::try_from(image.logical_pages).map_err(|_| {
            invalid_path(
                &image.database.path,
                "SQLite logical page count exceeds platform bounds",
            )
        })?)
        .map_err(|_| offline_resource_error("allocate bounded SQLite page-claim set failed"))?;
    validate_page_availability(image)?;
    let pending_byte_page = image.pending_byte_page();
    if pending_byte_page <= image.logical_pages {
        claimed.insert(pending_byte_page);
    }
    let mut btree_cells = 0_u64;
    let schema_records = validate_table_btree(image, 1, true, &mut claimed, &mut btree_cells)?;
    let schema_objects = validate_schema_records(&image.database.path, schema_records, header)?;
    let mut unique_roots = HashSet::new();
    unique_roots
        .try_reserve(schema_objects.len())
        .map_err(|_| offline_resource_error("allocate bounded SQLite schema-root set failed"))?;
    let mut index_counts = BTreeMap::new();
    for object in &schema_objects {
        if object.root == 1 || !unique_roots.insert(object.root) {
            return Err(invalid_path(
                &image.database.path,
                "sqlite_schema contains a duplicate or recursive root page",
            ));
        }
        match object.btree {
            SchemaBtree::Table => {
                validate_table_btree(image, object.root, false, &mut claimed, &mut btree_cells)?;
            }
            SchemaBtree::Index(columns) => {
                let count = validate_index_btree(
                    image,
                    object.root,
                    columns,
                    &mut claimed,
                    &mut btree_cells,
                )?;
                index_counts.insert(object.name.as_str(), count);
            }
        }
    }
    validate_freelist(image, header, &mut claimed)?;
    if claimed.len() != image.logical_pages as usize {
        return Err(invalid_path(
            &image.database.path,
            "SQLite logical database contains unreachable pages",
        ));
    }
    verify_application_records(image, &schema_objects, &index_counts, header.user_version)?;
    Ok(())
}

fn validate_page_availability(image: &DatabaseImage<'_>) -> Result<(), StateError> {
    let physical_pages = u32::try_from(image.physical_pages.min(u64::from(u32::MAX)))
        .expect("bounded physical page count fits u32");
    let pending = image.pending_byte_page();
    if image.wal_frames.contains_key(&pending) {
        return Err(invalid_path(
            &image.database.path,
            "committed WAL contains SQLite's reserved pending-byte page",
        ));
    }
    if image.logical_pages <= physical_pages {
        return Ok(());
    }
    let pending_is_missing = pending > physical_pages && pending <= image.logical_pages;
    let missing_pages = image.logical_pages - physical_pages - u32::from(pending_is_missing);
    let available = image
        .wal_frames
        .keys()
        .filter(|page| **page > physical_pages && **page <= image.logical_pages)
        .count();
    if usize::try_from(missing_pages).ok() != Some(available) {
        return Err(invalid_path(
            &image.database.path,
            "logical SQLite pages are absent from both main database and committed WAL",
        ));
    }
    for expected in (physical_pages + 1)..=image.logical_pages {
        if expected != pending && !image.wal_frames.contains_key(&expected) {
            return Err(invalid_path(
                &image.database.path,
                "committed WAL does not supply every logical page beyond the main database",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct TableBounds {
    minimum_exclusive: Option<i64>,
    maximum_inclusive: Option<i64>,
}

struct TableTask {
    page: u32,
    depth: usize,
    root: bool,
    bounds: TableBounds,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IndexValue {
    Integer(i64),
    Text(Vec<u8>),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct IndexKey(Vec<IndexValue>);

struct IndexTask {
    page: u32,
    depth: usize,
    root: bool,
    minimum_exclusive: Option<IndexKey>,
    maximum_exclusive: Option<IndexKey>,
}

struct BtreePage {
    bytes: Vec<u8>,
    page_type: u8,
    header_offset: usize,
    pointer_start: usize,
    cell_start: usize,
    cell_count: usize,
    occupied: Vec<(usize, usize)>,
}

fn read_btree_page(
    image: &DatabaseImage<'_>,
    claimed: &mut HashSet<u32>,
    page_number: u32,
) -> Result<BtreePage, StateError> {
    image.claim_page(
        claimed,
        page_number,
        "SQLite b-tree page is duplicated, reserved, or out of bounds",
    )?;
    let page = image.read_page(page_number)?;
    let header_offset = if page_number == 1 { 100 } else { 0 };
    if header_offset + 8 > image.usable_size {
        return Err(invalid_path(
            &image.database.path,
            "SQLite b-tree header is outside the usable page",
        ));
    }
    let page_type = page[header_offset];
    let header_length = match page_type {
        0x02 | 0x05 => 12_usize,
        0x0a | 0x0d => 8_usize,
        _ => {
            return Err(invalid_path(
                &image.database.path,
                "SQLite b-tree page type is invalid",
            ));
        }
    };
    let first_freeblock = usize::from(read_be_u16(&page, header_offset + 1));
    let cell_count = usize::from(read_be_u16(&page, header_offset + 3));
    if cell_count > (image.page_size - 8) / 6 {
        return Err(invalid_path(
            &image.database.path,
            "SQLite b-tree cell count exceeds the format maximum",
        ));
    }
    let encoded_cell_start = usize::from(read_be_u16(&page, header_offset + 5));
    let cell_start = if encoded_cell_start == 0 {
        65_536
    } else {
        encoded_cell_start
    };
    let pointer_start = header_offset + header_length;
    let pointer_end = pointer_start
        .checked_add(cell_count.checked_mul(2).ok_or_else(|| {
            invalid_path(&image.database.path, "SQLite cell pointer count overflowed")
        })?)
        .ok_or_else(|| {
            invalid_path(&image.database.path, "SQLite cell pointer array overflowed")
        })?;
    if page[header_offset + 7] > 60 || pointer_end > cell_start || cell_start > image.usable_size {
        return Err(invalid_path(
            &image.database.path,
            "SQLite b-tree page layout is invalid",
        ));
    }
    let occupied = validate_freeblocks(image, &page, first_freeblock, pointer_end)?;
    Ok(BtreePage {
        bytes: page,
        page_type,
        header_offset,
        pointer_start,
        cell_start,
        cell_count,
        occupied,
    })
}

fn btree_cell_offset(
    image: &DatabaseImage<'_>,
    page: &BtreePage,
    index: usize,
) -> Result<usize, StateError> {
    let pointer = page.pointer_start + index * 2;
    let offset = usize::from(read_be_u16(&page.bytes, pointer));
    if offset < page.cell_start || offset >= image.usable_size {
        return Err(invalid_path(
            &image.database.path,
            "SQLite b-tree cell pointer is invalid",
        ));
    }
    Ok(offset)
}

fn finish_btree_page(
    image: &DatabaseImage<'_>,
    mut occupied: Vec<(usize, usize)>,
) -> Result<(), StateError> {
    occupied.sort_unstable();
    for pair in occupied.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(invalid_path(
                &image.database.path,
                "SQLite b-tree cells or freeblocks overlap",
            ));
        }
    }
    Ok(())
}

fn charge_btree_cells(path: &Path, consumed: &mut u64, cells: usize) -> Result<(), StateError> {
    *consumed = consumed
        .checked_add(cells as u64)
        .ok_or_else(|| invalid_path(path, "SQLite b-tree cell budget overflowed"))?;
    if *consumed > MAX_OFFLINE_BTREE_CELLS {
        return Err(offline_resource_error(
            "SQLite b-tree cells exceed the offline verification bound",
        ));
    }
    Ok(())
}

fn validate_table_btree(
    image: &DatabaseImage<'_>,
    root: u32,
    collect_schema: bool,
    claimed: &mut HashSet<u32>,
    btree_cells: &mut u64,
) -> Result<Vec<SchemaRecord>, StateError> {
    let mut schema_records = Vec::new();
    walk_table_btree(
        image,
        root,
        claimed,
        collect_schema.then_some(MAX_RAW_SCHEMA_PAYLOAD_BYTES),
        btree_cells,
        &mut |_, payload| {
            if let Some(payload) = payload {
                if schema_records.len() == MAX_OFFLINE_SCHEMA_ROWS {
                    return Err(offline_resource_error(
                        "sqlite_schema exceeds the offline row bound",
                    ));
                }
                schema_records.try_reserve(1).map_err(|_| {
                    offline_resource_error("allocate bounded sqlite_schema records failed")
                })?;
                schema_records.push(parse_sqlite_schema_record(&image.database.path, payload)?);
            }
            Ok(())
        },
    )?;
    Ok(schema_records)
}

fn walk_table_btree(
    image: &DatabaseImage<'_>,
    root: u32,
    claimed: &mut HashSet<u32>,
    payload_limit: Option<usize>,
    btree_cells: &mut u64,
    inspect: &mut impl FnMut(i64, Option<&[u8]>) -> Result<(), StateError>,
) -> Result<(), StateError> {
    let mut stack = Vec::new();
    try_push_vec(
        &image.database.path,
        &mut stack,
        TableTask {
            page: root,
            depth: 0,
            root: true,
            bounds: TableBounds {
                minimum_exclusive: None,
                maximum_inclusive: None,
            },
        },
        "allocate bounded SQLite table traversal stack failed",
    )?;
    let mut leaf_depth = None;
    while let Some(task) = stack.pop() {
        let mut page = read_btree_page(image, claimed, task.page)?;
        charge_btree_cells(&image.database.path, btree_cells, page.cell_count)?;
        try_reserve_vec(
            &image.database.path,
            &mut page.occupied,
            page.cell_count,
            "allocate bounded SQLite table occupancy ranges failed",
        )?;
        if !matches!(page.page_type, 0x05 | 0x0d) {
            return Err(invalid_path(
                &image.database.path,
                "SQLite table b-tree mixes table and index page types",
            ));
        }
        if !task.root && page.cell_count == 0 {
            return Err(invalid_path(
                &image.database.path,
                "non-root SQLite table b-tree page is empty",
            ));
        }
        let mut keys = Vec::new();
        try_reserve_vec(
            &image.database.path,
            &mut keys,
            page.cell_count,
            "allocate bounded SQLite table keys failed",
        )?;
        let mut children = Vec::new();
        try_reserve_vec(
            &image.database.path,
            &mut children,
            page.cell_count.checked_add(1).ok_or_else(|| {
                invalid_path(&image.database.path, "SQLite table child count overflowed")
            })?,
            "allocate bounded SQLite table children failed",
        )?;
        for index in 0..page.cell_count {
            let offset = btree_cell_offset(image, &page, index)?;
            let (end, key, payload) = if page.page_type == 0x05 {
                ensure_range(image, offset, 4, image.usable_size)?;
                let child = read_be_u32(&page.bytes, offset);
                validate_page_reference(image, child)?;
                children.push(child);
                let (key, key_length) =
                    read_sqlite_varint(&page.bytes, offset + 4, image.usable_size)?;
                (offset + 4 + key_length, key as i64, None)
            } else {
                let (payload_size, payload_varint) =
                    read_sqlite_varint(&page.bytes, offset, image.usable_size)?;
                let rowid_start = offset + payload_varint;
                let (rowid, rowid_varint) =
                    read_sqlite_varint(&page.bytes, rowid_start, image.usable_size)?;
                let payload = validate_cell_payload(
                    image,
                    &page.bytes,
                    rowid_start + rowid_varint,
                    payload_size,
                    true,
                    claimed,
                    payload_limit,
                )?;
                (payload.0, rowid as i64, payload.1)
            };
            if task
                .bounds
                .minimum_exclusive
                .is_some_and(|minimum| key <= minimum)
                || task
                    .bounds
                    .maximum_inclusive
                    .is_some_and(|maximum| key > maximum)
                || keys.last().is_some_and(|previous| key <= *previous)
            {
                return Err(invalid_path(
                    &image.database.path,
                    "SQLite table b-tree rowids or separator keys are out of order",
                ));
            }
            if end > image.usable_size {
                return Err(invalid_path(
                    &image.database.path,
                    "SQLite b-tree cell exceeds the usable page",
                ));
            }
            keys.push(key);
            page.occupied.push((offset, end));
            if page.page_type == 0x0d {
                inspect(key, payload.as_deref())?;
            }
        }
        if page.page_type == 0x05 {
            let right = read_be_u32(&page.bytes, page.header_offset + 8);
            validate_page_reference(image, right)?;
            children.push(right);
            for child_index in (0..children.len()).rev() {
                try_push_vec(
                    &image.database.path,
                    &mut stack,
                    TableTask {
                        page: children[child_index],
                        depth: task.depth + 1,
                        root: false,
                        bounds: TableBounds {
                            minimum_exclusive: if child_index == 0 {
                                task.bounds.minimum_exclusive
                            } else {
                                Some(keys[child_index - 1])
                            },
                            maximum_inclusive: if child_index < keys.len() {
                                Some(keys[child_index])
                            } else {
                                task.bounds.maximum_inclusive
                            },
                        },
                    },
                    "allocate bounded SQLite table traversal stack failed",
                )?;
            }
        } else if leaf_depth
            .replace(task.depth)
            .is_some_and(|depth| depth != task.depth)
        {
            return Err(invalid_path(
                &image.database.path,
                "SQLite table b-tree leaves have inconsistent depths",
            ));
        }
        finish_btree_page(image, page.occupied)?;
    }
    Ok(())
}

fn validate_index_btree(
    image: &DatabaseImage<'_>,
    root: u32,
    columns: &'static [IndexColumn],
    claimed: &mut HashSet<u32>,
    btree_cells: &mut u64,
) -> Result<u64, StateError> {
    let mut stack = Vec::new();
    try_push_vec(
        &image.database.path,
        &mut stack,
        IndexTask {
            page: root,
            depth: 0,
            root: true,
            minimum_exclusive: None,
            maximum_exclusive: None,
        },
        "allocate bounded SQLite index traversal stack failed",
    )?;
    let mut leaf_depth = None;
    let mut entries = 0_u64;
    while let Some(task) = stack.pop() {
        let mut page = read_btree_page(image, claimed, task.page)?;
        charge_btree_cells(&image.database.path, btree_cells, page.cell_count)?;
        try_reserve_vec(
            &image.database.path,
            &mut page.occupied,
            page.cell_count,
            "allocate bounded SQLite index occupancy ranges failed",
        )?;
        if !matches!(page.page_type, 0x02 | 0x0a) {
            return Err(invalid_path(
                &image.database.path,
                "SQLite index b-tree mixes table and index page types",
            ));
        }
        if !task.root && page.cell_count == 0 {
            return Err(invalid_path(
                &image.database.path,
                "non-root SQLite index b-tree page is empty",
            ));
        }
        let mut keys = Vec::new();
        try_reserve_vec(
            &image.database.path,
            &mut keys,
            page.cell_count,
            "allocate bounded SQLite index keys failed",
        )?;
        entries = entries
            .checked_add(page.cell_count as u64)
            .ok_or_else(|| invalid_path(&image.database.path, "SQLite index count overflowed"))?;
        let mut children = Vec::new();
        try_reserve_vec(
            &image.database.path,
            &mut children,
            page.cell_count.checked_add(1).ok_or_else(|| {
                invalid_path(&image.database.path, "SQLite index child count overflowed")
            })?,
            "allocate bounded SQLite index children failed",
        )?;
        for index in 0..page.cell_count {
            let offset = btree_cell_offset(image, &page, index)?;
            let payload_offset = if page.page_type == 0x02 {
                ensure_range(image, offset, 4, image.usable_size)?;
                let child = read_be_u32(&page.bytes, offset);
                validate_page_reference(image, child)?;
                children.push(child);
                offset + 4
            } else {
                offset
            };
            let (payload_size, payload_varint) =
                read_sqlite_varint(&page.bytes, payload_offset, image.usable_size)?;
            let payload = validate_cell_payload(
                image,
                &page.bytes,
                payload_offset + payload_varint,
                payload_size,
                false,
                claimed,
                Some(MAX_RAW_INDEX_KEY_BYTES),
            )?;
            let key = parse_index_key(
                &image.database.path,
                payload
                    .1
                    .as_deref()
                    .expect("bounded index payload collection is requested"),
                columns,
            )?;
            if task
                .minimum_exclusive
                .as_ref()
                .is_some_and(|minimum| key <= *minimum)
                || task
                    .maximum_exclusive
                    .as_ref()
                    .is_some_and(|maximum| key >= *maximum)
                || keys.last().is_some_and(|previous| key <= *previous)
            {
                return Err(invalid_path(
                    &image.database.path,
                    "SQLite index keys or parent ranges are out of order",
                ));
            }
            if payload.0 > image.usable_size {
                return Err(invalid_path(
                    &image.database.path,
                    "SQLite index cell exceeds the usable page",
                ));
            }
            page.occupied.push((offset, payload.0));
            keys.push(key);
        }
        if page.page_type == 0x02 {
            let right = read_be_u32(&page.bytes, page.header_offset + 8);
            validate_page_reference(image, right)?;
            children.push(right);
            for child_index in (0..children.len()).rev() {
                let minimum_exclusive = if child_index == 0 {
                    task.minimum_exclusive
                        .as_ref()
                        .map(|key| try_clone_index_key(&image.database.path, key))
                        .transpose()?
                } else {
                    Some(try_clone_index_key(
                        &image.database.path,
                        &keys[child_index - 1],
                    )?)
                };
                let maximum_exclusive = if child_index < keys.len() {
                    Some(try_clone_index_key(
                        &image.database.path,
                        &keys[child_index],
                    )?)
                } else {
                    task.maximum_exclusive
                        .as_ref()
                        .map(|key| try_clone_index_key(&image.database.path, key))
                        .transpose()?
                };
                try_push_vec(
                    &image.database.path,
                    &mut stack,
                    IndexTask {
                        page: children[child_index],
                        depth: task.depth + 1,
                        root: false,
                        minimum_exclusive,
                        maximum_exclusive,
                    },
                    "allocate bounded SQLite index traversal stack failed",
                )?;
            }
        } else if leaf_depth
            .replace(task.depth)
            .is_some_and(|depth| depth != task.depth)
        {
            return Err(invalid_path(
                &image.database.path,
                "SQLite index b-tree leaves have inconsistent depths",
            ));
        }
        finish_btree_page(image, page.occupied)?;
    }
    Ok(entries)
}

fn validate_freeblocks(
    image: &DatabaseImage<'_>,
    page: &[u8],
    mut offset: usize,
    pointer_end: usize,
) -> Result<Vec<(usize, usize)>, StateError> {
    let mut ranges = Vec::new();
    let mut previous = 0_usize;
    while offset != 0 {
        ensure_range(image, offset, 4, image.usable_size)?;
        let next = usize::from(read_be_u16(page, offset));
        let size = usize::from(read_be_u16(page, offset + 2));
        if offset < pointer_end
            || size < 4
            || offset + size > image.usable_size
            || offset <= previous
            || (next != 0 && next <= offset)
        {
            return Err(invalid_path(
                &image.database.path,
                "SQLite b-tree freeblock chain is invalid",
            ));
        }
        try_push_vec(
            &image.database.path,
            &mut ranges,
            (offset, offset + size),
            "allocate bounded SQLite freeblock ranges failed",
        )?;
        previous = offset;
        offset = next;
    }
    Ok(ranges)
}

fn validate_cell_payload(
    image: &DatabaseImage<'_>,
    page: &[u8],
    payload_start: usize,
    payload_size: u64,
    table_leaf: bool,
    claimed: &mut HashSet<u32>,
    collect_limit: Option<usize>,
) -> Result<(usize, Option<Vec<u8>>), StateError> {
    if payload_size > u64::from(u32::MAX) {
        return Err(invalid_path(
            &image.database.path,
            "SQLite cell payload exceeds SQLite format bounds",
        ));
    }
    let payload_size = usize::try_from(payload_size).map_err(|_| {
        invalid_path(
            &image.database.path,
            "SQLite cell payload exceeds platform bounds",
        )
    })?;
    if collect_limit.is_some_and(|limit| payload_size > limit) {
        return Err(offline_resource_error(
            "SQLite metadata key payload exceeds the offline verification bound",
        ));
    }
    let min_local = ((image.usable_size - 12) * 32 / 255).saturating_sub(23);
    let max_local = if table_leaf {
        image.usable_size.saturating_sub(35)
    } else {
        ((image.usable_size - 12) * 64 / 255).saturating_sub(23)
    };
    let local = if payload_size <= max_local {
        payload_size
    } else {
        let candidate = min_local + (payload_size - min_local) % (image.usable_size - 4);
        if candidate > max_local {
            min_local
        } else {
            candidate
        }
    };
    let overflowed = payload_size > local;
    let end = payload_start
        .checked_add(local)
        .and_then(|value| value.checked_add(usize::from(overflowed) * 4))
        .ok_or_else(|| {
            invalid_path(
                &image.database.path,
                "SQLite cell payload offset overflowed",
            )
        })?;
    ensure_range(image, payload_start, end - payload_start, image.usable_size)?;
    let mut payload = match collect_limit {
        Some(_) => {
            let mut payload = Vec::new();
            payload.try_reserve_exact(payload_size).map_err(|_| {
                offline_resource_error("SQLite metadata key payload allocation failed")
            })?;
            Some(payload)
        }
        None => None,
    };
    if let Some(payload) = &mut payload {
        payload.extend_from_slice(&page[payload_start..payload_start + local]);
    }
    let mut remaining = payload_size - local;
    if remaining != 0 {
        let mut overflow = read_be_u32(page, payload_start + local);
        while remaining != 0 {
            image.claim_page(
                claimed,
                overflow,
                "SQLite overflow page is duplicated or out of bounds",
            )?;
            let overflow_page = image.read_page(overflow)?;
            let next = read_be_u32(&overflow_page, 0);
            let chunk = remaining.min(image.usable_size - 4);
            if let Some(payload) = &mut payload {
                payload.extend_from_slice(&overflow_page[4..4 + chunk]);
            }
            remaining -= chunk;
            if remaining == 0 {
                if next != 0 {
                    return Err(invalid_path(
                        &image.database.path,
                        "SQLite overflow chain continues past its payload",
                    ));
                }
            } else if next == 0 {
                return Err(invalid_path(
                    &image.database.path,
                    "SQLite overflow chain ends before its payload",
                ));
            }
            overflow = next;
        }
    }
    Ok((end, payload))
}

fn validate_freelist(
    image: &DatabaseImage<'_>,
    header: SqliteHeader,
    claimed: &mut HashSet<u32>,
) -> Result<(), StateError> {
    let mut trunk = header.freelist_trunk;
    let mut count = 0_u32;
    while trunk != 0 {
        image.claim_page(
            claimed,
            trunk,
            "SQLite freelist trunk is duplicated or out of bounds",
        )?;
        count = count.checked_add(1).ok_or_else(|| {
            invalid_path(&image.database.path, "SQLite freelist count overflowed")
        })?;
        if count > MAX_OFFLINE_FREELIST_PAGES {
            return Err(offline_resource_error(
                "SQLite freelist traversal exceeds the offline verification bound",
            ));
        }
        let page = image.read_page(trunk)?;
        let next = read_be_u32(&page, 0);
        let leaves = read_be_u32(&page, 4);
        let maximum = (image.usable_size / 4).saturating_sub(2);
        if leaves as usize > maximum {
            return Err(invalid_path(
                &image.database.path,
                "SQLite freelist trunk leaf count is invalid",
            ));
        }
        for index in 0..leaves as usize {
            let leaf = read_be_u32(&page, 8 + index * 4);
            image.claim_page(
                claimed,
                leaf,
                "SQLite freelist leaf is duplicated or out of bounds",
            )?;
            count = count.checked_add(1).ok_or_else(|| {
                invalid_path(&image.database.path, "SQLite freelist count overflowed")
            })?;
            if count > MAX_OFFLINE_FREELIST_PAGES {
                return Err(offline_resource_error(
                    "SQLite freelist traversal exceeds the offline verification bound",
                ));
            }
        }
        trunk = next;
    }
    if count != header.freelist_pages {
        return Err(invalid_path(
            &image.database.path,
            "SQLite freelist header count contradicts its pages",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum IndexColumn {
    Integer,
    Text,
}

const TEXT_ROWID_INDEX: &[IndexColumn] = &[IndexColumn::Text, IndexColumn::Integer];
const TEXT_INTEGER_TEXT_ROWID_INDEX: &[IndexColumn] = &[
    IndexColumn::Text,
    IndexColumn::Integer,
    IndexColumn::Text,
    IndexColumn::Integer,
];
const INTEGER_TEXT_ROWID_INDEX: &[IndexColumn] = &[
    IndexColumn::Integer,
    IndexColumn::Text,
    IndexColumn::Integer,
];

#[derive(Clone, Copy)]
enum SchemaBtree {
    Table,
    Index(&'static [IndexColumn]),
}

struct SchemaRecord {
    kind: String,
    name: String,
    table: String,
    root: u32,
    sql: Option<String>,
}

struct ValidatedSchemaObject {
    name: String,
    root: u32,
    btree: SchemaBtree,
}

struct ExpectedSchemaObject {
    kind: &'static str,
    table: String,
    sql: Option<String>,
    btree: SchemaBtree,
}

struct RecordField<'payload> {
    serial: u64,
    bytes: &'payload [u8],
}

fn validate_schema_records(
    path: &Path,
    records: Vec<SchemaRecord>,
    header: SqliteHeader,
) -> Result<Vec<ValidatedSchemaObject>, StateError> {
    if records.is_empty() {
        if header.user_version != 0 || header.application_id != 0 {
            return Err(invalid_path(
                path,
                "empty sqlite_schema contradicts the SQLite application header",
            ));
        }
        return Ok(Vec::new());
    }
    if header.schema_format != 4
        || header.encoding != 1
        || header.user_version == 0
        || header.user_version > crate::store::LATEST_SCHEMA_VERSION as u32
        || header.application_id != crate::store::APPLICATION_ID as u32
    {
        return Err(invalid_path(
            path,
            "sqlite_schema contradicts the accepted application header",
        ));
    }
    let mut expected = expected_schema_objects(path, header.user_version)?;
    let mut validated = Vec::new();
    try_reserve_vec(
        path,
        &mut validated,
        records.len(),
        "allocate bounded schema-object records failed",
    )?;
    for record in records {
        let Some(definition) = expected.remove(&record.name) else {
            return Err(invalid_path(
                path,
                "sqlite_schema contains an object outside the accepted migration catalog",
            ));
        };
        let normalized_sql = record
            .sql
            .as_deref()
            .map(|sql| normalize_schema_sql(path, sql))
            .transpose()?;
        if record.kind != definition.kind
            || record.table != definition.table
            || normalized_sql != definition.sql
        {
            return Err(invalid_path(
                path,
                "sqlite_schema object fields or SQL do not match the accepted migration catalog",
            ));
        }
        validated.push(ValidatedSchemaObject {
            name: record.name,
            root: record.root,
            btree: definition.btree,
        });
    }
    if !expected.is_empty() {
        return Err(invalid_path(
            path,
            "sqlite_schema omits objects required by its schema version",
        ));
    }
    Ok(validated)
}

fn expected_schema_objects(
    path: &Path,
    version: u32,
) -> Result<BTreeMap<String, ExpectedSchemaObject>, StateError> {
    let mut expected = BTreeMap::new();
    let sources = [
        (0_u32, crate::store::MIGRATION_TABLE_SQL),
        (1, include_str!("../migrations/0001_initial.sql")),
        (2, include_str!("../migrations/0002_pagination_indexes.sql")),
    ];
    for (minimum_version, source) in sources {
        if minimum_version > version {
            continue;
        }
        for statement in source
            .split(';')
            .map(str::trim)
            .filter(|sql| !sql.is_empty())
        {
            let mut sql = normalize_schema_sql(path, statement)?;
            if let Some(suffix) = sql.strip_prefix("CREATE TABLE IF NOT EXISTS ") {
                sql = format!("CREATE TABLE {suffix}");
            }
            let tokens = sql.split_whitespace().collect::<Vec<_>>();
            let (kind, name, table, btree) = match tokens.as_slice() {
                ["CREATE", "TABLE", name, ..] => (
                    "table",
                    (*name).to_owned(),
                    (*name).to_owned(),
                    SchemaBtree::Table,
                ),
                ["CREATE", "INDEX", name, "ON", table, ..] => {
                    let table = table.split('(').next().unwrap_or(table).to_owned();
                    let columns = accepted_index_columns(name).ok_or_else(|| {
                        invalid_path(
                            path,
                            "accepted migration index has no raw key specification",
                        )
                    })?;
                    (
                        "index",
                        (*name).to_owned(),
                        table,
                        SchemaBtree::Index(columns),
                    )
                }
                _ => {
                    return Err(invalid_path(
                        path,
                        "accepted migration SQL cannot be fingerprinted offline",
                    ));
                }
            };
            if expected
                .insert(
                    name,
                    ExpectedSchemaObject {
                        kind,
                        table,
                        sql: Some(sql),
                        btree,
                    },
                )
                .is_some()
            {
                return Err(invalid_path(
                    path,
                    "accepted migration catalog contains a duplicate object",
                ));
            }
        }
    }
    if version >= 1 {
        for (name, table) in [
            ("sqlite_autoindex_sessions_1", "sessions"),
            ("sqlite_autoindex_devices_1", "devices"),
            (
                "sqlite_autoindex_authentication_records_1",
                "authentication_records",
            ),
            ("sqlite_autoindex_tasks_1", "tasks"),
        ] {
            expected.insert(
                name.to_owned(),
                ExpectedSchemaObject {
                    kind: "index",
                    table: table.to_owned(),
                    sql: None,
                    btree: SchemaBtree::Index(TEXT_ROWID_INDEX),
                },
            );
        }
    }
    Ok(expected)
}

fn accepted_index_columns(name: &str) -> Option<&'static [IndexColumn]> {
    match name {
        "sqlite_autoindex_sessions_1"
        | "sqlite_autoindex_devices_1"
        | "sqlite_autoindex_authentication_records_1"
        | "sqlite_autoindex_tasks_1" => Some(TEXT_ROWID_INDEX),
        "authentication_records_device_order" | "tasks_session_order" => {
            Some(TEXT_INTEGER_TEXT_ROWID_INDEX)
        }
        "sessions_creation_order" | "devices_creation_order" => Some(INTEGER_TEXT_ROWID_INDEX),
        _ => None,
    }
}

fn normalize_schema_sql(_path: &Path, sql: &str) -> Result<String, StateError> {
    let mut normalized = String::new();
    normalized
        .try_reserve(sql.len())
        .map_err(|_| offline_resource_error("allocate bounded normalized schema SQL failed"))?;
    for token in sql.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.push_str(token);
    }
    Ok(normalized)
}

fn parse_sqlite_schema_record(path: &Path, payload: &[u8]) -> Result<SchemaRecord, StateError> {
    let fields = parse_sqlite_record(path, payload, 5)?;
    if fields.len() != 5 {
        return Err(invalid_path(
            path,
            "sqlite_schema record does not have five canonical columns",
        ));
    }
    let kind = decode_sqlite_text(path, &fields[0], "sqlite_schema type")?;
    let name = decode_sqlite_text(path, &fields[1], "sqlite_schema name")?;
    let table = decode_sqlite_text(path, &fields[2], "sqlite_schema table name")?;
    let root = decode_sqlite_integer(path, fields[3].serial, fields[3].bytes)?
        .ok_or_else(|| invalid_path(path, "sqlite_schema root page is null"))?;
    let root = u32::try_from(root)
        .ok()
        .filter(|root| *root != 0)
        .ok_or_else(|| invalid_path(path, "sqlite_schema root page is outside SQLite bounds"))?;
    let sql = if fields[4].serial == 0 {
        None
    } else {
        Some(decode_sqlite_text(path, &fields[4], "sqlite_schema SQL")?)
    };
    Ok(SchemaRecord {
        kind,
        name,
        table,
        root,
        sql,
    })
}

fn parse_index_key(
    path: &Path,
    payload: &[u8],
    columns: &[IndexColumn],
) -> Result<IndexKey, StateError> {
    let fields = parse_sqlite_record(path, payload, columns.len())?;
    if fields.len() != columns.len() {
        return Err(invalid_path(
            path,
            "SQLite index key has the wrong number of fields",
        ));
    }
    let mut values = Vec::new();
    try_reserve_vec(
        path,
        &mut values,
        fields.len(),
        "allocate bounded SQLite index values failed",
    )?;
    for (field, column) in fields.iter().zip(columns) {
        values.push(match column {
            IndexColumn::Integer => IndexValue::Integer(
                decode_sqlite_integer(path, field.serial, field.bytes)?.ok_or_else(|| {
                    invalid_path(path, "SQLite index integer key is unexpectedly null")
                })?,
            ),
            IndexColumn::Text => IndexValue::Text(try_clone_bytes(
                path,
                decode_sqlite_text_bytes(path, field, "SQLite index text key")?,
                "allocate bounded SQLite index text key failed",
            )?),
        });
    }
    Ok(IndexKey(values))
}

struct LogicalRecord {
    indexes: Vec<(&'static str, IndexKey)>,
    references: Vec<(&'static str, Vec<u8>)>,
    unique_id: Option<Vec<u8>>,
    migration: bool,
}

fn verify_application_records(
    image: &DatabaseImage<'_>,
    schema: &[ValidatedSchemaObject],
    index_counts: &BTreeMap<&str, u64>,
    user_version: u32,
) -> Result<(), StateError> {
    if schema.is_empty() {
        return Ok(());
    }
    let mut expected_index_counts = index_counts
        .keys()
        .map(|name| (*name, 0_u64))
        .collect::<BTreeMap<_, _>>();
    let mut unique_ids = HashSet::new();
    let mut migration_rows = 0_u32;
    let mut application_rows = 0_u64;
    let mut verification_cells = 0_u64;
    for table in schema
        .iter()
        .filter(|object| matches!(object.btree, SchemaBtree::Table))
    {
        let mut row_count = 0_u64;
        let mut table_claimed = HashSet::new();
        table_claimed
            .try_reserve(usize::try_from(image.logical_pages).map_err(|_| {
                invalid_path(
                    &image.database.path,
                    "SQLite logical page count exceeds platform bounds",
                )
            })?)
            .map_err(|_| {
                offline_resource_error("allocate bounded application page-claim set failed")
            })?;
        walk_table_btree(
            image,
            table.root,
            &mut table_claimed,
            Some(MAX_RAW_APPLICATION_ROW_BYTES),
            &mut verification_cells,
            &mut |rowid, payload| {
                row_count = row_count.checked_add(1).ok_or_else(|| {
                    invalid_path(&image.database.path, "SQLite table row count overflowed")
                })?;
                application_rows = application_rows.checked_add(1).ok_or_else(|| {
                    invalid_path(
                        &image.database.path,
                        "SQLite application row count overflowed",
                    )
                })?;
                if application_rows > MAX_OFFLINE_APPLICATION_ROWS {
                    return Err(offline_resource_error(
                        "SQLite application rows exceed the offline verification bound",
                    ));
                }
                let payload = payload.ok_or_else(|| {
                    invalid_path(
                        &image.database.path,
                        "SQLite application table leaf has no record payload",
                    )
                })?;
                let logical = validate_application_record(
                    &image.database.path,
                    &table.name,
                    rowid,
                    payload,
                    user_version,
                )?;
                if let Some(id) = logical.unique_id {
                    let table_identity = match table.name.as_str() {
                        "sessions" => 1_u8,
                        "devices" => 2,
                        "authentication_records" => 3,
                        "tasks" => 4,
                        _ => {
                            return Err(invalid_path(
                                &image.database.path,
                                "SQLite application identifier belongs to an unexpected table",
                            ));
                        }
                    };
                    unique_ids.try_reserve(1).map_err(|_| {
                        offline_resource_error("allocate bounded application identifier set failed")
                    })?;
                    if !unique_ids.insert((table_identity, id)) {
                        return Err(invalid_path(
                            &image.database.path,
                            "SQLite application primary key is duplicated",
                        ));
                    }
                }
                migration_rows += u32::from(logical.migration);
                for (index_name, key) in logical.indexes {
                    let index = schema_index(schema, index_name)?;
                    let SchemaBtree::Index(columns) = index.btree else {
                        unreachable!("accepted index object has index b-tree metadata");
                    };
                    if !index_contains_key(image, index.root, columns, &key)? {
                        return Err(invalid_path(
                            &image.database.path,
                            "SQLite table row is missing its exact index entry",
                        ));
                    }
                    let count = expected_index_counts.get_mut(index_name).ok_or_else(|| {
                        invalid_path(
                            &image.database.path,
                            "SQLite application row targets an absent index",
                        )
                    })?;
                    *count = count.checked_add(1).ok_or_else(|| {
                        invalid_path(
                            &image.database.path,
                            "SQLite expected index count overflowed",
                        )
                    })?;
                }
                for (index_name, prefix) in logical.references {
                    let index = schema_index(schema, index_name)?;
                    let SchemaBtree::Index(columns) = index.btree else {
                        unreachable!("accepted reference index has index b-tree metadata");
                    };
                    if !index_contains_text_prefix(image, index.root, columns, &prefix)? {
                        return Err(invalid_path(
                            &image.database.path,
                            "SQLite application row violates a foreign-key reference",
                        ));
                    }
                }
                Ok(())
            },
        )?;
        if table.name == "claw_writer_lock" && row_count > 1 {
            return Err(invalid_path(
                &image.database.path,
                "SQLite application writer table has multiple singleton rows",
            ));
        }
    }
    if migration_rows != user_version {
        return Err(invalid_path(
            &image.database.path,
            "SQLite migration rows contradict the application user version",
        ));
    }
    for (name, actual) in index_counts {
        if expected_index_counts.get(name).copied() != Some(*actual) {
            return Err(invalid_path(
                &image.database.path,
                "SQLite index contains missing or surplus application entries",
            ));
        }
    }
    Ok(())
}

fn schema_index<'schema>(
    schema: &'schema [ValidatedSchemaObject],
    name: &str,
) -> Result<&'schema ValidatedSchemaObject, StateError> {
    schema
        .iter()
        .find(|object| object.name == name)
        .ok_or_else(|| invalid_path(Path::new("state.sqlite"), "accepted SQLite index is absent"))
}

fn validate_application_record(
    path: &Path,
    table: &str,
    rowid: i64,
    payload: &[u8],
    user_version: u32,
) -> Result<LogicalRecord, StateError> {
    let expected_fields = match table {
        "claw_schema_migrations" => 4,
        "sessions" | "devices" => 5,
        "authentication_records" | "tasks" => 8,
        "claw_writer_lock" => 3,
        _ => {
            return Err(invalid_path(
                path,
                "SQLite application table is outside the accepted schema",
            ));
        }
    };
    let fields = parse_sqlite_record(path, payload, expected_fields)?;
    let mut indexes = Vec::new();
    let mut references = Vec::new();
    try_reserve_vec(
        path,
        &mut indexes,
        2,
        "allocate bounded application index mappings failed",
    )?;
    try_reserve_vec(
        path,
        &mut references,
        1,
        "allocate bounded application references failed",
    )?;
    let mut unique_id = None;
    let mut migration = false;
    match table {
        "claw_schema_migrations" => {
            require_field_count(path, &fields, 4)?;
            require_rowid_alias(path, &fields[0])?;
            let name = required_text(path, &fields[1], MAX_RAW_TEXT_FIELD_BYTES)?;
            let checksum = required_text(path, &fields[2], 64)?;
            let applied = required_integer(path, &fields[3])?;
            if rowid <= 0 || rowid > i64::from(user_version) || applied < 0 {
                return Err(invalid_path(
                    path,
                    "SQLite migration row values are invalid",
                ));
            }
            let (expected_name, source) = match rowid {
                1 => ("initial", include_str!("../migrations/0001_initial.sql")),
                2 => (
                    "pagination_indexes",
                    include_str!("../migrations/0002_pagination_indexes.sql"),
                ),
                _ => {
                    return Err(invalid_path(
                        path,
                        "SQLite migration version is unsupported",
                    ));
                }
            };
            if name != expected_name || checksum != migration_checksum(source) {
                return Err(invalid_path(
                    path,
                    "SQLite migration row does not match the embedded migration",
                ));
            }
            migration = true;
        }
        "sessions" => {
            require_field_count(path, &fields, 5)?;
            let id = required_id(path, &fields[0])?;
            let status = required_text(path, &fields[1], 16)?;
            let created = required_integer(path, &fields[2])?;
            let updated = required_integer(path, &fields[3])?;
            let version = required_integer(path, &fields[4])?;
            if !matches!(status.as_str(), "active" | "archived")
                || created < 0
                || updated < created
                || version < 1
            {
                return Err(invalid_path(
                    path,
                    "SQLite session row violates its constraints",
                ));
            }
            indexes.push((
                "sqlite_autoindex_sessions_1",
                try_index_key(
                    path,
                    [
                        IndexValue::Text(try_clone_bytes(
                            path,
                            &id,
                            "allocate bounded session index identifier failed",
                        )?),
                        IndexValue::Integer(rowid),
                    ],
                )?,
            ));
            if user_version >= 2 {
                indexes.push((
                    "sessions_creation_order",
                    try_index_key(
                        path,
                        [
                            IndexValue::Integer(created),
                            IndexValue::Text(try_clone_bytes(
                                path,
                                &id,
                                "allocate bounded session ordering identifier failed",
                            )?),
                            IndexValue::Integer(rowid),
                        ],
                    )?,
                ));
            }
            unique_id = Some(id);
        }
        "devices" => {
            require_field_count(path, &fields, 5)?;
            let id = required_id(path, &fields[0])?;
            let display_name = required_text(path, &fields[1], MAX_RAW_TEXT_FIELD_BYTES)?;
            let created = required_integer(path, &fields[2])?;
            let updated = required_integer(path, &fields[3])?;
            let version = required_integer(path, &fields[4])?;
            if !valid_model_text(&display_name) || created < 0 || updated < created || version < 1 {
                return Err(invalid_path(
                    path,
                    "SQLite device row violates its constraints",
                ));
            }
            indexes.push((
                "sqlite_autoindex_devices_1",
                try_index_key(
                    path,
                    [
                        IndexValue::Text(try_clone_bytes(
                            path,
                            &id,
                            "allocate bounded device index identifier failed",
                        )?),
                        IndexValue::Integer(rowid),
                    ],
                )?,
            ));
            if user_version >= 2 {
                indexes.push((
                    "devices_creation_order",
                    try_index_key(
                        path,
                        [
                            IndexValue::Integer(created),
                            IndexValue::Text(try_clone_bytes(
                                path,
                                &id,
                                "allocate bounded device ordering identifier failed",
                            )?),
                            IndexValue::Integer(rowid),
                        ],
                    )?,
                ));
            }
            unique_id = Some(id);
        }
        "authentication_records" => {
            require_field_count(path, &fields, 8)?;
            let id = required_id(path, &fields[0])?;
            let device_id = required_id(path, &fields[1])?;
            let provider = required_text(path, &fields[2], MAX_RAW_TEXT_FIELD_BYTES)?;
            let subject = optional_text(path, &fields[3], MAX_RAW_TEXT_FIELD_BYTES)?;
            let status = required_text(path, &fields[4], 16)?;
            let created = required_integer(path, &fields[5])?;
            let updated = required_integer(path, &fields[6])?;
            let version = required_integer(path, &fields[7])?;
            let valid_subject = match status.as_str() {
                "authorized" => subject.as_deref().is_some_and(valid_model_text),
                "pending" | "revoked" => subject.is_none(),
                _ => false,
            };
            if !valid_model_text(&provider)
                || !valid_subject
                || created < 0
                || updated < created
                || version < 1
            {
                return Err(invalid_path(
                    path,
                    "SQLite authentication row violates its constraints",
                ));
            }
            indexes.push((
                "sqlite_autoindex_authentication_records_1",
                try_index_key(
                    path,
                    [
                        IndexValue::Text(try_clone_bytes(
                            path,
                            &id,
                            "allocate bounded authentication index identifier failed",
                        )?),
                        IndexValue::Integer(rowid),
                    ],
                )?,
            ));
            indexes.push((
                "authentication_records_device_order",
                try_index_key(
                    path,
                    [
                        IndexValue::Text(try_clone_bytes(
                            path,
                            &device_id,
                            "allocate bounded authentication device identifier failed",
                        )?),
                        IndexValue::Integer(created),
                        IndexValue::Text(try_clone_bytes(
                            path,
                            &id,
                            "allocate bounded authentication ordering identifier failed",
                        )?),
                        IndexValue::Integer(rowid),
                    ],
                )?,
            ));
            references.push(("sqlite_autoindex_devices_1", device_id));
            unique_id = Some(id);
        }
        "tasks" => {
            require_field_count(path, &fields, 8)?;
            let id = required_id(path, &fields[0])?;
            let session_id = required_id(path, &fields[1])?;
            let kind = required_text(path, &fields[2], MAX_RAW_TEXT_FIELD_BYTES)?;
            let _payload = required_text(path, &fields[3], MAX_RAW_APPLICATION_ROW_BYTES)?;
            let status = required_text(path, &fields[4], 16)?;
            let created = required_integer(path, &fields[5])?;
            let updated = required_integer(path, &fields[6])?;
            let version = required_integer(path, &fields[7])?;
            if !valid_model_text(&kind)
                || !matches!(
                    status.as_str(),
                    "pending" | "running" | "succeeded" | "failed" | "cancelled"
                )
                || created < 0
                || updated < created
                || version < 1
            {
                return Err(invalid_path(
                    path,
                    "SQLite task row violates its constraints",
                ));
            }
            indexes.push((
                "sqlite_autoindex_tasks_1",
                try_index_key(
                    path,
                    [
                        IndexValue::Text(try_clone_bytes(
                            path,
                            &id,
                            "allocate bounded task index identifier failed",
                        )?),
                        IndexValue::Integer(rowid),
                    ],
                )?,
            ));
            indexes.push((
                "tasks_session_order",
                try_index_key(
                    path,
                    [
                        IndexValue::Text(try_clone_bytes(
                            path,
                            &session_id,
                            "allocate bounded task session identifier failed",
                        )?),
                        IndexValue::Integer(created),
                        IndexValue::Text(try_clone_bytes(
                            path,
                            &id,
                            "allocate bounded task ordering identifier failed",
                        )?),
                        IndexValue::Integer(rowid),
                    ],
                )?,
            ));
            references.push(("sqlite_autoindex_sessions_1", session_id));
            unique_id = Some(id);
        }
        "claw_writer_lock" => {
            require_field_count(path, &fields, 3)?;
            require_rowid_alias(path, &fields[0])?;
            let owner = required_text(path, &fields[1], MAX_RAW_TEXT_FIELD_BYTES)?;
            let acquired = required_integer(path, &fields[2])?;
            if rowid != 1 || owner.is_empty() || acquired < 0 {
                return Err(invalid_path(
                    path,
                    "SQLite application writer row violates its constraints",
                ));
            }
        }
        _ => {
            return Err(invalid_path(
                path,
                "SQLite application table is outside the accepted schema",
            ));
        }
    }
    Ok(LogicalRecord {
        indexes,
        references,
        unique_id,
        migration,
    })
}

fn valid_model_text(value: &str) -> bool {
    !value.contains('\0') && !value.trim().is_empty()
}

fn require_field_count(
    path: &Path,
    fields: &[RecordField<'_>],
    expected: usize,
) -> Result<(), StateError> {
    if fields.len() != expected {
        return Err(invalid_path(
            path,
            "SQLite application record has the wrong field count",
        ));
    }
    Ok(())
}

fn require_rowid_alias(path: &Path, field: &RecordField<'_>) -> Result<(), StateError> {
    if field.serial != 0 {
        return Err(invalid_path(
            path,
            "SQLite INTEGER PRIMARY KEY record field is not null",
        ));
    }
    Ok(())
}

fn required_integer(path: &Path, field: &RecordField<'_>) -> Result<i64, StateError> {
    decode_sqlite_integer(path, field.serial, field.bytes)?
        .ok_or_else(|| invalid_path(path, "SQLite application integer field is null"))
}

fn required_id(path: &Path, field: &RecordField<'_>) -> Result<Vec<u8>, StateError> {
    let id = required_text(path, field, MAX_RAW_ID_BYTES)?;
    if id.trim() != id || id.is_empty() || id.chars().any(char::is_control) {
        return Err(invalid_path(
            path,
            "SQLite application identifier is not canonical",
        ));
    }
    Ok(id.into_bytes())
}

fn required_text(
    path: &Path,
    field: &RecordField<'_>,
    maximum: usize,
) -> Result<String, StateError> {
    let bytes = decode_sqlite_text_bytes(path, field, "SQLite application text")?;
    if bytes.len() > maximum {
        return Err(offline_resource_error(
            "SQLite application text exceeds its offline verification bound",
        ));
    }
    try_utf8_owned(
        path,
        bytes,
        "SQLite application text is not valid UTF-8",
        "allocate bounded SQLite application text failed",
    )
}

fn optional_text(
    path: &Path,
    field: &RecordField<'_>,
    maximum: usize,
) -> Result<Option<String>, StateError> {
    if field.serial == 0 {
        Ok(None)
    } else {
        required_text(path, field, maximum).map(Some)
    }
}

fn migration_checksum(sql: &str) -> String {
    let normalized = sql.replace("\r\n", "\n").replace('\r', "\n");
    let digest = Sha256::digest(normalized.as_bytes());
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn read_index_search_page(
    image: &DatabaseImage<'_>,
    page_number: u32,
    columns: &'static [IndexColumn],
    claimed: &mut HashSet<u32>,
) -> Result<(u8, Vec<IndexKey>, Vec<u32>), StateError> {
    let mut page = read_btree_page(image, claimed, page_number)?;
    if !matches!(page.page_type, 0x02 | 0x0a) {
        return Err(invalid_path(
            &image.database.path,
            "SQLite index search reached a non-index page",
        ));
    }
    try_reserve_vec(
        &image.database.path,
        &mut page.occupied,
        page.cell_count,
        "allocate bounded SQLite search occupancy ranges failed",
    )?;
    let mut keys = Vec::new();
    try_reserve_vec(
        &image.database.path,
        &mut keys,
        page.cell_count,
        "allocate bounded SQLite search keys failed",
    )?;
    let mut children = Vec::new();
    try_reserve_vec(
        &image.database.path,
        &mut children,
        page.cell_count.checked_add(1).ok_or_else(|| {
            invalid_path(&image.database.path, "SQLite search child count overflowed")
        })?,
        "allocate bounded SQLite search children failed",
    )?;
    for index in 0..page.cell_count {
        let offset = btree_cell_offset(image, &page, index)?;
        let payload_offset = if page.page_type == 0x02 {
            ensure_range(image, offset, 4, image.usable_size)?;
            let child = read_be_u32(&page.bytes, offset);
            validate_page_reference(image, child)?;
            children.push(child);
            offset + 4
        } else {
            offset
        };
        let (payload_size, payload_varint) =
            read_sqlite_varint(&page.bytes, payload_offset, image.usable_size)?;
        let payload = validate_cell_payload(
            image,
            &page.bytes,
            payload_offset + payload_varint,
            payload_size,
            false,
            claimed,
            Some(MAX_RAW_INDEX_KEY_BYTES),
        )?;
        let key = parse_index_key(
            &image.database.path,
            payload
                .1
                .as_deref()
                .expect("index search requests bounded payload collection"),
            columns,
        )?;
        page.occupied.push((offset, payload.0));
        keys.push(key);
    }
    if page.page_type == 0x02 {
        let right = read_be_u32(&page.bytes, page.header_offset + 8);
        validate_page_reference(image, right)?;
        children.push(right);
    }
    finish_btree_page(image, page.occupied)?;
    Ok((page.page_type, keys, children))
}

fn index_contains_key(
    image: &DatabaseImage<'_>,
    root: u32,
    columns: &'static [IndexColumn],
    target: &IndexKey,
) -> Result<bool, StateError> {
    let mut page = root;
    let mut claimed = HashSet::new();
    loop {
        let (page_type, keys, children) =
            read_index_search_page(image, page, columns, &mut claimed)?;
        match keys.binary_search(target) {
            Ok(_) => return Ok(true),
            Err(_) if page_type == 0x0a => return Ok(false),
            Err(child) => page = children[child],
        }
    }
}

fn index_contains_text_prefix(
    image: &DatabaseImage<'_>,
    root: u32,
    columns: &'static [IndexColumn],
    target: &[u8],
) -> Result<bool, StateError> {
    let mut page = root;
    let mut claimed = HashSet::new();
    loop {
        let (page_type, keys, children) =
            read_index_search_page(image, page, columns, &mut claimed)?;
        let mut child = keys.len();
        for (index, key) in keys.iter().enumerate() {
            let Some(IndexValue::Text(value)) = key.0.first() else {
                return Err(invalid_path(
                    &image.database.path,
                    "SQLite reference index does not begin with text",
                ));
            };
            match value.as_slice().cmp(target) {
                std::cmp::Ordering::Equal => return Ok(true),
                std::cmp::Ordering::Greater => {
                    child = index;
                    break;
                }
                std::cmp::Ordering::Less => {}
            }
        }
        if page_type == 0x0a {
            return Ok(false);
        }
        page = children[child];
    }
}

fn parse_sqlite_record<'payload>(
    path: &Path,
    payload: &'payload [u8],
    maximum_fields: usize,
) -> Result<Vec<RecordField<'payload>>, StateError> {
    let (header_size, header_varint) = read_sqlite_varint(payload, 0, payload.len())?;
    let header_size = usize::try_from(header_size)
        .map_err(|_| invalid_path(path, "SQLite record header is too large"))?;
    if header_size < header_varint || header_size > payload.len() {
        return Err(invalid_path(path, "SQLite record header is invalid"));
    }
    let mut serials = Vec::new();
    try_reserve_vec(
        path,
        &mut serials,
        maximum_fields,
        "allocate bounded SQLite record serials failed",
    )?;
    let mut cursor = header_varint;
    while cursor < header_size {
        if serials.len() == maximum_fields {
            return Err(invalid_path(
                path,
                "SQLite record has more fields than its accepted schema",
            ));
        }
        let (serial, length) = read_sqlite_varint(payload, cursor, header_size)?;
        serials.push(serial);
        cursor += length;
    }
    if cursor != header_size {
        return Err(invalid_path(path, "SQLite record header is malformed"));
    }
    let mut data = header_size;
    let mut fields = Vec::new();
    try_reserve_vec(
        path,
        &mut fields,
        serials.len(),
        "allocate bounded SQLite record fields failed",
    )?;
    for serial in serials {
        let length = sqlite_serial_length(path, serial)?;
        ensure_slice(path, payload, data, length)?;
        fields.push(RecordField {
            serial,
            bytes: &payload[data..data + length],
        });
        data += length;
    }
    if data != payload.len() {
        return Err(invalid_path(
            path,
            "SQLite record payload length is invalid",
        ));
    }
    Ok(fields)
}

fn decode_sqlite_text(
    path: &Path,
    field: &RecordField<'_>,
    field_name: &'static str,
) -> Result<String, StateError> {
    let bytes = decode_sqlite_text_bytes(path, field, field_name)?;
    try_utf8_owned(
        path,
        bytes,
        "SQLite schema text is not valid UTF-8",
        "allocate bounded SQLite schema text failed",
    )
}

fn decode_sqlite_text_bytes<'field>(
    path: &Path,
    field: &'field RecordField<'_>,
    _field_name: &'static str,
) -> Result<&'field [u8], StateError> {
    if field.serial < 13 || field.serial.is_multiple_of(2) {
        return Err(invalid_path(
            path,
            "SQLite text field does not use a text serial type",
        ));
    }
    Ok(field.bytes)
}

fn sqlite_serial_length(path: &Path, serial: u64) -> Result<usize, StateError> {
    match serial {
        0 | 8 | 9 => Ok(0),
        1 => Ok(1),
        2 => Ok(2),
        3 => Ok(3),
        4 => Ok(4),
        5 => Ok(6),
        6 | 7 => Ok(8),
        10 | 11 => Err(invalid_path(
            path,
            "SQLite record uses a reserved serial type",
        )),
        value if value >= 12 => usize::try_from((value - 12) / 2)
            .map_err(|_| invalid_path(path, "SQLite record serial length exceeds platform bounds")),
        _ => unreachable!("all SQLite serial types are covered"),
    }
}

fn decode_sqlite_integer(
    path: &Path,
    serial: u64,
    bytes: &[u8],
) -> Result<Option<i64>, StateError> {
    match serial {
        0 => Ok(None),
        8 => Ok(Some(0)),
        9 => Ok(Some(1)),
        1..=6 => {
            let mut value = if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
                -1_i64
            } else {
                0_i64
            };
            for byte in bytes {
                value = (value << 8) | i64::from(*byte);
            }
            Ok(Some(value))
        }
        _ => Err(invalid_path(path, "SQLite record field is not an integer")),
    }
}

fn read_sqlite_varint(
    bytes: &[u8],
    offset: usize,
    limit: usize,
) -> Result<(u64, usize), StateError> {
    if offset >= limit || limit > bytes.len() {
        return Err(invalid_path(
            Path::new("state.sqlite"),
            "SQLite varint starts outside its field",
        ));
    }
    let mut value = 0_u64;
    for index in 0..9 {
        let position = offset + index;
        if position >= limit {
            return Err(invalid_path(
                Path::new("state.sqlite"),
                "SQLite varint is truncated",
            ));
        }
        let byte = bytes[position];
        if index == 8 {
            return Ok(((value << 8) | u64::from(byte), 9));
        }
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    unreachable!("nine-byte SQLite varint returns")
}

fn validate_page_reference(image: &DatabaseImage<'_>, page: u32) -> Result<(), StateError> {
    if page == 0 || page > image.logical_pages {
        return Err(invalid_path(
            &image.database.path,
            "SQLite b-tree child page is out of bounds",
        ));
    }
    Ok(())
}

fn ensure_range(
    image: &DatabaseImage<'_>,
    offset: usize,
    length: usize,
    limit: usize,
) -> Result<(), StateError> {
    if offset.checked_add(length).is_none_or(|end| end > limit) {
        return Err(invalid_path(
            &image.database.path,
            "SQLite page field exceeds its usable bounds",
        ));
    }
    Ok(())
}

fn ensure_slice(path: &Path, bytes: &[u8], offset: usize, length: usize) -> Result<(), StateError> {
    if offset
        .checked_add(length)
        .is_none_or(|end| end > bytes.len())
    {
        return Err(invalid_path(
            path,
            "SQLite record field exceeds its payload",
        ));
    }
    Ok(())
}

fn offline_resource_error(reason: &'static str) -> StateError {
    StateError::InvalidValue {
        field: "LinuxProtected offline verification resources",
        reason,
    }
}

fn try_zeroed_vec(
    _path: &Path,
    length: usize,
    reason: &'static str,
) -> Result<Vec<u8>, StateError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| offline_resource_error(reason))?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn try_reserve_vec<T>(
    _path: &Path,
    values: &mut Vec<T>,
    additional: usize,
    reason: &'static str,
) -> Result<(), StateError> {
    values
        .try_reserve(additional)
        .map_err(|_| offline_resource_error(reason))
}

fn try_push_vec<T>(
    path: &Path,
    values: &mut Vec<T>,
    value: T,
    reason: &'static str,
) -> Result<(), StateError> {
    if values.len() == values.capacity() {
        try_reserve_vec(path, values, 1, reason)?;
    }
    values.push(value);
    Ok(())
}

fn try_utf8_owned(
    path: &Path,
    bytes: &[u8],
    utf8_reason: &'static str,
    allocation_reason: &'static str,
) -> Result<String, StateError> {
    let value = std::str::from_utf8(bytes).map_err(|_| invalid_path(path, utf8_reason))?;
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| offline_resource_error(allocation_reason))?;
    owned.push_str(value);
    Ok(owned)
}

fn try_clone_bytes(
    _path: &Path,
    bytes: &[u8],
    reason: &'static str,
) -> Result<Vec<u8>, StateError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(bytes.len())
        .map_err(|_| offline_resource_error(reason))?;
    cloned.extend_from_slice(bytes);
    Ok(cloned)
}

fn try_clone_index_key(path: &Path, key: &IndexKey) -> Result<IndexKey, StateError> {
    let mut values = Vec::new();
    try_reserve_vec(
        path,
        &mut values,
        key.0.len(),
        "allocate bounded SQLite index bound failed",
    )?;
    for value in &key.0 {
        values.push(match value {
            IndexValue::Integer(value) => IndexValue::Integer(*value),
            IndexValue::Text(value) => IndexValue::Text(try_clone_bytes(
                path,
                value,
                "allocate bounded SQLite index text bound failed",
            )?),
        });
    }
    Ok(IndexKey(values))
}

fn try_index_key<const N: usize>(
    path: &Path,
    values: [IndexValue; N],
) -> Result<IndexKey, StateError> {
    let mut key = Vec::new();
    try_reserve_vec(
        path,
        &mut key,
        N,
        "allocate bounded SQLite application index key failed",
    )?;
    key.extend(values);
    Ok(IndexKey(key))
}

fn read_be_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("validated SQLite u16 field is in bounds"),
    )
}

fn read_be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated SQLite u32 field is in bounds"),
    )
}

fn minimal_fresh_handoff_page(page: &[u8; 4096]) -> bool {
    page.starts_with(b"SQLite format 3\0")
        && read_be_u16(page, 16) == 4096
        && page[18..24] == [2, 2, 0, 64, 32, 32]
        && read_be_u32(page, 24) == 1
        && read_be_u32(page, 28) == 1
        && page[32..92].iter().all(|byte| *byte == 0)
        && read_be_u32(page, 92) == 1
        && read_be_u32(page, 96) != 0
        && page[100..108] == [0x0d, 0, 0, 0, 0, 0x10, 0, 0]
        && page[108..].iter().all(|byte| *byte == 0)
}

fn validate_offline_wal(
    wal: &HeldEntry,
    database_page_size: u64,
    cutoff: Instant,
    timeout_ms: u64,
) -> Result<WalObservation, StateError> {
    let length = wal
        .file
        .metadata()
        .map_err(|error| file_error("inspect initialized LinuxProtected WAL", &wal.path, error))?
        .len();
    if length > MAX_OFFLINE_WAL_BYTES {
        return Err(offline_resource_error(
            "initialized LinuxProtected WAL exceeds the offline verification bound",
        ));
    }
    if length <= 32 {
        return Ok(WalObservation {
            committed_pages: None,
            page_one: None,
            frames: HashMap::new(),
        });
    }
    let frame_size = 24_u64
        .checked_add(database_page_size)
        .ok_or_else(|| invalid_path(&wal.path, "LinuxProtected WAL frame size overflowed"))?;
    let payload = length - 32;

    let mut header = [0_u8; 32];
    read_exact_at(
        &wal.file,
        &mut header,
        0,
        &wal.path,
        Some(cutoff),
        None,
        timeout_ms,
    )?;
    let magic = u32::from_be_bytes(
        header[0..4]
            .try_into()
            .expect("fixed WAL magic is in bounds"),
    );
    if !matches!(magic, 0x377f_0682 | 0x377f_0683)
        || u32::from_be_bytes(
            header[4..8]
                .try_into()
                .expect("fixed WAL version is in bounds"),
        ) != 3_007_000
        || u64::from(u32::from_be_bytes(
            header[8..12]
                .try_into()
                .expect("fixed WAL page size is in bounds"),
        )) != database_page_size
    {
        return Err(invalid_path(
            &wal.path,
            "initialized LinuxProtected WAL header is invalid",
        ));
    }
    let big_endian_checksum = magic & 1 != 0;
    let mut checksum = wal_checksum(&header[..24], big_endian_checksum, [0, 0]);
    if checksum != stored_wal_checksum(&header[24..32]) {
        return Err(invalid_path(
            &wal.path,
            "initialized LinuxProtected WAL header checksum is invalid",
        ));
    }
    let salts = &header[16..24];
    let frame_count = payload / frame_size;
    let frame_capacity = usize::try_from(frame_count).map_err(|_| {
        invalid_path(
            &wal.path,
            "initialized LinuxProtected WAL frame count exceeds platform bounds",
        )
    })?;
    if frame_capacity > MAX_OFFLINE_WAL_FRAMES {
        return Err(offline_resource_error(
            "initialized LinuxProtected WAL frame count exceeds the offline verification bound",
        ));
    }
    let page_size =
        usize::try_from(database_page_size).expect("validated SQLite page size fits this platform");
    let mut page = try_zeroed_vec(
        &wal.path,
        page_size,
        "allocate bounded LinuxProtected WAL page buffer",
    )?;
    let mut latest_commit = None;
    let mut committed_frames = HashMap::new();
    let mut pending_frames = HashMap::new();
    committed_frames
        .try_reserve(frame_capacity)
        .map_err(|_| offline_resource_error("allocate bounded committed WAL frame map failed"))?;
    pending_frames
        .try_reserve(frame_capacity)
        .map_err(|_| offline_resource_error("allocate bounded pending WAL frame map failed"))?;
    for frame_index in 0..frame_count {
        check_cutoff(&wal.path, Some(cutoff), None, timeout_ms)?;
        let offset = 32_u64
            .checked_add(frame_index.checked_mul(frame_size).ok_or_else(|| {
                invalid_path(&wal.path, "LinuxProtected WAL frame offset overflowed")
            })?)
            .ok_or_else(|| invalid_path(&wal.path, "LinuxProtected WAL frame offset overflowed"))?;
        let mut frame_header = [0_u8; 24];
        read_exact_at(
            &wal.file,
            &mut frame_header,
            offset,
            &wal.path,
            Some(cutoff),
            None,
            timeout_ms,
        )?;
        read_exact_at(
            &wal.file,
            &mut page,
            offset + 24,
            &wal.path,
            Some(cutoff),
            None,
            timeout_ms,
        )?;
        let page_number = u32::from_be_bytes(
            frame_header[0..4]
                .try_into()
                .expect("fixed WAL frame page number is in bounds"),
        );
        if !(1..=0xffff_fffe).contains(&page_number) || &frame_header[8..16] != salts {
            break;
        }
        let mut next_checksum = wal_checksum(&frame_header[..8], big_endian_checksum, checksum);
        next_checksum = wal_checksum(&page, big_endian_checksum, next_checksum);
        if next_checksum != stored_wal_checksum(&frame_header[16..24]) {
            break;
        }
        checksum = next_checksum;
        pending_frames.insert(page_number, offset + 24);
        let database_pages = u32::from_be_bytes(
            frame_header[4..8]
                .try_into()
                .expect("fixed WAL commit size is in bounds"),
        );
        if database_pages != 0 {
            latest_commit = Some(database_pages);
            for (page_number, frame_offset) in pending_frames.drain() {
                committed_frames.insert(page_number, frame_offset);
            }
        }
    }
    if wal
        .file
        .metadata()
        .map_err(|error| file_error("reinspect initialized LinuxProtected WAL", &wal.path, error))?
        .len()
        != length
    {
        return Err(invalid_path(
            &wal.path,
            "initialized LinuxProtected WAL length changed during verification",
        ));
    }
    if let Some(database_pages) = latest_commit {
        committed_frames.retain(|page_number, _| *page_number <= database_pages);
    }
    let committed_page_one = committed_frames
        .get(&1)
        .map(|offset| {
            let mut bytes = try_zeroed_vec(
                &wal.path,
                page_size,
                "allocate bounded committed WAL page-one buffer failed",
            )?;
            read_exact_at(
                &wal.file,
                &mut bytes,
                *offset,
                &wal.path,
                Some(cutoff),
                None,
                timeout_ms,
            )?;
            Ok::<_, StateError>(bytes)
        })
        .transpose()?;
    Ok(WalObservation {
        committed_pages: latest_commit,
        page_one: committed_page_one,
        frames: committed_frames,
    })
}

fn wal_checksum(bytes: &[u8], big_endian: bool, mut checksum: [u32; 2]) -> [u32; 2] {
    debug_assert!(!bytes.is_empty() && bytes.len().is_multiple_of(8));
    for words in bytes.chunks_exact(8) {
        let first = if big_endian {
            u32::from_be_bytes(words[0..4].try_into().expect("first WAL checksum word"))
        } else {
            u32::from_le_bytes(words[0..4].try_into().expect("first WAL checksum word"))
        };
        let second = if big_endian {
            u32::from_be_bytes(words[4..8].try_into().expect("second WAL checksum word"))
        } else {
            u32::from_le_bytes(words[4..8].try_into().expect("second WAL checksum word"))
        };
        checksum[0] = checksum[0].wrapping_add(first).wrapping_add(checksum[1]);
        checksum[1] = checksum[1].wrapping_add(second).wrapping_add(checksum[0]);
    }
    checksum
}

fn stored_wal_checksum(bytes: &[u8]) -> [u32; 2] {
    [
        u32::from_be_bytes(
            bytes[0..4]
                .try_into()
                .expect("first stored WAL checksum is in bounds"),
        ),
        u32::from_be_bytes(
            bytes[4..8]
                .try_into()
                .expect("second stored WAL checksum is in bounds"),
        ),
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OfflineNamespaceState {
    Fresh,
    PreparingFresh,
    PreparedFresh,
    TransitionedFresh,
    InitializedFresh,
    Initialized,
}

const OFFLINE_INITIALIZE_TIMEOUT: Duration = Duration::from_secs(30);
const OFFLINE_INITIALIZE_CLEANUP_TAIL: Duration = Duration::from_secs(5);

struct RetainedOfflineInitializer {
    worker: std::thread::JoinHandle<Result<(), StateError>>,
    _writer_lock: crate::store::LinuxProtectedOfflineLock,
    namespace: Arc<ProtectedNamespace>,
    identities: [FileIdentity; ENTRY_NAMES.len()],
    may_rollback: bool,
}

struct RetainedOfflineNamespace {
    _writer_lock: crate::store::LinuxProtectedOfflineLock,
    _namespace: Arc<ProtectedNamespace>,
    _identities: [FileIdentity; ENTRY_NAMES.len()],
}

fn retain_offline_namespace(
    writer_lock: crate::store::LinuxProtectedOfflineLock,
    namespace: Arc<ProtectedNamespace>,
    identities: [FileIdentity; ENTRY_NAMES.len()],
) {
    #[cfg(test)]
    {
        OFFLINE_INITIALIZER_TEST_RETAINED_NAMESPACES
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(gate) = offline_initializer_reaper_test_gate() {
            gate.record_namespace_retention();
        }
    }
    std::mem::forget(RetainedOfflineNamespace {
        _writer_lock: writer_lock,
        _namespace: namespace,
        _identities: identities,
    });
}

#[cfg(test)]
fn block_completed_offline_initializer_for_reaper_test(result: &Result<(), StateError>) {
    if let Some(gate) = offline_initializer_reaper_test_gate() {
        assert!(
            result.is_ok(),
            "reaper test worker must complete the exact transition before blocking"
        );
        gate.record_worker_transition_and_wait();
    }
}

#[cfg(test)]
fn offline_initializer_completion_wait_for_test(deadline: Instant) -> Duration {
    let Some(gate) = offline_initializer_reaper_test_gate() else {
        return deadline.saturating_duration_since(Instant::now());
    };
    gate.wait_for(
        |state| state.worker_transitioned,
        "wait for exact transition before reaper handoff",
    );
    Duration::ZERO
}

#[cfg(test)]
fn record_offline_initializer_reaper_handoff() {
    if let Some(gate) = offline_initializer_reaper_test_gate() {
        gate.record_caller_handoff();
    }
}

fn spawn_offline_initializer_reaper() -> Result<
    (
        std::sync::mpsc::SyncSender<RetainedOfflineInitializer>,
        std::thread::JoinHandle<()>,
    ),
    StateError,
> {
    let (sender, receiver) = std::sync::mpsc::sync_channel::<RetainedOfflineInitializer>(1);
    let reaper = std::thread::Builder::new()
        .name("claw-state-offline-init-reaper".to_owned())
        .spawn(move || {
            let Ok(retained) = receiver.recv() else {
                return;
            };
            let RetainedOfflineInitializer {
                worker,
                _writer_lock: writer_lock,
                namespace,
                identities,
                may_rollback,
            } = retained;
            let terminal = worker.join();
            let safe_to_release = match terminal {
                Ok(_) => match namespace.recovery_fresh_state() {
                    Ok(OfflineNamespaceState::TransitionedFresh) if may_rollback => {
                        namespace.restore_exact_fresh(identities).is_ok()
                    }
                    Ok(_) => true,
                    Err(_) => false,
                },
                Err(_) => false,
            };
            if safe_to_release {
                drop(writer_lock);
            } else {
                retain_offline_namespace(writer_lock, namespace, identities);
            }
        })
        .map_err(|error| {
            database(
                "start LinuxProtected offline initializer reaper",
                sqlx::Error::Protocol(error.to_string()),
            )
        })?;
    Ok((sender, reaper))
}

fn verify_and_sync_provisioned_namespace(
    spec: &LinuxProtectedSpec,
    provisioning_parent: &File,
    provisioning_parent_path: &Path,
) -> Result<(), StateError> {
    let preflight = OfflineNamespacePreflight::open(spec)?;
    let _writer_lock = crate::store::acquire_linux_protected_offline_lock(&preflight)?;
    let namespace = ProtectedNamespace::open_for_offline_initialization(spec)?;
    preflight.verify_locked_namespace(&namespace)?;
    let identities = namespace.captured_identities();
    let deadline = Instant::now()
        .checked_add(OFFLINE_INITIALIZE_TIMEOUT)
        .ok_or(StateError::InvalidValue {
            field: "LinuxProtected provisioning verification timeout",
            reason: "is too large for the monotonic clock",
        })?;
    let timeout_ms = u64::try_from(OFFLINE_INITIALIZE_TIMEOUT.as_millis())
        .expect("fixed provisioning timeout fits u64");
    let state = namespace.offline_state(deadline, timeout_ms)?;
    namespace.verify_captured_identities(identities)?;
    if state == OfflineNamespaceState::Initialized {
        namespace.validate_runtime_layout(deadline, timeout_ms)?;
        namespace.verify_captured_identities(identities)?;
    }

    for entry in &namespace.entries {
        entry.file.sync_all().map_err(|error| {
            file_error("sync provisioned LinuxProtected entry", &entry.path, error)
        })?;
    }
    namespace.parent.sync_all().map_err(|error| {
        file_error(
            "sync provisioned LinuxProtected directory",
            &namespace.directory,
            error,
        )
    })?;
    provisioning_parent.sync_all().map_err(|error| {
        file_error(
            "sync LinuxProtected provisioning parent",
            provisioning_parent_path,
            error,
        )
    })?;
    namespace.verify_captured_identities(identities)
}

pub(crate) fn provision_offline(
    directory: &Path,
    service_uid: u32,
    service_gid: u32,
) -> Result<(), StateError> {
    let spec = LinuxProtectedSpec::new(directory.to_owned(), service_uid, service_gid);
    validate_root_credentials()?;
    validate_spec(&spec)?;
    validate_ancestors(directory)?;
    validate_offline_ancestor_acls(directory)?;

    let parent_path = directory
        .parent()
        .filter(|parent| *parent != directory)
        .ok_or_else(|| invalid_path(directory, "LinuxProtected directory must have a parent"))?;
    let name = directory
        .file_name()
        .ok_or_else(|| invalid_path(directory, "LinuxProtected directory must have a name"))?;
    let provisioning_parent = rustix::fs::open(
        parent_path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        file_error(
            "open LinuxProtected provisioning parent",
            parent_path,
            error.into(),
        )
    })?;
    validate_filesystem(directory, &provisioning_parent)?;

    let mut created_directory = false;
    let protected_directory = match rustix::fs::openat(
        &provisioning_parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    ) {
        Ok(directory) => File::from(directory),
        Err(error) if error == rustix::io::Errno::NOENT => {
            rustix::fs::mkdirat(
                &provisioning_parent,
                name,
                rustix::fs::Mode::from_bits_truncate(0o750),
            )
            .map_err(|error| {
                file_error("create LinuxProtected directory", directory, error.into())
            })?;
            created_directory = true;
            rustix::fs::openat(
                &provisioning_parent,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .map(File::from)
            .map_err(|error| {
                file_error(
                    "open created LinuxProtected directory",
                    directory,
                    error.into(),
                )
            })?
        }
        Err(error) => {
            return Err(file_error(
                "open LinuxProtected directory for provisioning",
                directory,
                error.into(),
            ));
        }
    };

    if created_directory {
        rustix::fs::fchown(
            &protected_directory,
            Some(rustix::fs::Uid::ROOT),
            Some(rustix::fs::Gid::from_raw(service_gid)),
        )
        .map_err(|error| {
            file_error(
                "set LinuxProtected directory ownership",
                directory,
                error.into(),
            )
        })?;
        rustix::fs::fchmod(
            &protected_directory,
            rustix::fs::Mode::from_bits_truncate(0o750),
        )
        .map_err(|error| {
            file_error("set LinuxProtected directory mode", directory, error.into())
        })?;
    }

    let identity = FileIdentity::capture(
        directory,
        &protected_directory,
        "inspect provisioned LinuxProtected directory",
    )?;
    validate_parent(&spec, &protected_directory, identity)?;
    validate_filesystem(directory, &protected_directory)?;

    let mut entries = std::fs::read_dir(directory).map_err(|error| {
        file_error(
            "enumerate provisioned LinuxProtected directory",
            directory,
            error,
        )
    })?;
    let is_empty = entries
        .next()
        .transpose()
        .map_err(|error| file_error("inspect provisioned LinuxProtected entry", directory, error))?
        .is_none();
    drop(entries);

    if !is_empty {
        drop(protected_directory);
        return verify_and_sync_provisioned_namespace(&spec, &provisioning_parent, parent_path);
    }

    for name in ENTRY_NAMES {
        let path = directory.join(name);
        let entry = rustix::fs::openat(
            &protected_directory,
            name,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .map(File::from)
        .map_err(|error| file_error("create LinuxProtected entry", &path, error.into()))?;
        rustix::fs::fchown(
            &entry,
            Some(rustix::fs::Uid::from_raw(service_uid)),
            Some(rustix::fs::Gid::from_raw(service_gid)),
        )
        .map_err(|error| file_error("set LinuxProtected entry ownership", &path, error.into()))?;
        rustix::fs::fchmod(&entry, rustix::fs::Mode::from_bits_truncate(0o600))
            .map_err(|error| file_error("set LinuxProtected entry mode", &path, error.into()))?;
        entry
            .sync_all()
            .map_err(|error| file_error("sync LinuxProtected entry", &path, error))?;
    }
    protected_directory
        .sync_all()
        .map_err(|error| file_error("sync LinuxProtected directory", directory, error))?;
    drop(protected_directory);
    verify_and_sync_provisioned_namespace(&spec, &provisioning_parent, parent_path)
}

pub(crate) fn initialize_offline(
    directory: &Path,
    service_uid: u32,
    service_gid: u32,
) -> Result<LinuxProtectedInitialization, StateError> {
    let started = Instant::now();
    let deadline =
        started
            .checked_add(OFFLINE_INITIALIZE_TIMEOUT)
            .ok_or(StateError::InvalidValue {
                field: "LinuxProtected offline initialization timeout",
                reason: "is too large for the monotonic clock",
            })?;
    let work_cutoff = deadline
        .checked_sub(OFFLINE_INITIALIZE_CLEANUP_TAIL)
        .ok_or(StateError::InvalidValue {
            field: "LinuxProtected offline initialization timeout",
            reason: "does not leave a cleanup interval",
        })?;
    let timeout_ms = u64::try_from(OFFLINE_INITIALIZE_TIMEOUT.as_millis())
        .expect("fixed offline timeout fits u64");
    let spec = LinuxProtectedSpec::new(directory.to_owned(), service_uid, service_gid);
    let preflight = OfflineNamespacePreflight::open(&spec)?;
    let writer_lock = crate::store::acquire_linux_protected_offline_lock(&preflight)?;
    let namespace = ProtectedNamespace::open_for_offline_initialization(&spec)?;
    preflight.verify_locked_namespace(&namespace)?;
    let state = namespace.offline_state(work_cutoff, timeout_ms)?;
    let identities = namespace.captured_identities();
    let started_fresh = state == OfflineNamespaceState::Fresh;
    match state {
        OfflineNamespaceState::Initialized => {
            namespace.verify_captured_identities(identities)?;
            check_initializer_deadline(deadline, timeout_ms)?;
            namespace.validate_runtime_layout(deadline, timeout_ms)?;
            check_initializer_deadline(deadline, timeout_ms)?;
            return Ok(LinuxProtectedInitialization::AlreadyInitialized);
        }

        OfflineNamespaceState::InitializedFresh => {
            return settle_initialized_fresh(&namespace, identities, deadline, timeout_ms);
        }
        OfflineNamespaceState::TransitionedFresh => {
            return finish_transitioned_fresh(
                &namespace,
                identities,
                work_cutoff,
                deadline,
                timeout_ms,
            );
        }
        OfflineNamespaceState::Fresh | OfflineNamespaceState::PreparingFresh => {
            let started_fresh = state == OfflineNamespaceState::Fresh;
            if let Err(primary) = namespace.initialize_prep_record() {
                return Err(if started_fresh {
                    rollback_started_fresh(&namespace, identities, primary)
                } else {
                    classify_prepared_failure(&namespace, primary)
                });
            }
            fail_offline_initializer_stage(
                OfflineInitializerTestStage::DeathAfterPrep,
                namespace.database_path(),
            )?;
        }
        OfflineNamespaceState::PreparedFresh => {}
    }
    if Instant::now() >= work_cutoff {
        return Err(StateError::OperationTimedOut {
            operation: "initialize LinuxProtected state offline",
            timeout_ms,
        });
    }
    let (reaper, reaper_thread) = spawn_offline_initializer_reaper()?;
    let worker_namespace = Arc::clone(&namespace);
    let (completion, completed) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("claw-state-offline-init".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    database(
                        "create LinuxProtected offline initializer runtime",
                        sqlx::Error::Protocol(error.to_string()),
                    )
                })?;
            let result = runtime.block_on(run_offline_sqlite(
                &worker_namespace,
                work_cutoff,
                deadline,
                timeout_ms,
            ));
            drop(runtime);
            #[cfg(test)]
            block_completed_offline_initializer_for_reaper_test(&result);
            let _ = completion.send(());
            result
        })
        .map_err(|error| {
            database(
                "start LinuxProtected offline initializer thread",
                sqlx::Error::Protocol(error.to_string()),
            )
        })?;
    #[cfg(not(test))]
    let completion_wait = deadline.saturating_duration_since(Instant::now());
    #[cfg(test)]
    let completion_wait = offline_initializer_completion_wait_for_test(deadline);
    match completed.recv_timeout(completion_wait) {
        Ok(()) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let retained = RetainedOfflineInitializer {
                worker,
                _writer_lock: writer_lock,
                namespace: Arc::clone(&namespace),
                identities,
                may_rollback: started_fresh,
            };
            if let Err(error) = reaper.try_send(retained) {
                let retained = match error {
                    std::sync::mpsc::TrySendError::Full(retained)
                    | std::sync::mpsc::TrySendError::Disconnected(retained) => retained,
                };
                std::mem::forget(retained);
                return Err(StateError::OperationCleanupFailed {
                    operation: "retain timed-out LinuxProtected initializer",
                    primary: Box::new(StateError::OperationTimedOut {
                        operation: "initialize LinuxProtected state offline",
                        timeout_ms,
                    }),
                    cleanup:
                        "offline initializer reaper disconnected; worker and fixed lock were intentionally leaked"
                            .to_owned(),
                });
            }
            #[cfg(test)]
            record_offline_initializer_reaper_handoff();
            drop(reaper);
            drop(reaper_thread);
            return Err(StateError::OperationTimedOut {
                operation: "initialize LinuxProtected state offline",
                timeout_ms,
            });
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
    }
    let worker_result = match worker.join() {
        Ok(result) => result,
        Err(_) => {
            drop(reaper);
            let _ = reaper_thread.join();
            std::mem::forget(writer_lock);
            return Err(StateError::OperationCleanupFailed {
            operation: "initialize LinuxProtected state offline",
            primary: Box::new(database(
                "join LinuxProtected offline initializer thread",
                sqlx::Error::Protocol(
                    "LinuxProtected offline initializer thread panicked".to_owned(),
                ),
            )),
            cleanup:
                "initializer worker panicked; terminal SQLite retirement was not proven, so the fixed lock was intentionally retained"
                    .to_owned(),
            });
        }
    };
    drop(reaper);
    let _ = reaper_thread.join();
    if let Err(primary) = worker_result {
        let settlement =
            settle_failed_fresh_transition(&namespace, identities, primary, started_fresh);
        return Err(match settlement {
            FailedFreshTransitionSettlement::ReleaseLock(error) => error,
            FailedFreshTransitionSettlement::RetainLock(error) => {
                retain_offline_namespace(writer_lock, namespace, identities);
                error
            }
        });
    }
    finish_transitioned_fresh(&namespace, identities, work_cutoff, deadline, timeout_ms)
}

fn finish_transitioned_fresh(
    namespace: &ProtectedNamespace,
    identities: [FileIdentity; ENTRY_NAMES.len()],
    work_cutoff: Instant,
    deadline: Instant,
    timeout_ms: u64,
) -> Result<LinuxProtectedInitialization, StateError> {
    let precommit = (|| {
        namespace.verify_captured_identities(identities)?;
        fail_offline_initializer_stage(
            OfflineInitializerTestStage::Deadline,
            namespace.database_path(),
        )?;
        check_initializer_deadline(work_cutoff, timeout_ms)?;
        fail_offline_initializer_stage(
            OfflineInitializerTestStage::WalSync,
            &namespace.entries[WAL_INDEX].path,
        )?;
        namespace.entries[WAL_INDEX]
            .file
            .sync_all()
            .map_err(|error| {
                file_error(
                    "sync transitioned LinuxProtected WAL",
                    &namespace.entries[WAL_INDEX].path,
                    error,
                )
            })?;
        fail_offline_initializer_stage(
            OfflineInitializerTestStage::DatabaseSync,
            namespace.database_path(),
        )?;
        namespace.entries[DATABASE_INDEX]
            .file
            .sync_all()
            .map_err(|error| {
                file_error(
                    "sync transitioned LinuxProtected database",
                    namespace.database_path(),
                    error,
                )
            })?;
        fail_offline_initializer_stage(
            OfflineInitializerTestStage::RawValidation,
            namespace.database_path(),
        )?;
        namespace.validate_prepared_fresh_sqlite(work_cutoff, timeout_ms)?;
        check_initializer_deadline(work_cutoff, timeout_ms)
    })();
    if let Err(primary) = precommit {
        return Err(classify_prepared_failure(namespace, primary));
    }
    if let Err(failure) = namespace.initialize_empty_selector() {
        return Err(match failure {
            SelectorPublicationFailure::Precommit(primary) => {
                classify_prepared_failure(namespace, primary)
            }
            SelectorPublicationFailure::Uncertain(primary) => {
                selector_publication_uncertain(namespace, primary)
            }
            SelectorPublicationFailure::Committed(primary) => {
                committed_initializer_cleanup(primary)
            }
        });
    }

    let committed = (|| {
        let selector = namespace.read_entry(SELECTOR_INDEX, SELECTOR_LEN, None, None, 0)?;
        if selector.len() != SELECTOR_LEN || selector.iter().any(|byte| *byte != 0) {
            return Err(invalid_path(
                namespace.selector_path(),
                "committed LinuxProtected selector failed exact reread",
            ));
        }
        namespace.cleanup_prep_record()?;
        check_initializer_deadline(deadline, timeout_ms)?;
        namespace.verify_captured_identities(identities)?;
        check_initializer_deadline(deadline, timeout_ms)?;
        fail_offline_initializer_stage(
            OfflineInitializerTestStage::FinalValidation,
            namespace.database_path(),
        )?;
        namespace.validate_runtime_layout(deadline, timeout_ms)?;
        check_initializer_deadline(deadline, timeout_ms)
    })();
    match committed {
        Ok(()) => Ok(LinuxProtectedInitialization::Initialized),
        Err(primary) => Err(classify_committed_initializer_failure(namespace, primary)),
    }
}

fn settle_initialized_fresh(
    namespace: &ProtectedNamespace,
    identities: [FileIdentity; ENTRY_NAMES.len()],
    deadline: Instant,
    timeout_ms: u64,
) -> Result<LinuxProtectedInitialization, StateError> {
    if let Err(primary) = namespace
        .verify_captured_identities(identities)
        .and_then(|()| namespace.validate_prepared_fresh_sqlite(deadline, timeout_ms))
    {
        return Err(selector_publication_uncertain(namespace, primary));
    }
    let selector = &namespace.entries[SELECTOR_INDEX];
    let bytes = namespace
        .read_entry(SELECTOR_INDEX, SELECTOR_LEN, None, None, 0)
        .map_err(|primary| selector_publication_uncertain(namespace, primary))?;
    if bytes.len() != SELECTOR_LEN || bytes.iter().any(|byte| *byte != 0) {
        return Err(selector_publication_uncertain(
            namespace,
            invalid_path(
                &selector.path,
                "ambiguous LinuxProtected selector is not the exact commit value",
            ),
        ));
    }
    selector.file.sync_all().map_err(|error| {
        selector_publication_uncertain(
            namespace,
            file_error(
                "settle ambiguous LinuxProtected selector durability",
                &selector.path,
                error,
            ),
        )
    })?;
    namespace.parent.sync_all().map_err(|error| {
        committed_initializer_cleanup(file_error(
            "sync LinuxProtected namespace after selector settlement",
            &namespace.directory,
            error,
        ))
    })?;
    namespace
        .cleanup_prep_record()
        .and_then(|()| namespace.validate_runtime_layout(deadline, timeout_ms))
        .map_err(committed_initializer_cleanup)?;
    Ok(LinuxProtectedInitialization::AlreadyInitialized)
}

fn rollback_started_fresh(
    namespace: &ProtectedNamespace,
    identities: [FileIdentity; ENTRY_NAMES.len()],
    primary: StateError,
) -> StateError {
    match namespace.restore_exact_fresh(identities) {
        Ok(()) => primary,
        Err(cleanup) => StateError::OperationCleanupFailed {
            operation: "rollback failed LinuxProtected fresh preparation",
            primary: Box::new(primary),
            cleanup: cleanup.to_string(),
        },
    }
}

enum FailedFreshTransitionSettlement {
    ReleaseLock(StateError),
    RetainLock(StateError),
}

fn settle_failed_fresh_transition(
    namespace: &ProtectedNamespace,
    identities: [FileIdentity; ENTRY_NAMES.len()],
    primary: StateError,
    may_rollback: bool,
) -> FailedFreshTransitionSettlement {
    match namespace.recovery_fresh_state() {
        // Exact-Fresh provenance permits discarding this invocation's own precommit handoff.
        Ok(OfflineNamespaceState::TransitionedFresh) if may_rollback => {
            FailedFreshTransitionSettlement::ReleaseLock(
                match namespace.restore_exact_fresh(identities) {
                    Ok(()) => primary,
                    Err(rollback) => StateError::OperationCleanupFailed {
                        operation: "restore failed LinuxProtected fresh initialization",
                        primary: Box::new(primary),
                        cleanup: format!(
                            "post-transition state classified as TransitionedFresh and authorized exact fresh rollback; exact fresh rollback failed: {rollback}"
                        ),
                    },
                },
            )
        }
        Ok(OfflineNamespaceState::TransitionedFresh) => {
            FailedFreshTransitionSettlement::ReleaseLock(primary)
        }
        Ok(
            OfflineNamespaceState::Fresh
            | OfflineNamespaceState::PreparingFresh
            | OfflineNamespaceState::PreparedFresh
            | OfflineNamespaceState::InitializedFresh
            | OfflineNamespaceState::Initialized,
        ) => FailedFreshTransitionSettlement::ReleaseLock(primary),
        Err(classification) => {
            FailedFreshTransitionSettlement::RetainLock(StateError::OperationCleanupFailed {
                operation: "retain unclassifiable LinuxProtected initialization",
                primary: Box::new(primary),
                cleanup: format!(
                    "post-transition classification failed; destructive rollback was not authorized, so the held namespace, identities, and fixed lock were intentionally retained: {classification}"
                ),
            })
        }
    }
}

fn classify_prepared_failure(namespace: &ProtectedNamespace, primary: StateError) -> StateError {
    match namespace.recovery_fresh_state() {
        Ok(
            OfflineNamespaceState::PreparingFresh
            | OfflineNamespaceState::PreparedFresh
            | OfflineNamespaceState::TransitionedFresh
            | OfflineNamespaceState::InitializedFresh
            | OfflineNamespaceState::Initialized,
        ) => primary,
        Ok(OfflineNamespaceState::Fresh) => StateError::OperationCleanupFailed {
            operation: "resume prepared LinuxProtected initialization",
            primary: Box::new(primary),
            cleanup: "prepared state unexpectedly reverted to fresh".to_owned(),
        },
        Err(classification) => StateError::OperationCleanupFailed {
            operation: "resume prepared LinuxProtected initialization",
            primary: Box::new(primary),
            cleanup: format!("selector precommit state became unclassifiable: {classification}"),
        },
    }
}

fn classify_committed_initializer_failure(
    _namespace: &ProtectedNamespace,
    primary: StateError,
) -> StateError {
    committed_initializer_cleanup(primary)
}

fn selector_publication_uncertain(
    namespace: &ProtectedNamespace,
    primary: StateError,
) -> StateError {
    StateError::PublicationUncertain {
        path: namespace.selector_path().to_owned(),
        reason: format!(
            "selector reached its full visible value before durability was confirmed: {primary}"
        ),
    }
}

fn committed_initializer_cleanup(primary: StateError) -> StateError {
    StateError::CommittedWithCleanupFailure {
        operation: "initialize LinuxProtected state offline",
        cleanup: primary.to_string(),
    }
}

fn check_initializer_deadline(deadline: Instant, timeout_ms: u64) -> Result<(), StateError> {
    if Instant::now() >= deadline {
        return Err(StateError::OperationTimedOut {
            operation: "initialize LinuxProtected state offline",
            timeout_ms,
        });
    }
    Ok(())
}

async fn run_offline_sqlite(
    namespace: &ProtectedNamespace,
    work_cutoff: Instant,
    deadline: Instant,
    timeout_ms: u64,
) -> Result<(), StateError> {
    namespace.verify()?;
    let held_database_path = namespace.held_offline_database_path();
    let options = SqliteConnectOptions::new()
        .filename(&held_database_path)
        .create_if_missing(false)
        .vfs("unix-excl")
        .locking_mode(SqliteLockingMode::Exclusive)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(5));
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|error| database("open LinuxProtected database offline", error))?;

    let mut result = verify_offline_live_identity(namespace, &mut connection).await;
    if result.is_ok() {
        result = verify_offline_connection(namespace, &mut connection, work_cutoff).await;
    }
    if result.is_err() && Instant::now() >= work_cutoff {
        result = Err(StateError::OperationTimedOut {
            operation: "initialize LinuxProtected state offline",
            timeout_ms,
        });
    }
    let injected_clear = fail_offline_initializer_stage(
        OfflineInitializerTestStage::HandlerCleanup,
        namespace.database_path(),
    );
    let clear = clear_offline_progress_handler(&mut connection).await;
    for cleanup in [injected_clear.err(), clear.err()].into_iter().flatten() {
        result = Err(match result {
            Ok(()) => cleanup,
            Err(primary) => append_offline_cleanup(primary, cleanup),
        });
    }
    let injected_close = fail_offline_initializer_stage(
        OfflineInitializerTestStage::Close,
        namespace.database_path(),
    );
    let close = connection
        .close()
        .await
        .map_err(|error| database("close LinuxProtected database offline", error));
    for cleanup in [injected_close.err(), close.err()].into_iter().flatten() {
        result = Err(match result {
            Ok(()) => cleanup,
            Err(primary) => append_offline_cleanup(primary, cleanup),
        });
    }
    result?;
    namespace.verify()?;
    if Instant::now() >= deadline {
        return Err(StateError::OperationTimedOut {
            operation: "initialize LinuxProtected state offline",
            timeout_ms,
        });
    }
    Ok(())
}

fn append_offline_cleanup(primary: StateError, cleanup: StateError) -> StateError {
    StateError::OperationCleanupFailed {
        operation: "initialize LinuxProtected state offline",
        primary: Box::new(primary),
        cleanup: cleanup.to_string(),
    }
}

async fn clear_offline_progress_handler(
    connection: &mut SqliteConnection,
) -> Result<(), StateError> {
    let mut handle = connection
        .lock_handle()
        .await
        .map_err(|error| database("lock offline SQLite connection for cleanup", error))?;
    handle.set_progress_handler(0, || true);
    Ok(())
}

async fn verify_offline_connection(
    namespace: &ProtectedNamespace,
    connection: &mut SqliteConnection,
    work_cutoff: Instant,
) -> Result<(), StateError> {
    claw_sqlite_file_control::enable_persistent_wal(connection)
        .await
        .map_err(|error| {
            file_control_error(
                "enable LinuxProtected offline persistent WAL handoff",
                error,
            )
        })?;
    claw_sqlite_file_control::disable_wal_checkpoint_on_close(connection)
        .await
        .map_err(|error| {
            file_control_error("disable LinuxProtected offline checkpoint-on-close", error)
        })?;
    verify_offline_live_identity(namespace, connection).await?;
    {
        let mut handle = connection
            .lock_handle()
            .await
            .map_err(|error| database("lock deadline-bound offline SQLite connection", error))?;
        handle.set_progress_handler(100, move || Instant::now() < work_cutoff);
    }
    let vfs = claw_sqlite_file_control::main_database_vfs_name(connection)
        .await
        .map_err(|error| {
            file_control_error("query LinuxProtected offline initializer VFS", error)
        })?;
    if vfs != "unix-excl" {
        return Err(invalid_path(
            namespace.database_path(),
            "LinuxProtected offline initializer requires exact unix-excl VFS",
        ));
    }
    let locking_mode = sqlx::query_scalar::<_, String>("PRAGMA locking_mode")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| database("query offline SQLite locking mode", error))?;
    if locking_mode != "exclusive" {
        return Err(invalid_path(
            namespace.database_path(),
            "LinuxProtected offline initializer requires exclusive locking mode",
        ));
    }
    verify_offline_live_identity(namespace, connection).await?;
    let memory_mode = sqlx::query_scalar::<_, String>("PRAGMA journal_mode = MEMORY")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| database("prepare in-memory SQLite journal handoff", error))?;
    if memory_mode != "memory" {
        return Err(invalid_path(
            namespace.database_path(),
            "LinuxProtected offline initializer requires an in-memory transition journal",
        ));
    }
    verify_offline_live_identity(namespace, connection).await?;
    fail_offline_initializer_stage(
        OfflineInitializerTestStage::TransitionBeforeWal,
        namespace.database_path(),
    )?;
    let journal_mode = sqlx::query_scalar::<_, String>("PRAGMA journal_mode = WAL")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| database("query offline SQLite journal mode", error))?;
    if journal_mode != "wal" {
        return Err(invalid_path(
            namespace.database_path(),
            "LinuxProtected offline initializer requires WAL journal mode",
        ));
    }
    fail_offline_initializer_stage(
        OfflineInitializerTestStage::Transition,
        namespace.database_path(),
    )?;
    fail_offline_initializer_stage(
        OfflineInitializerTestStage::Identity,
        namespace.database_path(),
    )?;
    verify_offline_live_identity(namespace, connection).await?;

    Ok(())
}

async fn verify_offline_live_identity(
    namespace: &ProtectedNamespace,
    connection: &mut SqliteConnection,
) -> Result<(), StateError> {
    namespace.verify()?;
    if claw_sqlite_file_control::main_database_has_moved(connection)
        .await
        .map_err(|error| {
            file_control_error("verify LinuxProtected offline database identity", error)
        })?
    {
        return Err(invalid_path(
            namespace.database_path(),
            "SQLite offline connection no longer names the held LinuxProtected database",
        ));
    }
    namespace.verify()
}

fn file_control_error(
    operation: &'static str,
    error: claw_sqlite_file_control::FileControlError,
) -> StateError {
    match error.code() {
        Some(code) => database_code(operation, code, error.to_string()),
        None => database(operation, sqlx::Error::Protocol(error.to_string())),
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
    if spec.expected_uid == 0
        || spec.expected_gid == 0
        || spec.expected_uid == u32::MAX
        || spec.expected_gid == u32::MAX
    {
        return Err(invalid_path(
            &spec.directory,
            "LinuxProtected service UID and GID must both be valid nonzero Unix IDs",
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

fn validate_credentials(
    spec: &LinuxProtectedSpec,
    purpose: NamespacePurpose,
) -> Result<(), StateError> {
    match purpose {
        NamespacePurpose::RuntimeService => validate_service_credentials(spec),
        NamespacePurpose::OfflineRoot => validate_root_credentials(),
    }
}

fn validate_service_credentials(spec: &LinuxProtectedSpec) -> Result<(), StateError> {
    let supplementary_groups = rustix::process::getgroups().map_err(|error| {
        file_error(
            "inspect LinuxProtected supplementary groups",
            &spec.directory,
            error.into(),
        )
    })?;
    if rustix::process::getuid().as_raw() != spec.expected_uid
        || rustix::process::geteuid().as_raw() != spec.expected_uid
        || rustix::process::getgid().as_raw() != spec.expected_gid
        || rustix::process::getegid().as_raw() != spec.expected_gid
        || supplementary_groups
            .iter()
            .any(|group| group.as_raw() != spec.expected_gid)
    {
        return Err(invalid_path(
            &spec.directory,
            "LinuxProtected expected service credentials do not match the process",
        ));
    }
    Ok(())
}

fn validate_root_credentials() -> Result<(), StateError> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(StateError::InvalidValue {
            field: "state privilege",
            reason: "offline LinuxProtected initialization requires real and effective UID 0",
        });
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

fn validate_offline_ancestor_acls(directory: &Path) -> Result<(), StateError> {
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
        .map_err(|error| {
            file_error(
                "open LinuxProtected ancestor for offline ACL validation",
                ancestor,
                error.into(),
            )
        })?;
        if !claw_sqlite_file_control::unix_file_has_trivial_acl(&file).map_err(|_| {
            invalid_path(
                ancestor,
                "LinuxProtected ancestor ACL could not be validated offline",
            )
        })? {
            return Err(invalid_path(
                ancestor,
                "LinuxProtected ancestors must have trivial ACLs for offline initialization",
            ));
        }
        let identity = FileIdentity::capture(
            ancestor,
            &file,
            "inspect LinuxProtected ancestor link count",
        )?;
        if identity.links == 0 {
            return Err(invalid_path(
                ancestor,
                "LinuxProtected ancestor link count is invalid",
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

fn validate_offline_catalog_bounds(entries: &[HeldEntry; 8]) -> Result<(), StateError> {
    let writer_length = entries[WRITER_LOCK_INDEX]
        .file
        .metadata()
        .map_err(|error| {
            file_error(
                "inspect offline fixed writer lock length",
                &entries[WRITER_LOCK_INDEX].path,
                error,
            )
        })?
        .len();
    if writer_length != 0 {
        return Err(invalid_path(
            &entries[WRITER_LOCK_INDEX].path,
            "LinuxProtected fixed writer lock must be empty during offline initialization",
        ));
    }

    let selector_length = entries[SELECTOR_INDEX]
        .file
        .metadata()
        .map_err(|error| {
            file_error(
                "inspect offline fixed selector length",
                &entries[SELECTOR_INDEX].path,
                error,
            )
        })?
        .len();
    if selector_length != 0 && selector_length != SELECTOR_LEN as u64 {
        return Err(invalid_path(
            &entries[SELECTOR_INDEX].path,
            "LinuxProtected selector is neither fresh nor initialized to its fixed length",
        ));
    }
    for index in SLOT_METADATA_INDEX {
        if entries[index]
            .file
            .metadata()
            .map_err(|error| {
                file_error(
                    "inspect offline snapshot metadata length",
                    &entries[index].path,
                    error,
                )
            })?
            .len()
            > METADATA_LEN as u64
        {
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
                file_error(
                    "inspect offline snapshot slot length",
                    &entries[index].path,
                    error,
                )
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
    use sqlx::SqliteConnection;
    use sqlx::sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqliteSynchronous,
    };

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
    const REDUNDANT_GROUP_CHILD: &str = "redundant-group";
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

    fn entry_bytes(path: &Path) -> Vec<Vec<u8>> {
        ENTRY_NAMES
            .iter()
            .map(|name| {
                fs::read(path.join(name))
                    .unwrap_or_else(|error| panic!("read protected {name}: {error}"))
            })
            .collect()
    }

    fn entry_lengths(path: &Path) -> Vec<u64> {
        ENTRY_NAMES
            .iter()
            .map(|name| {
                fs::metadata(path.join(name))
                    .unwrap_or_else(|error| panic!("inspect protected {name}: {error}"))
                    .len()
            })
            .collect()
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
                .iter()
                .all(|group| group.as_raw() == SERVICE_GID)
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

    fn fresh_root_fixture() -> RootFixture {
        assert!(
            rustix::process::getuid().is_root() && rustix::process::geteuid().is_root(),
            "fresh LinuxProtected fixture requires real and effective UID 0"
        );
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time follows Unix epoch")
            .as_nanos();
        let outer = PathBuf::from(format!(
            "/var/lib/gta-claw-lp3-fault-{}-{nonce}",
            std::process::id()
        ));
        let namespace = outer.join("state");
        fs::create_dir(&outer).expect("create fresh fixture ancestor");
        chown(&outer, Some(0), Some(0)).expect("own fresh fixture ancestor");
        fs::set_permissions(&outer, fs::Permissions::from_mode(0o755))
            .expect("secure fresh fixture ancestor");
        fs::create_dir(&namespace).expect("create fresh protected namespace");
        for name in ENTRY_NAMES {
            let path = namespace.join(name);
            File::create(&path).unwrap_or_else(|error| panic!("precreate fresh {name}: {error}"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .unwrap_or_else(|error| panic!("secure fresh {name}: {error}"));
            chown(&path, Some(SERVICE_UID), Some(SERVICE_GID))
                .unwrap_or_else(|error| panic!("own fresh {name}: {error}"));
        }
        chown(&namespace, Some(0), Some(SERVICE_GID))
            .expect("assign fresh namespace service group");
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o750))
            .expect("secure fresh protected namespace");
        RootFixture {
            ready: outer.join("unused.ready"),
            control: outer.join("unused.control"),
            outer,
            namespace,
        }
    }

    fn schedule_offline_initializer_fault(stage: OfflineInitializerTestStage) {
        schedule_offline_initializer_faults(&[stage]);
    }

    fn schedule_offline_initializer_faults(stages: &[OfflineInitializerTestStage]) {
        let mut scheduled = OFFLINE_INITIALIZER_TEST_FAULT
            .lock()
            .expect("offline initializer fault schedule lock poisoned");
        assert!(scheduled.is_empty());
        scheduled.extend_from_slice(stages);
    }

    fn exercise_offline_initializer_fault_matrix() {
        for stage in [
            OfflineInitializerTestStage::PrepPrefix,
            OfflineInitializerTestStage::PrepWrite,
            OfflineInitializerTestStage::PrepSync,
            OfflineInitializerTestStage::DeathAfterPrep,
            OfflineInitializerTestStage::TransitionBeforeWal,
            OfflineInitializerTestStage::Transition,
            OfflineInitializerTestStage::Identity,
            OfflineInitializerTestStage::HandlerCleanup,
            OfflineInitializerTestStage::Close,
            OfflineInitializerTestStage::WalSync,
            OfflineInitializerTestStage::DatabaseSync,
            OfflineInitializerTestStage::Deadline,
            OfflineInitializerTestStage::RawValidation,
            OfflineInitializerTestStage::SelectorData,
            OfflineInitializerTestStage::SelectorWrite,
            OfflineInitializerTestStage::SelectorPartialWrite,
            OfflineInitializerTestStage::SelectorSync,
            OfflineInitializerTestStage::SelectorParentSync,
            OfflineInitializerTestStage::MarkerCleanup,
            OfflineInitializerTestStage::FinalValidation,
        ] {
            let fixture = fresh_root_fixture();
            let identities = entry_identities(&fixture.namespace);
            schedule_offline_initializer_fault(stage);
            let error = crate::initialize_linux_protected_offline(
                &fixture.namespace,
                SERVICE_UID,
                SERVICE_GID,
            )
            .expect_err("scheduled initializer stage must fail");
            if stage == OfflineInitializerTestStage::SelectorSync {
                assert_eq!(error.write_outcome(), WriteOutcome::Uncertain);
                let StateError::PublicationUncertain { path, reason } = &error else {
                    panic!("SelectorSync must report publication uncertainty: {error:?}");
                };
                let fault_path = fixture.namespace.join(SELECTOR_NAME);
                let primary = format!(
                    "invalid state path {}: injected SelectorSync stage failure",
                    fault_path.display()
                );
                let expected_reason = format!(
                    "selector reached its full visible value before durability was confirmed: {primary}"
                );
                let expected_error = StateError::PublicationUncertain {
                    path: fault_path.clone(),
                    reason: expected_reason.clone(),
                };
                assert_eq!(path, &fault_path);
                assert_eq!(reason, &expected_reason);
                assert_eq!(error, expected_error);
                assert_eq!(
                    error.to_string(),
                    format!(
                        "publication state is uncertain at {}: {expected_reason}",
                        fault_path.display()
                    )
                );
            } else if matches!(
                stage,
                OfflineInitializerTestStage::SelectorParentSync
                    | OfflineInitializerTestStage::MarkerCleanup
                    | OfflineInitializerTestStage::FinalValidation
            ) {
                assert_eq!(error.write_outcome(), WriteOutcome::Committed);
                let StateError::CommittedWithCleanupFailure { operation, cleanup } = &error else {
                    panic!("{stage:?} must report committed cleanup degradation: {error:?}");
                };
                let (fault_path, fault_reason) = match stage {
                    OfflineInitializerTestStage::SelectorParentSync => (
                        fixture.namespace.clone(),
                        "injected SelectorParentSync stage failure",
                    ),
                    OfflineInitializerTestStage::MarkerCleanup => (
                        fixture.namespace.join(SNAPSHOT_METADATA_NAMES[1]),
                        "injected MarkerCleanup stage failure",
                    ),
                    OfflineInitializerTestStage::FinalValidation => (
                        fixture.namespace.join(DATABASE_NAME),
                        "injected FinalValidation stage failure",
                    ),
                    _ => unreachable!("post-sync diagnostic stage is exhaustively matched"),
                };
                let expected_cleanup = format!(
                    "invalid state path {}: {fault_reason}",
                    fault_path.display()
                );
                let expected_error = StateError::CommittedWithCleanupFailure {
                    operation: "initialize LinuxProtected state offline",
                    cleanup: expected_cleanup.clone(),
                };
                assert_eq!(*operation, "initialize LinuxProtected state offline");
                assert_eq!(cleanup, &expected_cleanup);
                assert_eq!(error, expected_error);
                assert_eq!(
                    error.to_string(),
                    format!(
                        "initialize LinuxProtected state offline committed; post-commit finalization failed: {expected_cleanup}"
                    )
                );
            } else {
                assert!(
                    matches!(
                        error,
                        StateError::InvalidPath { .. } | StateError::OperationCleanupFailed { .. }
                    ),
                    "{stage:?} returned the wrong injected failure: {error:?}"
                );
            }
            assert!(
                OFFLINE_INITIALIZER_TEST_FAULT
                    .lock()
                    .expect("offline initializer fault schedule lock poisoned")
                    .is_empty(),
                "{stage:?} was not reached"
            );
            assert_eq!(exact_names(&fixture.namespace), expected_names());
            assert_eq!(entry_identities(&fixture.namespace), identities);

            let resumed = crate::initialize_linux_protected_offline(
                &fixture.namespace,
                SERVICE_UID,
                SERVICE_GID,
            )
            .unwrap_or_else(|error| panic!("{stage:?} did not resume safely: {error:?}"));
            let expected = if matches!(
                stage,
                OfflineInitializerTestStage::SelectorSync
                    | OfflineInitializerTestStage::SelectorParentSync
                    | OfflineInitializerTestStage::MarkerCleanup
                    | OfflineInitializerTestStage::FinalValidation
            ) {
                LinuxProtectedInitialization::AlreadyInitialized
            } else {
                LinuxProtectedInitialization::Initialized
            };
            assert_eq!(resumed, expected, "{stage:?} resumed from the wrong state");
            assert_eq!(
                crate::initialize_linux_protected_offline(
                    &fixture.namespace,
                    SERVICE_UID,
                    SERVICE_GID,
                )
                .expect("completed fault fixture is idempotent"),
                LinuxProtectedInitialization::AlreadyInitialized
            );
            assert_eq!(entry_identities(&fixture.namespace), identities);
            assert_eq!(exact_names(&fixture.namespace), expected_names());
            let database =
                fs::read(fixture.namespace.join(DATABASE_NAME)).expect("read fault database");
            assert!(!database.windows(6).any(|bytes| bytes == b"CREATE"));
            assert!(
                !database
                    .windows(16)
                    .any(|bytes| bytes == b"claw_writer_lock")
            );
        }

        for (trigger, rollback) in [
            (
                OfflineInitializerTestStage::PrepWrite,
                OfflineInitializerTestStage::RollbackTruncate,
            ),
            (
                OfflineInitializerTestStage::PrepSync,
                OfflineInitializerTestStage::RollbackSync,
            ),
        ] {
            let fixture = fresh_root_fixture();
            let identities = entry_identities(&fixture.namespace);
            schedule_offline_initializer_faults(&[trigger, rollback]);
            let error = crate::initialize_linux_protected_offline(
                &fixture.namespace,
                SERVICE_UID,
                SERVICE_GID,
            )
            .expect_err("rollback stage failure must remain explicit");
            assert!(
                matches!(error, StateError::OperationCleanupFailed { .. }),
                "rollback stage returned the wrong error: {error:?}"
            );
            assert!(
                OFFLINE_INITIALIZER_TEST_FAULT
                    .lock()
                    .expect("offline initializer fault schedule lock poisoned")
                    .is_empty()
            );
            assert_eq!(entry_identities(&fixture.namespace), identities);
            if rollback == OfflineInitializerTestStage::RollbackSync {
                assert_eq!(
                    fs::metadata(fixture.namespace.join(SNAPSHOT_METADATA_NAMES[1]))
                        .expect("inspect retained rollback prep record")
                        .len(),
                    PREP_RECORD_LEN as u64,
                    "rollback sync failure must retain prep provenance"
                );
            }
            assert_eq!(
                crate::initialize_linux_protected_offline(
                    &fixture.namespace,
                    SERVICE_UID,
                    SERVICE_GID,
                )
                .expect("rollback-stage residue remains resumable"),
                LinuxProtectedInitialization::Initialized
            );
        }

        let rollback_entry = fresh_root_fixture();
        let identities = entry_identities(&rollback_entry.namespace);
        let database_path = rollback_entry.namespace.join(DATABASE_NAME);
        schedule_offline_initializer_faults(&[
            OfflineInitializerTestStage::Transition,
            OfflineInitializerTestStage::RollbackEntrySyncFailure,
        ]);
        let error = crate::initialize_linux_protected_offline(
            &rollback_entry.namespace,
            SERVICE_UID,
            SERVICE_GID,
        )
        .expect_err("post-transition rollback sync failure must remain explicit");
        let StateError::OperationCleanupFailed {
            operation,
            primary,
            cleanup,
        } = &error
        else {
            panic!("entry sync failure must degrade production rollback: {error:?}");
        };
        let expected_primary = StateError::InvalidPath {
            path: database_path.clone(),
            reason: "injected private offline initializer stage failure",
        };
        let expected_primary_display = format!(
            "invalid state path {}: injected private offline initializer stage failure",
            database_path.display()
        );
        let expected_rollback_display = format!(
            "invalid state path {}: injected RollbackEntrySyncFailure stage failure",
            database_path.display()
        );
        let expected_cleanup = format!(
            "post-transition state classified as TransitionedFresh and authorized exact fresh rollback; exact fresh rollback failed: {expected_rollback_display}"
        );
        assert_eq!(
            *operation,
            "restore failed LinuxProtected fresh initialization"
        );
        assert_eq!(primary.as_ref(), &expected_primary);
        assert_eq!(cleanup, &expected_cleanup);
        assert_eq!(
            error.to_string(),
            format!(
                "{expected_primary_display}; restore failed LinuxProtected fresh initialization cleanup failed: {expected_cleanup}"
            )
        );
        assert!(
            OFFLINE_INITIALIZER_TEST_FAULT
                .lock()
                .expect("offline initializer fault schedule lock poisoned")
                .is_empty(),
            "production classifier did not route the post-transition failure through rollback"
        );
        let spec =
            LinuxProtectedSpec::new(rollback_entry.namespace.clone(), SERVICE_UID, SERVICE_GID);
        let preflight =
            OfflineNamespacePreflight::open(&spec).expect("open rollback-entry preflight");
        let writer_lock = crate::store::acquire_linux_protected_offline_lock(&preflight)
            .expect("lock rollback-entry fixture");
        let namespace = ProtectedNamespace::open_for_offline_initialization(&spec)
            .expect("hold rollback-entry namespace");
        let expected_prep = namespace.initializer_prep_record();
        assert_eq!(
            namespace
                .recovery_fresh_state()
                .expect("classify partial production rollback"),
            OfflineNamespaceState::PreparedFresh,
            "database truncate plus retained prep must remain exactly resumable"
        );
        assert_eq!(
            fs::read(rollback_entry.namespace.join(SNAPSHOT_METADATA_NAMES[1]))
                .expect("read retained rollback prep record"),
            expected_prep,
            "production rollback sync failure must retain exact durable prep bytes"
        );
        assert_eq!(
            fs::metadata(&database_path)
                .expect("inspect actually truncated rollback database")
                .len(),
            0,
            "production rollback must truncate the real handoff database before injected sync failure"
        );
        assert_eq!(entry_identities(&rollback_entry.namespace), identities);
        drop(namespace);
        drop(writer_lock);
        drop(preflight);
        assert_eq!(
            crate::initialize_linux_protected_offline(
                &rollback_entry.namespace,
                SERVICE_UID,
                SERVICE_GID,
            )
            .expect("public retry resumes retained real rollback residue"),
            LinuxProtectedInitialization::Initialized
        );
        assert_eq!(
            crate::initialize_linux_protected_offline(
                &rollback_entry.namespace,
                SERVICE_UID,
                SERVICE_GID,
            )
            .expect("completed production rollback fixture is idempotent"),
            LinuxProtectedInitialization::AlreadyInitialized
        );

        let classifier_error = fresh_root_fixture();
        let classifier_identities = entry_identities(&classifier_error.namespace);
        let classifier_names = exact_names(&classifier_error.namespace);
        let retained_before =
            OFFLINE_INITIALIZER_TEST_RETAINED_NAMESPACES.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            OFFLINE_INITIALIZER_TEST_CLASSIFICATION_SNAPSHOT
                .lock()
                .expect("offline initializer classification snapshot lock poisoned")
                .take()
                .is_none()
        );
        schedule_offline_initializer_faults(&[
            OfflineInitializerTestStage::Transition,
            OfflineInitializerTestStage::RecoveryClassification,
            OfflineInitializerTestStage::RollbackTruncate,
        ]);
        let classifier_database = classifier_error.namespace.join(DATABASE_NAME);
        let error = crate::initialize_linux_protected_offline(
            &classifier_error.namespace,
            SERVICE_UID,
            SERVICE_GID,
        )
        .expect_err("classifier uncertainty must fail closed");
        let expected_primary = StateError::InvalidPath {
            path: classifier_database.clone(),
            reason: "injected private offline initializer stage failure",
        };
        let expected_primary_display = format!(
            "invalid state path {}: injected private offline initializer stage failure",
            classifier_database.display()
        );
        let expected_classification_display = format!(
            "invalid state path {}: injected RecoveryClassification stage failure",
            classifier_error.namespace.display()
        );
        let expected_cleanup = format!(
            "post-transition classification failed; destructive rollback was not authorized, so the held namespace, identities, and fixed lock were intentionally retained: {expected_classification_display}"
        );
        let expected_error = StateError::OperationCleanupFailed {
            operation: "retain unclassifiable LinuxProtected initialization",
            primary: Box::new(expected_primary.clone()),
            cleanup: expected_cleanup.clone(),
        };
        assert_eq!(error, expected_error);
        assert_eq!(
            error.to_string(),
            format!(
                "{expected_primary_display}; retain unclassifiable LinuxProtected initialization cleanup failed: {expected_cleanup}"
            )
        );
        {
            let mut scheduled = OFFLINE_INITIALIZER_TEST_FAULT
                .lock()
                .expect("offline initializer fault schedule lock poisoned");
            assert_eq!(
                scheduled.as_slice(),
                &[OfflineInitializerTestStage::RollbackTruncate],
                "classifier uncertainty must not enter destructive rollback"
            );
            scheduled.clear();
        }
        let classifier_snapshot = OFFLINE_INITIALIZER_TEST_CLASSIFICATION_SNAPSHOT
            .lock()
            .expect("offline initializer classification snapshot lock poisoned")
            .take()
            .expect("capture exact state before injected classifier uncertainty");
        let classifier_snapshot_lengths = classifier_snapshot
            .iter()
            .map(|bytes| bytes.len() as u64)
            .collect::<Vec<_>>();
        assert_eq!(
            entry_bytes(&classifier_error.namespace),
            classifier_snapshot,
            "classifier uncertainty must preserve every held entry byte"
        );
        assert_eq!(
            entry_lengths(&classifier_error.namespace),
            classifier_snapshot_lengths,
            "classifier uncertainty must preserve every held entry length"
        );
        assert_eq!(
            entry_identities(&classifier_error.namespace),
            classifier_identities
        );
        assert_eq!(exact_names(&classifier_error.namespace), classifier_names);
        let spec =
            LinuxProtectedSpec::new(classifier_error.namespace.clone(), SERVICE_UID, SERVICE_GID);
        let namespace = ProtectedNamespace::open_for_offline_initialization(&spec)
            .expect("inspect retained classifier-error namespace");
        assert_eq!(
            namespace
                .recovery_fresh_state()
                .expect("reclassify retained exact transition"),
            OfflineNamespaceState::TransitionedFresh
        );
        let retained_bytes = entry_bytes(&classifier_error.namespace);
        assert_eq!(
            retained_bytes[PREP_RECORD_INDEX],
            namespace.initializer_prep_record()
        );
        let database_page: &[u8; 4096] = retained_bytes[DATABASE_INDEX]
            .as_slice()
            .try_into()
            .expect("retained transition database is exactly one page");
        assert!(minimal_fresh_handoff_page(database_page));
        assert!(retained_bytes[WAL_INDEX].is_empty());
        assert!(retained_bytes[SELECTOR_INDEX].is_empty());
        drop(namespace);
        assert_eq!(
            OFFLINE_INITIALIZER_TEST_RETAINED_NAMESPACES.load(std::sync::atomic::Ordering::SeqCst),
            retained_before + 1,
            "classifier uncertainty must retain the held namespace bundle"
        );
        let retry = crate::initialize_linux_protected_offline(
            &classifier_error.namespace,
            SERVICE_UID,
            SERVICE_GID,
        )
        .expect_err("fail-closed classifier uncertainty retains the fixed lock");
        assert_eq!(
            retry,
            StateError::StoreLocked {
                path: classifier_error.namespace.join(WRITER_LOCK_NAME),
            }
        );
        assert_eq!(entry_bytes(&classifier_error.namespace), retained_bytes);
        assert_eq!(
            entry_lengths(&classifier_error.namespace),
            classifier_snapshot_lengths
        );
        assert_eq!(
            entry_identities(&classifier_error.namespace),
            classifier_identities
        );
        assert_eq!(exact_names(&classifier_error.namespace), classifier_names);

        let reaper_error = fresh_root_fixture();
        let reaper_identities = entry_identities(&reaper_error.namespace);
        let reaper_names = exact_names(&reaper_error.namespace);
        let retained_before =
            OFFLINE_INITIALIZER_TEST_RETAINED_NAMESPACES.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            OFFLINE_INITIALIZER_TEST_CLASSIFICATION_SNAPSHOT
                .lock()
                .expect("offline initializer classification snapshot lock poisoned")
                .take()
                .is_none()
        );
        let reaper_gate = install_offline_initializer_reaper_test_gate();
        schedule_offline_initializer_faults(&[
            OfflineInitializerTestStage::RecoveryClassification,
            OfflineInitializerTestStage::RollbackTruncate,
        ]);
        assert_eq!(
            crate::initialize_linux_protected_offline(
                &reaper_error.namespace,
                SERVICE_UID,
                SERVICE_GID,
            )
            .expect_err("gated exact transition must transfer to the timeout reaper"),
            StateError::OperationTimedOut {
                operation: "initialize LinuxProtected state offline",
                timeout_ms: 30_000,
            }
        );
        assert_eq!(
            reaper_gate.snapshot(),
            OfflineInitializerReaperTestState {
                worker_transitioned: true,
                caller_handoff: true,
                ..OfflineInitializerReaperTestState::default()
            },
            "caller must hand the blocked exact-transition worker to the reaper"
        );
        reaper_gate.release_worker();
        reaper_gate.wait_for(
            |state| state.namespace_retained,
            "wait for reaper classifier-error retention",
        );
        assert_eq!(
            reaper_gate.snapshot(),
            OfflineInitializerReaperTestState {
                worker_transitioned: true,
                caller_handoff: true,
                release_worker: true,
                classifier_failed: true,
                namespace_retained: true,
            },
            "reaper must classify, fail closed, and retain the complete ownership bundle"
        );
        remove_offline_initializer_reaper_test_gate(&reaper_gate);
        {
            let mut scheduled = OFFLINE_INITIALIZER_TEST_FAULT
                .lock()
                .expect("offline initializer fault schedule lock poisoned");
            assert_eq!(
                scheduled.as_slice(),
                &[OfflineInitializerTestStage::RollbackTruncate],
                "reaper classifier uncertainty must not enter destructive rollback"
            );
            scheduled.clear();
        }
        let reaper_snapshot = OFFLINE_INITIALIZER_TEST_CLASSIFICATION_SNAPSHOT
            .lock()
            .expect("offline initializer classification snapshot lock poisoned")
            .take()
            .expect("capture exact state inside the reaper classifier");
        let reaper_snapshot_lengths = reaper_snapshot
            .iter()
            .map(|bytes| bytes.len() as u64)
            .collect::<Vec<_>>();
        assert_eq!(entry_bytes(&reaper_error.namespace), reaper_snapshot);
        assert_eq!(
            entry_lengths(&reaper_error.namespace),
            reaper_snapshot_lengths
        );
        assert_eq!(entry_identities(&reaper_error.namespace), reaper_identities);
        assert_eq!(exact_names(&reaper_error.namespace), reaper_names);
        let spec =
            LinuxProtectedSpec::new(reaper_error.namespace.clone(), SERVICE_UID, SERVICE_GID);
        let namespace = ProtectedNamespace::open_for_offline_initialization(&spec)
            .expect("inspect reaper-retained namespace");
        assert_eq!(
            namespace
                .recovery_fresh_state()
                .expect("independently classify reaper-retained image"),
            OfflineNamespaceState::TransitionedFresh
        );
        let retained_bytes = entry_bytes(&reaper_error.namespace);
        assert_eq!(
            retained_bytes[PREP_RECORD_INDEX],
            namespace.initializer_prep_record()
        );
        let database_page: &[u8; 4096] = retained_bytes[DATABASE_INDEX]
            .as_slice()
            .try_into()
            .expect("reaper-retained database is exactly one page");
        assert!(minimal_fresh_handoff_page(database_page));
        assert!(retained_bytes[WAL_INDEX].is_empty());
        assert!(retained_bytes[SELECTOR_INDEX].is_empty());
        drop(namespace);
        assert_eq!(
            OFFLINE_INITIALIZER_TEST_RETAINED_NAMESPACES.load(std::sync::atomic::Ordering::SeqCst),
            retained_before + 1,
            "reaper classifier uncertainty must retain the held namespace bundle"
        );
        assert_eq!(
            crate::initialize_linux_protected_offline(
                &reaper_error.namespace,
                SERVICE_UID,
                SERVICE_GID,
            )
            .expect_err("reaper retention must keep the fixed lock"),
            StateError::StoreLocked {
                path: reaper_error.namespace.join(WRITER_LOCK_NAME),
            }
        );
        assert_eq!(entry_bytes(&reaper_error.namespace), retained_bytes);
        assert_eq!(
            entry_lengths(&reaper_error.namespace),
            reaper_snapshot_lengths
        );
        assert_eq!(entry_identities(&reaper_error.namespace), reaper_identities);
        assert_eq!(exact_names(&reaper_error.namespace), reaper_names);

        let sparse = fresh_root_fixture();
        assert_eq!(
            crate::initialize_linux_protected_offline(&sparse.namespace, SERVICE_UID, SERVICE_GID,)
                .expect("initialize sparse-bound fixture"),
            LinuxProtectedInitialization::Initialized
        );
        let identities = entry_identities(&sparse.namespace);
        let database_path = sparse.namespace.join(DATABASE_NAME);
        let database = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&database_path)
            .expect("open sparse-bound database");
        database
            .set_len(MAX_OFFLINE_DATABASE_BYTES)
            .expect("extend sparse-bound database without allocation");
        write_all_at(
            &database,
            &(MAX_OFFLINE_FREELIST_PAGES + 1).to_be_bytes(),
            36,
        )
        .and_then(|()| database.sync_all())
        .expect("persist oversized sparse freelist declaration");
        let mut first_page = [0_u8; 4096];
        database
            .read_at(&mut first_page, 0)
            .expect("read sparse-bound first page");
        let error =
            crate::initialize_linux_protected_offline(&sparse.namespace, SERVICE_UID, SERVICE_GID)
                .expect_err("oversized sparse freelist must fail safely");
        assert!(
            matches!(error, StateError::InvalidValue { .. }),
            "oversized sparse freelist returned the wrong error: {error:?}"
        );
        assert_eq!(
            fs::metadata(&database_path)
                .expect("inspect sparse-bound database")
                .len(),
            MAX_OFFLINE_DATABASE_BYTES
        );
        let mut reread = [0_u8; 4096];
        database
            .read_at(&mut reread, 0)
            .expect("reread sparse-bound first page");
        assert_eq!(reread, first_page);
        assert_eq!(entry_identities(&sparse.namespace), identities);

        let survivor = fresh_root_fixture();
        assert_eq!(
            crate::initialize_linux_protected_offline(
                &survivor.namespace,
                SERVICE_UID,
                SERVICE_GID,
            )
            .expect("initializer process survives sparse-bound rejection"),
            LinuxProtectedInitialization::Initialized
        );
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
        } else if mode == REDUNDANT_GROUP_CHILD {
            command.arg(format!("--groups={SERVICE_GID}"));
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
        assert!(matches!(
            StateStore::open(StoreConfig::linux_protected(namespace).with_max_connections(2)).await,
            Err(StateError::InvalidValue {
                field: "maximum connections",
                reason: "LinuxProtected requires exactly one connection",
            })
        ));
        let config = StoreConfig::linux_protected(namespace)
            .with_operation_timeout(Duration::from_secs(10))
            .with_close_timeout(Duration::from_millis(1_500));
        assert_eq!(config.path(), database);
        assert_eq!(config.profile(), crate::StateProfile::LinuxProtected);
        let store = StateStore::open(config.clone())
            .await
            .expect("open LinuxProtected state store");
        assert_eq!(store.profile(), crate::StateProfile::LinuxProtected);
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

        assert_eq!(
            store
                .latest_protected_snapshot_receipt()
                .await
                .expect("read empty protected catalog"),
            None
        );
        let first = store
            .publish_protected_snapshot()
            .await
            .expect("publish first protected snapshot");
        assert_eq!((first.generation, first.slot), (1, 0));
        assert_snapshot_receipt(namespace, &first);
        assert_eq!(
            store
                .latest_protected_snapshot_receipt()
                .await
                .expect("read first protected receipt"),
            Some(first)
        );
        let second = store
            .publish_protected_snapshot()
            .await
            .expect("publish second protected snapshot");
        assert_eq!((second.generation, second.slot), (2, 1));
        assert_snapshot_receipt(namespace, &second);
        assert_eq!(
            store
                .latest_protected_snapshot_receipt()
                .await
                .expect("read second protected receipt"),
            Some(second)
        );

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
            Err(StateError::InvalidValue {
                field: "state profile operation",
                reason: "arbitrary-path snapshot publication is unavailable for LinuxProtected",
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

        let reopened = StateStore::open(config)
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
        let latest = reopened
            .latest_protected_snapshot_receipt()
            .await
            .expect("recover latest protected receipt")
            .expect("protected catalog remains populated");
        assert_eq!((latest.generation(), latest.slot()), (10, 1));
        let eleventh = reopened
            .publish_protected_snapshot()
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

    fn exercise_redundant_group_credentials(namespace: &Path) {
        assert_service_credentials();
        validate_service_credentials(&LinuxProtectedSpec::new(
            namespace.to_owned(),
            SERVICE_UID,
            SERVICE_GID,
        ))
        .expect("redundant supplementary primary GID is accepted");
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

        let dispatch_deadline_session = SessionRecord::new(
            SessionId::new("lp2-protected-dispatch-deadline")
                .expect("valid dispatch deadline session id"),
            TimestampMs::new(26).expect("valid dispatch deadline timestamp"),
        );
        install_repository_temp_marker(&store).await;
        let (dispatch_entered, dispatch_release) =
            repository_test_support::set_protected_commit_dispatch_barrier(&owner);
        let dispatch_store = Arc::clone(&store);
        let dispatch_record = dispatch_deadline_session.clone();
        let dispatch_write =
            tokio::spawn(async move { dispatch_store.sessions().create(&dispatch_record).await });
        tokio::time::timeout(Duration::from_secs(5), dispatch_entered.notified())
            .await
            .expect("protected write reaches owner-taken commit dispatch barrier");
        assert_repository_pool_blocked(&store).await;
        tokio::time::sleep(Duration::from_millis(550)).await;
        dispatch_release.notify_one();
        let error = dispatch_write
            .await
            .expect("protected dispatch rollback task joins")
            .expect_err("owner-taken pre-poll deadline must rollback");
        assert!(matches!(error, StateError::OperationTimedOut { .. }));
        assert_eq!(error.write_outcome(), WriteOutcome::NotCommitted);
        assert_replacement_connection(&store).await;
        assert!(
            store
                .sessions()
                .get(&dispatch_deadline_session.id)
                .await
                .expect("read dispatch-deadline rolled-back record")
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
    fn offline_initializer_source_contract_excludes_mutating_legacy_paths() {
        let source = include_str!("linux_protected.rs");
        let connection_start = source
            .find("async fn verify_offline_connection(")
            .expect("find fresh handoff actor");
        let connection_end = source[connection_start..]
            .find("\nasync fn verify_offline_live_identity(")
            .map(|offset| connection_start + offset)
            .expect("find end of fresh handoff actor");
        let handoff = &source[connection_start..connection_end];
        for forbidden in [
            "CREATE ",
            "DROP ",
            "PRAGMA wal_checkpoint",
            "sqlite3_wal_checkpoint",
            "TRUNCATE",
            "unlink",
        ] {
            assert!(
                !handoff.contains(forbidden),
                "fresh handoff actor contains forbidden operation {forbidden}"
            );
        }
        let persistent = handoff
            .find("enable_persistent_wal")
            .expect("persistent WAL control is present");
        let no_checkpoint = handoff
            .find("disable_wal_checkpoint_on_close")
            .expect("no-checkpoint control is present");
        let transition = handoff
            .find("PRAGMA journal_mode = WAL")
            .expect("WAL transition is present");
        assert!(persistent < transition);
        assert!(no_checkpoint < transition);

        let classify_start = source
            .find("fn offline_state(")
            .expect("find raw offline classifier");
        let classify_end = source[classify_start..]
            .find("\n    fn captured_identities(")
            .map(|offset| classify_start + offset)
            .expect("find end of raw offline classifier");
        let classifier = &source[classify_start..classify_end];
        for forbidden in [
            "SqliteConnection",
            "connect_with",
            "enable_persistent_wal",
            "disable_wal_checkpoint_on_close",
            "tempfile",
        ] {
            assert!(
                !classifier.contains(forbidden),
                "initialized raw classifier contains forbidden operation {forbidden}"
            );
        }
    }

    fn minimal_sqlite_page() -> [u8; 4096] {
        let mut page = [0_u8; 4096];
        page[..16].copy_from_slice(b"SQLite format 3\0");
        page[16..18].copy_from_slice(&4096_u16.to_be_bytes());
        page[18..24].copy_from_slice(&[2, 2, 0, 64, 32, 32]);
        page[24..28].copy_from_slice(&1_u32.to_be_bytes());
        page[28..32].copy_from_slice(&1_u32.to_be_bytes());
        page[92..96].copy_from_slice(&1_u32.to_be_bytes());
        page[96..100].copy_from_slice(&3_051_003_u32.to_be_bytes());
        page[100..108].copy_from_slice(&[0x0d, 0, 0, 0, 0, 0x10, 0, 0]);
        page
    }

    fn append_wal_frame(
        wal: &mut Vec<u8>,
        checksum: &mut [u32; 2],
        page_number: u32,
        database_pages: u32,
        salts: [u8; 8],
        page: &[u8; 4096],
    ) {
        let mut header = [0_u8; 24];
        header[..4].copy_from_slice(&page_number.to_be_bytes());
        header[4..8].copy_from_slice(&database_pages.to_be_bytes());
        header[8..16].copy_from_slice(&salts);
        *checksum = wal_checksum(&header[..8], false, *checksum);
        *checksum = wal_checksum(page, false, *checksum);
        header[16..20].copy_from_slice(&checksum[0].to_be_bytes());
        header[20..24].copy_from_slice(&checksum[1].to_be_bytes());
        wal.extend_from_slice(&header);
        wal.extend_from_slice(page);
    }

    #[tokio::test]
    async fn committed_wal_discards_spilled_pages_above_final_size() {
        let temporary = tempfile::tempdir().expect("create WAL shrink fixture");
        let database_path = temporary.path().join(DATABASE_NAME);
        let wal_path = temporary.path().join(WAL_NAME);
        let page_one = minimal_sqlite_page();
        fs::write(&database_path, page_one).expect("write WAL shrink main database");

        let salts = [0x21, 0x43, 0x65, 0x87, 0x10, 0x32, 0x54, 0x76];
        let mut wal_header = [0_u8; 32];
        wal_header[..4].copy_from_slice(&0x377f_0682_u32.to_be_bytes());
        wal_header[4..8].copy_from_slice(&3_007_000_u32.to_be_bytes());
        wal_header[8..12].copy_from_slice(&4096_u32.to_be_bytes());
        wal_header[16..24].copy_from_slice(&salts);
        let mut checksum = wal_checksum(&wal_header[..24], false, [0, 0]);
        wal_header[24..28].copy_from_slice(&checksum[0].to_be_bytes());
        wal_header[28..32].copy_from_slice(&checksum[1].to_be_bytes());
        let mut wal = wal_header.to_vec();
        append_wal_frame(&mut wal, &mut checksum, 2, 0, salts, &[0x5a; 4096]);
        append_wal_frame(&mut wal, &mut checksum, 1, 1, salts, &page_one);
        fs::write(&wal_path, &wal).expect("write checksummed shrinking WAL");

        let wal_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&wal_path)
            .expect("open shrinking WAL");
        let wal_entry = HeldEntry {
            name: WAL_NAME,
            path: wal_path.clone(),
            identity: FileIdentity::capture(&wal_path, &wal_file, "inspect shrinking WAL identity")
                .expect("capture shrinking WAL identity"),
            file: wal_file,
        };
        let observation = validate_offline_wal(
            &wal_entry,
            4096,
            Instant::now() + Duration::from_secs(5),
            5_000,
        )
        .expect("raw verifier accepts spill above final database size");
        assert_eq!(observation.committed_pages, Some(1));
        assert_eq!(observation.frames.keys().copied().collect::<Vec<_>>(), [1]);

        let options = SqliteConnectOptions::new()
            .filename(&database_path)
            .create_if_missing(false)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("SQLite 3.51.3 opens shrinking WAL");
        claw_sqlite_file_control::disable_wal_checkpoint_on_close(&mut connection)
            .await
            .expect("retain shrinking WAL during cross-check");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA page_count")
                .fetch_one(&mut connection)
                .await
                .expect("read effective shrinking WAL page count"),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
                .fetch_one(&mut connection)
                .await
                .expect("cross-check shrinking WAL integrity"),
            "ok"
        );
        connection
            .close()
            .await
            .expect("close shrinking WAL cross-check");
    }

    #[tokio::test]
    async fn committed_wal_shrink_then_regrow_retains_high_page() {
        let temporary = tempfile::tempdir().expect("create WAL regrow fixture");
        let database_path = temporary.path().join(DATABASE_NAME);
        let wal_path = temporary.path().join(WAL_NAME);
        let page_one = minimal_sqlite_page();
        fs::write(&database_path, page_one).expect("write WAL regrow main database");

        let salts = [0x11, 0x33, 0x55, 0x77, 0x20, 0x42, 0x64, 0x86];
        let mut wal_header = [0_u8; 32];
        wal_header[..4].copy_from_slice(&0x377f_0682_u32.to_be_bytes());
        wal_header[4..8].copy_from_slice(&3_007_000_u32.to_be_bytes());
        wal_header[8..12].copy_from_slice(&4096_u32.to_be_bytes());
        wal_header[16..24].copy_from_slice(&salts);
        let mut checksum = wal_checksum(&wal_header[..24], false, [0, 0]);
        wal_header[24..28].copy_from_slice(&checksum[0].to_be_bytes());
        wal_header[28..32].copy_from_slice(&checksum[1].to_be_bytes());
        let mut wal = wal_header.to_vec();
        let page_two = [0_u8; 4096];
        append_wal_frame(&mut wal, &mut checksum, 2, 2, salts, &page_two);
        append_wal_frame(&mut wal, &mut checksum, 1, 1, salts, &page_one);
        let mut regrown_page_one = page_one;
        regrown_page_one[24..28].copy_from_slice(&3_u32.to_be_bytes());
        regrown_page_one[28..32].copy_from_slice(&2_u32.to_be_bytes());
        regrown_page_one[32..36].copy_from_slice(&2_u32.to_be_bytes());
        regrown_page_one[36..40].copy_from_slice(&1_u32.to_be_bytes());
        regrown_page_one[92..96].copy_from_slice(&3_u32.to_be_bytes());
        append_wal_frame(&mut wal, &mut checksum, 1, 2, salts, &regrown_page_one);
        fs::write(&wal_path, &wal).expect("write checksummed regrowing WAL");

        let wal_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&wal_path)
            .expect("open regrowing WAL");
        let wal_entry = HeldEntry {
            name: WAL_NAME,
            path: wal_path.clone(),
            identity: FileIdentity::capture(&wal_path, &wal_file, "inspect regrowing WAL identity")
                .expect("capture regrowing WAL identity"),
            file: wal_file,
        };
        let observation = validate_offline_wal(
            &wal_entry,
            4096,
            Instant::now() + Duration::from_secs(5),
            5_000,
        )
        .expect("raw verifier retains high page across shrink and regrow");
        assert_eq!(observation.committed_pages, Some(2));
        assert!(observation.frames.contains_key(&1));
        assert!(observation.frames.contains_key(&2));

        let options = SqliteConnectOptions::new()
            .filename(&database_path)
            .create_if_missing(false)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("SQLite 3.51.3 opens regrowing WAL");
        claw_sqlite_file_control::disable_wal_checkpoint_on_close(&mut connection)
            .await
            .expect("retain regrowing WAL during cross-check");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA page_count")
                .fetch_one(&mut connection)
                .await
                .expect("read effective regrown page count"),
            2
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
                .fetch_one(&mut connection)
                .await
                .expect("cross-check regrowing WAL integrity"),
            "ok"
        );
        connection
            .close()
            .await
            .expect("close regrowing WAL cross-check");
    }

    #[test]
    fn malformed_index_interior_child_field_rejects_without_panic() {
        for cell_offset in [4093_u16, 4094, 4095] {
            let temporary = tempfile::tempdir().expect("create malformed index fixture");
            let database_path = temporary.path().join(DATABASE_NAME);
            let wal_path = temporary.path().join(WAL_NAME);
            let mut database_bytes = vec![0_u8; 3 * 4096];
            let page = &mut database_bytes[4096..8192];
            page[0] = 0x02;
            page[3..5].copy_from_slice(&1_u16.to_be_bytes());
            page[5..7].copy_from_slice(&cell_offset.to_be_bytes());
            page[8..12].copy_from_slice(&3_u32.to_be_bytes());
            page[12..14].copy_from_slice(&cell_offset.to_be_bytes());
            page[usize::from(cell_offset)] = 0xff;
            fs::write(&database_path, &database_bytes).expect("write malformed index database");
            fs::write(&wal_path, []).expect("write empty malformed index WAL");
            let database_file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&database_path)
                .expect("open malformed index database");
            let wal_file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&wal_path)
                .expect("open malformed index WAL");
            let database_identity = FileIdentity::capture(
                &database_path,
                &database_file,
                "capture malformed index database identity",
            )
            .expect("capture malformed index database identity");
            let database_entry = HeldEntry {
                name: DATABASE_NAME,
                path: database_path.clone(),
                file: database_file,
                identity: database_identity,
            };
            let wal_entry = HeldEntry {
                name: WAL_NAME,
                path: wal_path,
                identity: FileIdentity::capture(
                    &temporary.path().join(WAL_NAME),
                    &wal_file,
                    "capture malformed index WAL identity",
                )
                .expect("capture malformed index WAL identity"),
                file: wal_file,
            };
            let frames = HashMap::new();
            let image = DatabaseImage {
                database: &database_entry,
                wal: &wal_entry,
                wal_frames: &frames,
                page_size: 4096,
                usable_size: 4096,
                physical_pages: 3,
                logical_pages: 3,
                cutoff: Instant::now() + Duration::from_secs(5),
                timeout_ms: 5_000,
            };
            let mut claimed = HashSet::new();
            let mut cells = 0;
            let error = validate_index_btree(&image, 2, TEXT_ROWID_INDEX, &mut claimed, &mut cells)
                .expect_err("malformed index child field must reject");
            assert!(matches!(error, StateError::InvalidPath { .. }));
            let mut search_claimed = HashSet::new();
            let search_error =
                read_index_search_page(&image, 2, TEXT_ROWID_INDEX, &mut search_claimed)
                    .expect_err("malformed index search child field must reject");
            assert!(matches!(search_error, StateError::InvalidPath { .. }));
            assert_eq!(
                fs::read(&database_path).expect("reread malformed index database"),
                database_bytes
            );
            let after = fs::metadata(&database_path).expect("reinspect malformed index database");
            assert_eq!(
                (after.dev(), after.ino()),
                (database_identity.device, database_identity.inode)
            );
        }
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
                REDUNDANT_GROUP_CHILD => exercise_redundant_group_credentials(&namespace),
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
        exercise_offline_initializer_fault_matrix();
        let fixture = provision_root_fixture().await;
        let database = fixture.namespace.join(DATABASE_NAME);
        let mut uncheckpointed = SqliteConnection::connect_with(&protected_options(&database))
            .await
            .expect("open offline no-checkpoint fixture");
        claw_sqlite_file_control::enable_persistent_wal(&mut uncheckpointed)
            .await
            .expect("persist offline no-checkpoint fixture WAL");
        claw_sqlite_file_control::disable_wal_checkpoint_on_close(&mut uncheckpointed)
            .await
            .expect("disable fixture checkpoint-on-close");
        sqlx::raw_sql(
            "CREATE TABLE gta_claw_offline_close_probe(value INTEGER);
             DROP TABLE gta_claw_offline_close_probe;",
        )
        .execute(&mut uncheckpointed)
        .await
        .expect("leave committed frames for offline close verification");
        uncheckpointed
            .close()
            .await
            .expect("close no-checkpoint fixture connection");
        let database_before =
            fs::read(&database).expect("read database before idempotent offline verification");
        let wal_path = fixture.namespace.join(WAL_NAME);
        let wal_before =
            fs::read(&wal_path).expect("read WAL before idempotent offline verification");
        assert!(
            !wal_before.is_empty(),
            "no-checkpoint fixture retains committed WAL frames"
        );
        assert_eq!(
            crate::initialize_linux_protected_offline(
                &fixture.namespace,
                SERVICE_UID,
                SERVICE_GID,
            )
            .expect("offline initializer runs safely inside a Tokio test runtime"),
            LinuxProtectedInitialization::AlreadyInitialized
        );
        assert_eq!(
            fs::read(&database).expect("reread database after offline verification"),
            database_before
        );
        assert_eq!(
            fs::read(&wal_path).expect("reread WAL after offline verification"),
            wal_before
        );
        let original_identities = entry_identities(&fixture.namespace);
        assert_child_success(
            service_child_command(
                &fixture.namespace,
                &fixture.ready,
                &fixture.control,
                REDUNDANT_GROUP_CHILD,
            )
            .output()
            .expect("run redundant supplementary-group child"),
            "LinuxProtected redundant supplementary primary-group acceptance",
        );
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

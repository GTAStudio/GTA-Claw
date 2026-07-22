//! Linux characterization of SQLite's preprovisioned WAL namespace.

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqliteSynchronous};
use sqlx::{Connection as _, Row as _, SqliteConnection};

const CHILD_ENV: &str = "GTA_CLAW_LP1_CRASH_CHILD";
const DATABASE_ENV: &str = "GTA_CLAW_LP1_DATABASE";
const READY_ENV: &str = "GTA_CLAW_LP1_READY";
const ROOT_DRIVER_ENV: &str = "GTA_CLAW_LP1_ROOT_DRIVER";
const CLEAN_CHILD: &str = "clean";
const CRASH_CHILD: &str = "crash";
const EMPTY_LOCKED_CHILD: &str = "empty-locked";
const EMPTY_WRITABLE_CHILD: &str = "empty-writable";
const RECOVER_CHILD: &str = "recover";
const SERVICE_UID: u32 = 65_534;
const SERVICE_GID: u32 = 65_534;

unsafe extern "C" {
    fn setgroups(size: usize, groups: *const u32) -> i32;
    fn setgid(gid: u32) -> i32;
    fn setuid(uid: u32) -> i32;
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("child remains owned")
    }

    fn kill_with_sigkill_and_wait(&mut self) {
        let mut child = self.0.take().expect("child remains owned");
        child.kill().expect("send SIGKILL to crash fixture child");
        let status = child.wait().expect("reap crash fixture child");
        assert_eq!(
            status.signal(),
            Some(9),
            "crash fixture must observe SIGKILL"
        );
    }

    fn terminate(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

struct ProvisionedNamespace {
    root: PathBuf,
    database: PathBuf,
    wal: PathBuf,
}

#[derive(Clone, Copy)]
struct ServiceIdentity {
    uid: u32,
    gid: u32,
}

impl Drop for ProvisionedNamespace {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
    }
}

const fn service_identity() -> ServiceIdentity {
    ServiceIdentity {
        uid: SERVICE_UID,
        gid: SERVICE_GID,
    }
}

fn sidecar(database: &Path, suffix: &str) -> PathBuf {
    let mut path = database.as_os_str().to_owned();
    path.push(suffix);
    PathBuf::from(path)
}

fn fixture_tempdir() -> tempfile::TempDir {
    let directory = tempfile::Builder::new()
        .prefix("gta-claw-lp1-")
        .tempdir_in("/tmp")
        .expect("create fixture below the traversable native Linux temp root");
    std::os::unix::fs::chown(directory.path(), Some(0), Some(SERVICE_GID))
        .expect("assign root fixture service group");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))
        .expect("make root fixture traversable by the service group");
    directory
}

fn close_root_fixture(directory: tempfile::TempDir) {
    let path = directory.path().to_owned();
    directory.close().expect("root driver removes its fixture");
    assert!(!path.exists(), "root fixture cleanup must be observable");
}

fn provision_empty_namespace(
    root: &Path,
    identity: ServiceIdentity,
    parent_mode: u32,
) -> ProvisionedNamespace {
    fs::create_dir(root).expect("create protected SQLite fixture directory");
    let database = root.join("state.sqlite");
    let wal = sidecar(&database, "-wal");
    for path in [&database, &wal] {
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .expect("precreate protected SQLite identity");
    }
    lock_down_namespace(root, database, wal, identity, parent_mode)
}

fn lock_down_namespace(
    root: &Path,
    database: PathBuf,
    wal: PathBuf,
    identity: ServiceIdentity,
    parent_mode: u32,
) -> ProvisionedNamespace {
    for path in [&database, &wal] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("secure protected SQLite identity");
        std::os::unix::fs::chown(path, Some(identity.uid), Some(identity.gid))
            .expect("assign protected SQLite service identity");
    }
    std::os::unix::fs::chown(root, Some(0), Some(identity.gid))
        .expect("assign protected namespace service group");
    fs::set_permissions(root, fs::Permissions::from_mode(parent_mode))
        .expect("secure root-owned protected namespace");
    ProvisionedNamespace {
        root: root.to_owned(),
        database,
        wal,
    }
}

async fn provision_initialized_namespace(
    root: &Path,
    identity: ServiceIdentity,
) -> ProvisionedNamespace {
    fs::create_dir(root).expect("create initialized SQLite fixture directory");
    let database = root.join("state.sqlite");
    let wal = sidecar(&database, "-wal");
    let mut connection =
        SqliteConnection::connect_with(&protected_options(&database).create_if_missing(true))
            .await
            .expect("provision database directly into WAL mode");
    assert_eq!(
        claw_sqlite_file_control::main_database_vfs_name(&mut connection)
            .await
            .expect("query provisioner VFS"),
        "unix-excl"
    );
    claw_sqlite_file_control::enable_persistent_wal(&mut connection)
        .await
        .expect("persist provisioned WAL identity");
    sqlx::raw_sql(
        "CREATE TABLE gta_claw_provisioning_probe(value INTEGER);
         DROP TABLE gta_claw_provisioning_probe;",
    )
    .execute(&mut connection)
    .await
    .expect("materialize an empty WAL-mode database");
    checkpoint_truncate(&mut connection, &database).await;
    connection
        .close()
        .await
        .expect("close provisioning connection");
    assert_sqlite_entry_set(root);
    lock_down_namespace(root, database, wal, identity, 0o750)
}

fn provision_control_file(path: &Path, identity: ServiceIdentity) {
    File::create(path).expect("precreate child control file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("secure child control file");
    std::os::unix::fs::chown(path, Some(identity.uid), Some(identity.gid))
        .expect("assign child control file owner");
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

fn assert_namespace_contract(
    namespace: &ProvisionedNamespace,
    identity: ServiceIdentity,
    parent_mode: u32,
) {
    assert_ne!(identity.uid, 0);
    assert_ne!(identity.gid, 0);
    let parent_metadata =
        fs::symlink_metadata(&namespace.root).expect("inspect protected namespace parent");
    assert!(parent_metadata.file_type().is_dir());
    assert!(!parent_metadata.file_type().is_symlink());
    assert_eq!(parent_metadata.uid(), 0);
    assert_eq!(parent_metadata.gid(), identity.gid);
    assert_eq!(parent_metadata.mode() & 0o7777, parent_mode);
    assert_eq!(parent_metadata.nlink(), 2);
    let parent = File::open(&namespace.root).expect("open protected namespace parent");
    assert!(
        claw_sqlite_file_control::unix_file_has_trivial_acl(&parent)
            .expect("validate protected namespace ACL")
    );
    let parent_device = parent_metadata.dev();
    for path in [&namespace.database, &namespace.wal] {
        let metadata = fs::symlink_metadata(path).expect("inspect protected namespace file");
        assert!(metadata.file_type().is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), identity.uid);
        assert_eq!(metadata.gid(), identity.gid);
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.dev(), parent_device);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("open protected namespace file");
        assert!(
            claw_sqlite_file_control::unix_file_is_service_private(&file, identity.uid, 0o600)
                .expect("validate protected namespace file ACL")
        );
    }
    assert_sqlite_entry_set(&namespace.root);
}

fn assert_namespace_mutation_denied(database: &Path) {
    let identity = service_identity();
    assert_service_credentials(identity);
    let root = database
        .parent()
        .expect("protected database has a namespace parent");
    let wal = sidecar(database, "-wal");
    let wal_metadata = fs::symlink_metadata(&wal).unwrap_or_else(|error| {
        panic!(
            "protected WAL disappeared before mutation probes {}: {error}",
            wal.display()
        )
    });
    assert!(wal_metadata.file_type().is_file());
    let mutation_probe = root.join(".mutation-probe");
    expect_permission_denied(
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&mutation_probe),
        "create protected namespace entry",
    );
    expect_permission_denied(fs::remove_file(&wal), "unlink protected WAL");
    expect_permission_denied(
        fs::rename(database, root.join(".renamed-database")),
        "rename protected database",
    );
    expect_permission_denied(
        fs::hard_link(database, root.join(".database-hardlink")),
        "hard-link protected database",
    );
    expect_permission_denied(
        fs::set_permissions(root, fs::Permissions::from_mode(0o770)),
        "chmod protected namespace parent",
    );
    expect_permission_denied(
        std::os::unix::fs::chown(root, Some(identity.uid), Some(identity.gid)),
        "chown protected namespace parent",
    );
    let parent = fs::symlink_metadata(root).expect("reinspect protected namespace parent");
    assert_eq!(parent.uid(), 0);
    assert_eq!(parent.gid(), identity.gid);
    assert_eq!(parent.mode() & 0o7777, 0o750);
    assert_eq!(
        entry_names(root),
        [
            OsString::from("state.sqlite"),
            OsString::from("state.sqlite-wal")
        ]
        .into_iter()
        .collect()
    );
    expect_permission_denied(
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&mutation_probe),
        "restore protected namespace write authority",
    );
}

fn assert_preprovisioned_files_accessible(database: &Path) {
    for path in [database.to_owned(), sidecar(database, "-wal")] {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap_or_else(|error| {
                panic!(
                    "service identity cannot open preprovisioned file {}: {error}",
                    path.display()
                )
            });
    }
}

fn run_root_driver(test_name: &str) -> bool {
    if rustix::process::geteuid().is_root() {
        return false;
    }
    assert!(
        std::env::var_os(ROOT_DRIVER_ENV).is_none(),
        "sudo root driver did not acquire uid 0"
    );
    let output = Command::new("/usr/bin/sudo")
        .arg("-n")
        .arg("/usr/bin/env")
        .arg(format!("{ROOT_DRIVER_ENV}=1"))
        .arg(std::env::current_exe().expect("resolve root-driver test executable"))
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env_remove(CHILD_ENV)
        .env_remove(DATABASE_ENV)
        .env_remove(READY_ENV)
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

fn assert_root_driver() {
    assert!(
        rustix::process::geteuid().is_root() && rustix::process::getuid().is_root(),
        "LinuxProtected acceptance requires a real/effective root driver"
    );
}

fn assert_service_credentials(identity: ServiceIdentity) {
    assert_eq!(rustix::process::getuid().as_raw(), identity.uid);
    assert_eq!(rustix::process::geteuid().as_raw(), identity.uid);
    assert_eq!(rustix::process::getgid().as_raw(), identity.gid);
    assert_eq!(rustix::process::getegid().as_raw(), identity.gid);
    assert!(
        rustix::process::getgroups()
            .expect("read service supplementary groups")
            .is_empty(),
        "service child must start with no supplementary groups"
    );
}

fn child_command(test_name: &str, identity: ServiceIdentity) -> Command {
    let mut command =
        Command::new(std::env::current_exe().expect("resolve current test executable"));
    command
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env_remove(ROOT_DRIVER_ENV);
    // SAFETY: setgroups, setgid, and setuid are async-signal-safe credential
    // syscalls. The hook performs no allocation or shared-state access.
    unsafe {
        command.pre_exec(move || {
            if setgroups(0, std::ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if setgid(identity.gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if setuid(identity.uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

fn protected_options(database: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(database)
        .create_if_missing(false)
        .vfs("unix-excl")
        .locking_mode(SqliteLockingMode::Exclusive)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(1))
}

async fn open_protected(database: &Path) -> SqliteConnection {
    assert_preprovisioned_files_accessible(database);
    assert_namespace_mutation_denied(database);
    let mut connection = SqliteConnection::connect_with(&protected_options(database))
        .await
        .expect("open preprovisioned unix-excl database");
    assert_eq!(
        claw_sqlite_file_control::main_database_vfs_name(&mut connection)
            .await
            .expect("query main-database VFS"),
        "unix-excl"
    );
    claw_sqlite_file_control::enable_persistent_wal(&mut connection)
        .await
        .expect("enable and verify persistent WAL");
    assert_eq!(
        sqlx::query_scalar::<_, String>("PRAGMA locking_mode")
            .fetch_one(&mut connection)
            .await
            .expect("read exclusive locking mode"),
        "exclusive"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("PRAGMA journal_mode")
            .fetch_one(&mut connection)
            .await
            .expect("read WAL journal mode"),
        "wal"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT sqlite_version()")
            .fetch_one(&mut connection)
            .await
            .expect("read bundled SQLite version"),
        "3.51.3"
    );
    connection
}

async fn checkpoint_truncate(connection: &mut SqliteConnection, database: &Path) {
    let row = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_one(connection)
        .await
        .expect("run truncating WAL checkpoint");
    let busy = row
        .try_get::<i64, _>(0)
        .expect("read checkpoint busy result");
    let log_frames = row
        .try_get::<i64, _>(1)
        .expect("read checkpoint WAL frame count");
    let checkpointed_frames = row
        .try_get::<i64, _>(2)
        .expect("read checkpointed frame count");
    assert_eq!(
        busy, 0,
        "truncating checkpoint remained busy: log={log_frames}, checkpointed={checkpointed_frames}"
    );
    assert_eq!(
        fs::metadata(sidecar(database, "-wal"))
            .expect("inspect checkpointed WAL")
            .len(),
        0,
        "successful TRUNCATE checkpoint must empty the held WAL inode"
    );
}

fn wal_checksum(bytes: &[u8], big_endian: bool, mut checksum: [u32; 2]) -> [u32; 2] {
    assert!(!bytes.is_empty() && bytes.len().is_multiple_of(8));
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

fn stored_checksum(bytes: &[u8]) -> [u32; 2] {
    [
        u32::from_be_bytes(bytes[0..4].try_into().expect("first stored WAL checksum")),
        u32::from_be_bytes(bytes[4..8].try_into().expect("second stored WAL checksum")),
    ]
}

fn assert_complete_wal_frames(path: &Path) -> (u64, u64) {
    let bytes = fs::read(path).expect("read committed WAL evidence");
    assert!(bytes.len() >= 32, "WAL header must be complete");
    let magic = u32::from_be_bytes(bytes[0..4].try_into().expect("WAL magic width"));
    assert!(
        matches!(magic, 0x377f_0682 | 0x377f_0683),
        "unexpected WAL magic {magic:#010x}"
    );
    assert_eq!(
        u32::from_be_bytes(bytes[4..8].try_into().expect("WAL version width")),
        3_007_000
    );
    let encoded_page_size =
        u32::from_be_bytes(bytes[8..12].try_into().expect("WAL page-size width"));
    let page_size = u64::from(encoded_page_size);
    assert!(
        (512..=65_536).contains(&page_size) && page_size.is_power_of_two(),
        "invalid WAL page size {page_size}"
    );
    let frame_size = 24_u64 + page_size;
    let payload = u64::try_from(bytes.len() - 32).expect("WAL payload length fits u64");
    assert_eq!(payload % frame_size, 0, "WAL contains an incomplete frame");
    let frames = payload / frame_size;
    assert!(frames >= 1, "WAL must contain at least one committed frame");
    let big_endian_checksum = magic & 1 != 0;
    let mut rolling_checksum = wal_checksum(&bytes[..24], big_endian_checksum, [0_u32, 0_u32]);
    assert_eq!(rolling_checksum, stored_checksum(&bytes[24..32]));
    let salts = &bytes[16..24];
    let mut commit_frames = 0_u64;
    for frame_index in 0..frames {
        let offset =
            32_usize + usize::try_from(frame_index * frame_size).expect("WAL frame offset fits");
        let header = &bytes[offset..offset + 24];
        let page =
            &bytes[offset + 24..offset + usize::try_from(frame_size).expect("WAL frame size fits")];
        let page_number =
            u32::from_be_bytes(header[0..4].try_into().expect("WAL frame page number"));
        assert!(
            (1..=0xffff_fffe).contains(&page_number),
            "invalid WAL frame page number {page_number}"
        );
        assert_eq!(&header[8..16], salts, "WAL frame salts changed");
        rolling_checksum = wal_checksum(&header[..8], big_endian_checksum, rolling_checksum);
        rolling_checksum = wal_checksum(page, big_endian_checksum, rolling_checksum);
        assert_eq!(
            rolling_checksum,
            stored_checksum(&header[16..24]),
            "WAL frame checksum failed at frame {}",
            frame_index + 1
        );
        if u32::from_be_bytes(header[4..8].try_into().expect("WAL commit marker")) != 0 {
            commit_frames += 1;
        }
    }
    assert!(commit_frames >= 1, "WAL has no committed transaction");
    let last_frame_offset =
        32_usize + usize::try_from((frames - 1) * frame_size).expect("last WAL frame offset fits");
    assert_ne!(
        u32::from_be_bytes(
            bytes[last_frame_offset + 4..last_frame_offset + 8]
                .try_into()
                .expect("last WAL commit marker")
        ),
        0,
        "completed autocommit work must end on a commit frame"
    );
    (page_size, frames)
}

async fn assert_main_only_copy_has_no_crash_row(database: &Path) {
    let main_only = database
        .parent()
        .and_then(Path::parent)
        .expect("protected namespace has a fixture parent")
        .join("main-only.sqlite");
    fs::write(
        &main_only,
        fs::read(database).expect("read main database without WAL"),
    )
    .expect("write isolated main-only copy");
    fs::set_permissions(&main_only, fs::Permissions::from_mode(0o600))
        .expect("secure isolated main-only copy");
    let mut connection = SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .filename(&main_only)
            .read_only(true)
            .immutable(true),
    )
    .await
    .expect("open immutable main-only copy");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name = 'crash_value'",
        )
        .fetch_one(&mut connection)
        .await
        .expect("inspect main-only schema"),
        0,
        "committed crash row must still depend on the live WAL"
    );
    connection
        .close()
        .await
        .expect("close immutable main-only copy");
    assert!(!sidecar(&main_only, "-wal").exists());
    assert!(!sidecar(&main_only, "-shm").exists());
    fs::remove_file(main_only).expect("remove main-only evidence copy");
}

fn entry_names(root: &Path) -> BTreeSet<OsString> {
    fs::read_dir(root)
        .expect("read protected SQLite fixture directory")
        .map(|entry| entry.expect("read protected SQLite entry").file_name())
        .collect()
}

fn assert_sqlite_entry_set(root: &Path) {
    assert_eq!(
        entry_names(root),
        [
            OsString::from("state.sqlite"),
            OsString::from("state.sqlite-wal")
        ]
        .into_iter()
        .collect()
    );
}

fn file_identity(path: &Path) -> (u64, u64) {
    let metadata = fs::metadata(path).expect("inspect protected SQLite identity");
    (metadata.dev(), metadata.ino())
}

fn assert_file_identity(path: &Path, expected: (u64, u64), expected_owner: ServiceIdentity) {
    assert_eq!(file_identity(path), expected);
    let metadata = fs::metadata(path).expect("reinspect protected SQLite identity");
    assert!(metadata.is_file());
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.uid(), expected_owner.uid);
    assert_eq!(metadata.gid(), expected_owner.gid);
}

fn sqlite_header_journal_modes(bytes: &[u8]) -> Option<(u8, u8)> {
    (bytes.len() >= 20 && bytes.starts_with(b"SQLite format 3\0")).then(|| (bytes[18], bytes[19]))
}

fn assert_readonly_directory_failure(error: sqlx::Error) {
    let sqlx::Error::Database(error) = error else {
        panic!("locked-down WAL transition returned a non-database error: {error}");
    };
    let code = error
        .code()
        .and_then(|code| code.parse::<i32>().ok())
        .expect("SQLite failure exposes its numeric extended code");
    let readonly_directory = libsqlite3_sys::SQLITE_READONLY | (6 << 8);
    assert_eq!(code, readonly_directory);
    assert_eq!(code & 0xff, libsqlite3_sys::SQLITE_READONLY);
    assert_eq!(error.message(), "attempt to write a readonly database");
}

#[tokio::test]
async fn unix_excl_persistent_wal_uses_only_preprovisioned_entries() {
    if std::env::var_os(CHILD_ENV).as_deref() == Some(OsStr::new(CLEAN_CHILD)) {
        let database =
            PathBuf::from(std::env::var_os(DATABASE_ENV).expect("child database path is set"));
        let mut connection = open_protected(&database).await;
        sqlx::raw_sql(
            "CREATE TABLE durable_value(value INTEGER NOT NULL);
             INSERT INTO durable_value VALUES (1);",
        )
        .execute(&mut connection)
        .await
        .expect("write protected WAL fixture");
        checkpoint_truncate(&mut connection, &database).await;
        connection
            .close()
            .await
            .expect("close protected connection");

        let mut reopened = open_protected(&database).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT value FROM durable_value")
                .fetch_one(&mut reopened)
                .await
                .expect("read protected database after reopen"),
            1
        );
        reopened.close().await.expect("close reopened connection");
        return;
    }

    if run_root_driver("unix_excl_persistent_wal_uses_only_preprovisioned_entries") {
        return;
    }
    assert_root_driver();
    let directory = fixture_tempdir();
    let identity = service_identity();
    let root = directory.path().join("protected");
    let namespace = provision_initialized_namespace(&root, identity).await;
    assert_namespace_contract(&namespace, identity, 0o750);
    let database_identity = file_identity(&namespace.database);
    let wal_identity = file_identity(&namespace.wal);
    let output = child_command(
        "unix_excl_persistent_wal_uses_only_preprovisioned_entries",
        identity,
    )
    .env(CHILD_ENV, CLEAN_CHILD)
    .env(DATABASE_ENV, &namespace.database)
    .output()
    .expect("run clean protected SQLite child");
    assert!(
        output.status.success(),
        "clean protected SQLite child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_sqlite_entry_set(&root);
    assert_file_identity(&namespace.database, database_identity, identity);
    assert_file_identity(&namespace.wal, wal_identity, identity);
    assert_namespace_contract(&namespace, identity, 0o750);
    drop(namespace);
    close_root_fixture(directory);
}

#[tokio::test]
async fn empty_files_are_not_a_complete_provisioning_contract() {
    if std::env::var_os(CHILD_ENV).as_deref() == Some(OsStr::new(EMPTY_WRITABLE_CHILD)) {
        let database =
            PathBuf::from(std::env::var_os(DATABASE_ENV).expect("child database path is set"));
        let identity = service_identity();
        assert_service_credentials(identity);
        assert_preprovisioned_files_accessible(&database);
        assert_eq!(
            fs::read(&database).expect("read empty positive database"),
            []
        );
        assert_eq!(
            fs::read(sidecar(&database, "-wal")).expect("read empty positive WAL"),
            []
        );
        let mutation_probe = database
            .parent()
            .expect("positive database has a namespace parent")
            .join(".writable-probe");
        File::create(&mutation_probe).expect("positive control permits directory mutation");
        fs::remove_file(mutation_probe).expect("remove positive mutation probe");
        let mut connection = SqliteConnection::connect_with(&protected_options(&database))
            .await
            .expect("writable empty namespace enters WAL with the same options");
        assert_eq!(
            claw_sqlite_file_control::main_database_vfs_name(&mut connection)
                .await
                .expect("query writable-control VFS"),
            "unix-excl"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("PRAGMA journal_mode")
                .fetch_one(&mut connection)
                .await
                .expect("read writable-control journal mode"),
            "wal"
        );
        claw_sqlite_file_control::enable_persistent_wal(&mut connection)
            .await
            .expect("persist writable-control WAL");
        sqlx::raw_sql(
            "CREATE TABLE writable_control(value INTEGER);
             DROP TABLE writable_control;",
        )
        .execute(&mut connection)
        .await
        .expect("exercise writable WAL control");
        checkpoint_truncate(&mut connection, &database).await;
        connection
            .close()
            .await
            .expect("close writable WAL control");
        return;
    }
    if std::env::var_os(CHILD_ENV).as_deref() == Some(OsStr::new(EMPTY_LOCKED_CHILD)) {
        let database =
            PathBuf::from(std::env::var_os(DATABASE_ENV).expect("child database path is set"));
        assert_preprovisioned_files_accessible(&database);
        assert_namespace_mutation_denied(&database);
        let before_database = fs::read(&database).expect("read locked empty database");
        let before_wal = fs::read(sidecar(&database, "-wal")).expect("read locked empty WAL");
        assert!(before_database.is_empty());
        assert!(before_wal.is_empty());
        assert_eq!(sqlite_header_journal_modes(&before_database), None);
        let mut first_partial_state = None;
        for attempt in 0..2 {
            let error = SqliteConnection::connect_with(&protected_options(&database))
                .await
                .expect_err(
                    "locked empty namespace cannot complete a verifiable WAL handoff; offline provisioning is required",
                );
            assert_readonly_directory_failure(error);
            let state = (
                fs::read(&database).expect("read partial locked database"),
                fs::read(sidecar(&database, "-wal")).expect("read partial locked WAL"),
            );
            if attempt == 0 {
                first_partial_state = Some(state);
            } else {
                assert_eq!(
                    Some(state),
                    first_partial_state,
                    "repeated locked WAL transition must have stable partial state"
                );
            }
        }
        return;
    }

    if run_root_driver("empty_files_are_not_a_complete_provisioning_contract") {
        return;
    }
    assert_root_driver();
    let directory = fixture_tempdir();
    let identity = service_identity();
    let writable_root = directory.path().join("writable");
    let writable = provision_empty_namespace(&writable_root, identity, 0o770);
    assert_namespace_contract(&writable, identity, 0o770);
    assert!(
        fs::read(&writable.database)
            .expect("read writable start database")
            .is_empty()
    );
    assert!(
        fs::read(&writable.wal)
            .expect("read writable start WAL")
            .is_empty()
    );
    let writable_output = child_command(
        "empty_files_are_not_a_complete_provisioning_contract",
        identity,
    )
    .env(CHILD_ENV, EMPTY_WRITABLE_CHILD)
    .env(DATABASE_ENV, &writable.database)
    .output()
    .expect("run writable empty-control child");
    assert!(
        writable_output.status.success(),
        "writable empty-control child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&writable_output.stdout),
        String::from_utf8_lossy(&writable_output.stderr)
    );
    let writable_database =
        fs::read(&writable.database).expect("read initialized writable-control database");
    assert!(!writable_database.is_empty());
    assert_eq!(
        sqlite_header_journal_modes(&writable_database),
        Some((2, 2))
    );
    assert_namespace_contract(&writable, identity, 0o770);

    let locked_root = directory.path().join("locked");
    let locked = provision_empty_namespace(&locked_root, identity, 0o750);
    assert_namespace_contract(&locked, identity, 0o750);
    let database_identity = file_identity(&locked.database);
    let wal_identity = file_identity(&locked.wal);
    let before_database = fs::read(&locked.database).expect("read locked start database");
    let before_wal = fs::read(&locked.wal).expect("read locked start WAL");
    assert!(before_database.is_empty());
    assert!(before_wal.is_empty());
    let locked_output = child_command(
        "empty_files_are_not_a_complete_provisioning_contract",
        identity,
    )
    .env(CHILD_ENV, EMPTY_LOCKED_CHILD)
    .env(DATABASE_ENV, &locked.database)
    .output()
    .expect("run locked empty-contract child");
    assert!(
        locked_output.status.success(),
        "locked empty-contract child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&locked_output.stdout),
        String::from_utf8_lossy(&locked_output.stderr)
    );
    let after_database = fs::read(&locked.database).expect("read locked result database");
    let after_wal = fs::read(&locked.wal).expect("read locked result WAL");
    assert_eq!(
        after_database.len(),
        0,
        "unexpected locked-transition database partial state: mode={:?}",
        sqlite_header_journal_modes(&after_database)
    );
    assert_eq!(after_wal.len(), 0);
    assert_eq!(after_database, before_database);
    assert_eq!(after_wal, before_wal);
    assert_eq!(sqlite_header_journal_modes(&after_database), None);
    assert_file_identity(&locked.database, database_identity, identity);
    assert_file_identity(&locked.wal, wal_identity, identity);
    assert_namespace_contract(&locked, identity, 0o750);
    drop((locked, writable));
    close_root_fixture(directory);
}

#[tokio::test]
async fn unix_excl_crash_recovery_preserves_fixed_entry_set() {
    if std::env::var_os(CHILD_ENV).as_deref() == Some(OsStr::new(CRASH_CHILD)) {
        let database =
            PathBuf::from(std::env::var_os(DATABASE_ENV).expect("child database path is set"));
        let ready = PathBuf::from(std::env::var_os(READY_ENV).expect("child ready path is set"));
        let mut connection = open_protected(&database).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA wal_autocheckpoint = 0")
                .fetch_one(&mut connection)
                .await
                .expect("disable WAL auto-checkpoint"),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA wal_autocheckpoint")
                .fetch_one(&mut connection)
                .await
                .expect("verify disabled WAL auto-checkpoint"),
            0
        );
        sqlx::raw_sql(
            "CREATE TABLE crash_value(value INTEGER NOT NULL);
             INSERT INTO crash_value VALUES (7);",
        )
        .execute(&mut connection)
        .await
        .expect("commit crash fixture into WAL");
        fs::write(ready, b"ready").expect("signal committed crash fixture");
        loop {
            std::thread::park();
        }
    }
    if std::env::var_os(CHILD_ENV).as_deref() == Some(OsStr::new(RECOVER_CHILD)) {
        let database =
            PathBuf::from(std::env::var_os(DATABASE_ENV).expect("child database path is set"));
        let mut recovered = open_protected(&database).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT value FROM crash_value")
                .fetch_one(&mut recovered)
                .await
                .expect("recover committed crash WAL"),
            7
        );
        checkpoint_truncate(&mut recovered, &database).await;
        recovered.close().await.expect("close recovered connection");
        return;
    }

    if run_root_driver("unix_excl_crash_recovery_preserves_fixed_entry_set") {
        return;
    }
    assert_root_driver();
    let directory = fixture_tempdir();
    let identity = service_identity();
    let root = directory.path().join("protected");
    let ready = directory.path().join("child.ready");
    provision_control_file(&ready, identity);
    let namespace = provision_initialized_namespace(&root, identity).await;
    assert_namespace_contract(&namespace, identity, 0o750);
    let database_identity = file_identity(&namespace.database);
    let wal_identity = file_identity(&namespace.wal);
    let main_before_crash_commit =
        fs::read(&namespace.database).expect("capture pre-crash main database bytes");
    let child = child_command(
        "unix_excl_crash_recovery_preserves_fixed_entry_set",
        identity,
    )
    .env(CHILD_ENV, CRASH_CHILD)
    .env(DATABASE_ENV, &namespace.database)
    .env(READY_ENV, &ready)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .expect("spawn crash fixture child");
    let mut child = ChildGuard::new(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while fs::metadata(&ready).map_or(0, |metadata| metadata.len()) == 0
        && Instant::now() < deadline
    {
        if let Some(status) = child
            .child_mut()
            .try_wait()
            .expect("inspect crash fixture child")
        {
            panic!("crash fixture child exited before readiness: {status}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_ne!(
        fs::metadata(&ready)
            .expect("inspect crash fixture readiness")
            .len(),
        0,
        "crash fixture child did not become ready"
    );
    let (wal_page_size, wal_frames) = assert_complete_wal_frames(&namespace.wal);
    assert!(wal_page_size >= 512);
    assert!(wal_frames >= 1);
    assert_eq!(
        fs::read(&namespace.database).expect("capture post-commit main database bytes"),
        main_before_crash_commit,
        "disabled auto-checkpoint must leave the committed row out of the main database"
    );
    assert_main_only_copy_has_no_crash_row(&namespace.database).await;
    assert_sqlite_entry_set(&root);
    assert_file_identity(&namespace.database, database_identity, identity);
    assert_file_identity(&namespace.wal, wal_identity, identity);
    child.kill_with_sigkill_and_wait();

    let output = child_command(
        "unix_excl_crash_recovery_preserves_fixed_entry_set",
        identity,
    )
    .env(CHILD_ENV, RECOVER_CHILD)
    .env(DATABASE_ENV, &namespace.database)
    .output()
    .expect("run recovered protected SQLite child");
    assert!(
        output.status.success(),
        "recovered protected SQLite child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_sqlite_entry_set(&root);
    assert_file_identity(&namespace.database, database_identity, identity);
    assert_file_identity(&namespace.wal, wal_identity, identity);
    assert!(!sidecar(&namespace.database, "-shm").exists());
    assert!(!sidecar(&namespace.database, "-journal").exists());
    assert_namespace_contract(&namespace, identity, 0o750);
    drop(namespace);
    close_root_fixture(directory);
}

#[tokio::test]
async fn default_vfs_is_detectably_not_unix_excl() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = directory.path().join("default.sqlite");
    File::create(&database).expect("precreate default-VFS database");
    let mut connection = SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .filename(&database)
            .create_if_missing(false),
    )
    .await
    .expect("open default-VFS database");
    let name = claw_sqlite_file_control::main_database_vfs_name(&mut connection)
        .await
        .expect("query default VFS name");
    assert_ne!(name, "unix-excl");
    connection
        .close()
        .await
        .expect("close default-VFS database");
}

#[test]
fn fixture_names_are_native_unix_names() {
    assert_eq!(
        OsStr::new("state.sqlite-wal").as_encoded_bytes(),
        b"state.sqlite-wal"
    );
}

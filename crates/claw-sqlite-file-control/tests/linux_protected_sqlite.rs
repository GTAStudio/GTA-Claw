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
const CLEAN_CHILD: &str = "clean";
const CRASH_CHILD: &str = "crash";
const EMPTY_CHILD: &str = "empty";
const RECOVER_CHILD: &str = "recover";

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
    drop_privileges: bool,
}

impl Drop for ProvisionedNamespace {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
    }
}

fn fixture_identity(container: &Path) -> ServiceIdentity {
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    if uid == 0 {
        const UNPRIVILEGED_ID: u32 = 65_534;
        std::os::unix::fs::chown(container, Some(0), Some(UNPRIVILEGED_ID))
            .expect("assign fixture container group");
        fs::set_permissions(container, fs::Permissions::from_mode(0o750))
            .expect("make fixture container traversable");
        ServiceIdentity {
            uid: UNPRIVILEGED_ID,
            gid: UNPRIVILEGED_ID,
            drop_privileges: true,
        }
    } else {
        ServiceIdentity {
            uid,
            gid,
            drop_privileges: false,
        }
    }
}

fn sidecar(database: &Path, suffix: &str) -> PathBuf {
    let mut path = database.as_os_str().to_owned();
    path.push(suffix);
    PathBuf::from(path)
}

fn fixture_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("gta-claw-lp1-")
        .tempdir_in("/tmp")
        .expect("create fixture below the traversable native Linux temp root")
}

fn provision_empty_namespace(root: &Path, identity: ServiceIdentity) -> ProvisionedNamespace {
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
    lock_down_namespace(root, database, wal, identity)
}

fn lock_down_namespace(
    root: &Path,
    database: PathBuf,
    wal: PathBuf,
    identity: ServiceIdentity,
) -> ProvisionedNamespace {
    for path in [&database, &wal] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("secure protected SQLite identity");
        if identity.drop_privileges {
            std::os::unix::fs::chown(path, Some(identity.uid), Some(identity.gid))
                .expect("assign protected SQLite service identity");
        }
    }
    if identity.drop_privileges {
        std::os::unix::fs::chown(root, Some(0), Some(identity.gid))
            .expect("assign protected namespace service group");
        fs::set_permissions(root, fs::Permissions::from_mode(0o750))
            .expect("secure root-owned protected namespace");
    } else {
        fs::set_permissions(root, fs::Permissions::from_mode(0o500))
            .expect("remove directory-entry mutation authority");
    }
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
    lock_down_namespace(root, database, wal, identity)
}

fn provision_control_file(path: &Path, identity: ServiceIdentity) {
    File::create(path).expect("precreate child control file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("secure child control file");
    if identity.drop_privileges {
        std::os::unix::fs::chown(path, Some(identity.uid), Some(identity.gid))
            .expect("assign child control file owner");
    }
}

fn assert_namespace_mutation_denied(root: &Path) {
    let mutation_probe = root.join(".mutation-probe");
    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&mutation_probe)
    {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(error) => panic!("directory mutation probe failed unexpectedly: {error}"),
        Ok(probe) => {
            drop(probe);
            fs::remove_file(&mutation_probe).expect("remove unexpectedly created mutation probe");
            panic!("protected SQLite fixture retained directory-entry mutation authority");
        }
    }
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

fn child_command(test_name: &str, identity: ServiceIdentity) -> Command {
    let mut command =
        Command::new(std::env::current_exe().expect("resolve current test executable"));
    command
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .arg("--test-threads=1");
    if identity.drop_privileges {
        command.gid(identity.gid).uid(identity.uid);
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
    assert_namespace_mutation_denied(
        database
            .parent()
            .expect("protected database has a namespace parent"),
    );
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

    let directory = fixture_tempdir();
    let identity = fixture_identity(directory.path());
    let root = directory.path().join("protected");
    let namespace = provision_initialized_namespace(&root, identity).await;
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
}

#[tokio::test]
async fn empty_files_are_not_a_complete_provisioning_contract() {
    if std::env::var_os(CHILD_ENV).as_deref() == Some(OsStr::new(EMPTY_CHILD)) {
        let database =
            PathBuf::from(std::env::var_os(DATABASE_ENV).expect("child database path is set"));
        assert_preprovisioned_files_accessible(&database);
        assert_namespace_mutation_denied(
            database
                .parent()
                .expect("empty database has a namespace parent"),
        );
        SqliteConnection::connect_with(&protected_options(&database))
            .await
            .expect_err("an empty database cannot enter WAL after namespace lockdown");
        return;
    }

    let directory = fixture_tempdir();
    let identity = fixture_identity(directory.path());
    let root = directory.path().join("protected");
    let namespace = provision_empty_namespace(&root, identity);
    let database_identity = file_identity(&namespace.database);
    let wal_identity = file_identity(&namespace.wal);
    let output = child_command(
        "empty_files_are_not_a_complete_provisioning_contract",
        identity,
    )
    .env(CHILD_ENV, EMPTY_CHILD)
    .env(DATABASE_ENV, &namespace.database)
    .output()
    .expect("run empty-contract protected SQLite child");
    assert!(
        output.status.success(),
        "empty-contract child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_sqlite_entry_set(&root);
    assert_file_identity(&namespace.database, database_identity, identity);
    assert_file_identity(&namespace.wal, wal_identity, identity);
}

#[tokio::test]
async fn unix_excl_crash_recovery_preserves_fixed_entry_set() {
    if std::env::var_os(CHILD_ENV).as_deref() == Some(OsStr::new(CRASH_CHILD)) {
        let database =
            PathBuf::from(std::env::var_os(DATABASE_ENV).expect("child database path is set"));
        let ready = PathBuf::from(std::env::var_os(READY_ENV).expect("child ready path is set"));
        let mut connection = open_protected(&database).await;
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

    let directory = fixture_tempdir();
    let identity = fixture_identity(directory.path());
    let root = directory.path().join("protected");
    let ready = directory.path().join("child.ready");
    provision_control_file(&ready, identity);
    let namespace = provision_initialized_namespace(&root, identity).await;
    let database_identity = file_identity(&namespace.database);
    let wal_identity = file_identity(&namespace.wal);
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

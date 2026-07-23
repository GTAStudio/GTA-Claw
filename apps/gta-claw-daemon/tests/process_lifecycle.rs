//! Process-level checks for daemon lifecycle modes.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt as _, chown, symlink},
    time::SystemTime,
};
#[cfg(unix)]
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
const ROOT_DRIVER_ENV: &str = "GTA_CLAW_LP3_DAEMON_ROOT_DRIVER";
#[cfg(target_os = "linux")]
const ROOT_TEST_NAME: &str = "linux_protected_initializer_probe_and_serve_lifecycle";
#[cfg(target_os = "linux")]
const SERVICE_UID: u32 = 65_534;
#[cfg(target_os = "linux")]
const SERVICE_GID: u32 = 65_534;
#[cfg(target_os = "linux")]
const PROTECTED_NAMES: [&str; 8] = [
    "state.sqlite",
    "state.sqlite-wal",
    "state.writer.lock",
    "snapshot-0.sqlite",
    "snapshot-0.meta",
    "snapshot-1.sqlite",
    "snapshot-1.meta",
    "snapshot.selector",
];

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
struct StateFixture {
    directory: PathBuf,
    database: PathBuf,
}

#[cfg(unix)]
impl StateFixture {
    fn new() -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "gta-claw-daemon-state-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create daemon state fixture");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("secure daemon state fixture");
        let database = directory.join("state.sqlite");
        Self {
            directory,
            database,
        }
    }
}

#[cfg(unix)]
impl Drop for StateFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[cfg(unix)]
fn portable_arguments(database: &Path) -> Vec<std::ffi::OsString> {
    vec![
        "--state-profile".into(),
        "portable-private".into(),
        "--state-path".into(),
        database.as_os_str().to_owned(),
    ]
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("read child status") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn bounded_output(command: &mut Command, timeout: Duration) -> Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn bounded child");
    let status = wait_for_exit(&mut child, timeout);
    if status.is_none() {
        child.kill().expect("terminate unbounded child");
        let _ = child.wait();
        panic!("child exceeded its bounded process deadline");
    }
    child
        .wait_with_output()
        .expect("collect bounded child output")
}

fn read_lines_bounded(
    stdout: std::process::ChildStdout,
    count: usize,
    timeout: Duration,
) -> std::io::Result<Vec<String>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let result = (0..count)
            .map(|_| {
                let mut line = String::new();
                let read = reader.read_line(&mut line)?;
                if read == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "daemon stdout closed before readiness",
                    ));
                }
                Ok(line)
            })
            .collect();
        let _ = sender.send(result);
    });
    receiver.recv_timeout(timeout).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "daemon readiness exceeded its process deadline",
        )
    })?
}

#[cfg(unix)]
fn signal(process_id: u32, signal: &str) {
    let status = Command::new("/usr/bin/kill")
        .arg(format!("-{signal}"))
        .arg(process_id.to_string())
        .status()
        .expect("invoke /usr/bin/kill");
    assert!(status.success(), "signal delivery failed with {status}");
}

#[cfg(target_os = "linux")]
struct ProtectedFixture {
    outer: PathBuf,
    namespace: PathBuf,
}

#[cfg(target_os = "linux")]
impl Drop for ProtectedFixture {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.outer, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.outer);
    }
}

#[cfg(target_os = "linux")]
fn exact_names(path: &Path) -> Vec<OsString> {
    let mut names = fs::read_dir(path)
        .expect("enumerate protected daemon namespace")
        .map(|entry| entry.expect("read protected daemon entry").file_name())
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[cfg(target_os = "linux")]
fn expected_protected_names() -> Vec<OsString> {
    let mut names = PROTECTED_NAMES
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[cfg(target_os = "linux")]
fn protected_identities(path: &Path) -> Vec<(OsString, u64, u64)> {
    let mut identities = PROTECTED_NAMES
        .iter()
        .map(|name| {
            let metadata =
                fs::symlink_metadata(path.join(name)).expect("inspect protected daemon entry");
            (OsString::from(name), metadata.dev(), metadata.ino())
        })
        .collect::<Vec<_>>();
    identities.sort_by(|left, right| left.0.cmp(&right.0));
    identities
}

#[cfg(target_os = "linux")]
fn create_protected_fixture() -> ProtectedFixture {
    let mut identity_command = Command::new("/usr/bin/id");
    identity_command.arg("-u");
    let identity = bounded_output(&mut identity_command, Duration::from_secs(5));
    assert_eq!(identity.stdout, b"0\n");
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time follows Unix epoch")
        .as_nanos();
    let outer = PathBuf::from(format!(
        "/var/lib/gta-claw-lp3-daemon-{}-{nonce}",
        std::process::id()
    ));
    let namespace = outer.join("state");
    fs::create_dir(&outer).expect("create protected daemon fixture ancestor");
    chown(&outer, Some(0), Some(0)).expect("own fixture ancestor as root");
    fs::set_permissions(&outer, fs::Permissions::from_mode(0o755))
        .expect("secure fixture ancestor");
    fs::create_dir(&namespace).expect("create protected daemon namespace");
    for name in PROTECTED_NAMES {
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(namespace.join(name))
            .unwrap_or_else(|error| panic!("precreate protected daemon entry {name}: {error}"));
        fs::set_permissions(namespace.join(name), fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("secure protected daemon entry {name}: {error}"));
        chown(namespace.join(name), Some(SERVICE_UID), Some(SERVICE_GID))
            .unwrap_or_else(|error| panic!("own protected daemon entry {name}: {error}"));
    }
    chown(&namespace, Some(0), Some(SERVICE_GID)).expect("assign protected daemon namespace group");
    fs::set_permissions(&namespace, fs::Permissions::from_mode(0o750))
        .expect("secure protected daemon namespace");
    ProtectedFixture { outer, namespace }
}

#[cfg(target_os = "linux")]
fn initializer_command(namespace: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command.args([
        OsStr::new("--initialize-linux-protected"),
        OsStr::new("--state-path"),
        namespace.as_os_str(),
        OsStr::new("--service-uid"),
        OsStr::new("65534"),
        OsStr::new("--service-gid"),
        OsStr::new("65534"),
    ]);
    command
}

#[cfg(target_os = "linux")]
fn protected_service_command(namespace: &Path, probe: bool) -> Command {
    let mut command = Command::new("/usr/bin/setpriv");
    command
        .arg(format!("--reuid={SERVICE_UID}"))
        .arg(format!("--regid={SERVICE_GID}"))
        .arg("--clear-groups")
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    if probe {
        command.arg("--probe");
    }
    command
        .arg("--state-profile")
        .arg("linux-protected")
        .arg("--state-path")
        .arg(namespace);
    command
}

#[cfg(target_os = "linux")]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

#[cfg(target_os = "linux")]
fn assert_initializer_rejected(namespace: &Path, operation: &str) {
    let output = bounded_output(&mut initializer_command(namespace), Duration::from_secs(10));
    assert!(
        !output.status.success(),
        "{operation} unexpectedly passed offline initialization"
    );
    assert!(
        output.stdout.is_empty(),
        "{operation} returned success-shaped stdout"
    );
}

#[test]
fn normal_mode_remains_running_until_terminated() {
    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process starts");
    let mut child = ChildGuard(child);
    let stdout = child.0.stdout.take().expect("daemon stdout is piped");
    let startup =
        read_lines_bounded(stdout, 2, Duration::from_secs(5)).expect("daemon startup is readable");
    assert_eq!(startup[0], "ready protocol=1\n");
    assert!(startup[1].starts_with("healthy runtime="));

    thread::sleep(Duration::from_millis(100));

    assert!(
        child
            .0
            .try_wait()
            .expect("daemon status is available")
            .is_none(),
        "normal daemon mode exited instead of supervising"
    );
}

#[test]
fn one_shot_probe_exits_successfully() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command.arg("--probe");
    let output = bounded_output(&mut command, Duration::from_secs(5));

    assert!(output.status.success());

    let output = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(output.starts_with("healthy runtime="));
    assert!(!output.contains("ready protocol="));
}

#[cfg(unix)]
#[test]
fn bare_probe_does_not_create_state_in_its_working_directory() {
    let fixture = StateFixture::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command.arg("--probe").current_dir(&fixture.directory);
    let output = bounded_output(&mut command, Duration::from_secs(5));

    assert!(output.status.success());
    assert!(
        fs::read_dir(&fixture.directory)
            .expect("read probe working directory")
            .next()
            .is_none(),
        "bare probe unexpectedly created state"
    );
}

#[cfg(unix)]
#[test]
fn portable_probe_opens_health_checks_and_closes_state() {
    let fixture = StateFixture::new();
    let mut arguments = portable_arguments(&fixture.database);
    arguments.insert(0, "--probe".into());

    for _ in 0..2 {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
        command.args(&arguments);
        let output = bounded_output(&mut command, Duration::from_secs(10));
        assert!(
            output.status.success(),
            "state-backed probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("probe stdout is UTF-8");
        assert!(stdout.starts_with("healthy runtime="));
        assert!(!stdout.contains("ready protocol="));
    }
    assert!(fixture.database.is_file());
}

#[cfg(unix)]
#[test]
fn portable_serve_handles_signals_excludes_second_writer_and_releases_lock() {
    for signal_name in ["TERM", "INT"] {
        let fixture = StateFixture::new();
        let arguments = portable_arguments(&fixture.database);
        let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
            .args(&arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("state-backed daemon starts");
        let mut child = ChildGuard(child);
        let stdout = child.0.stdout.take().expect("daemon stdout is piped");
        let lines = read_lines_bounded(stdout, 2, Duration::from_secs(10))
            .expect("read state-backed readiness and health");
        assert_eq!(lines[0], "ready protocol=1\n");
        assert!(lines[1].starts_with("healthy runtime="));

        let second = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"))
            .args(&arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("second daemon process starts");
        let mut second = ChildGuard(second);
        let second_status = wait_for_exit(&mut second.0, Duration::from_secs(5));
        if second_status.is_none() {
            second.0.kill().expect("terminate unexpected second writer");
        }
        assert!(
            second_status.is_some_and(|status| !status.success()),
            "second state writer did not fail under the fixed lock"
        );

        signal(child.0.id(), signal_name);
        let status = wait_for_exit(&mut child.0, Duration::from_secs(5));
        if status.is_none() {
            child.0.kill().expect("terminate unbounded daemon shutdown");
        }
        assert!(
            status.is_some_and(|status| status.success()),
            "daemon did not close cleanly after SIG{signal_name}"
        );

        let mut probe_arguments = arguments.clone();
        probe_arguments.insert(0, "--probe".into());
        let mut probe_command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
        probe_command.args(probe_arguments);
        let probe = bounded_output(&mut probe_command, Duration::from_secs(10));
        assert!(
            probe.status.success(),
            "writer lock was not released after SIG{signal_name}: {}",
            String::from_utf8_lossy(&probe.stderr)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_protected_initializer_probe_and_serve_lifecycle() {
    if std::env::var_os(ROOT_DRIVER_ENV).is_none() {
        let mut command = Command::new("/usr/bin/sudo");
        command
            .arg("-n")
            .arg("/usr/bin/env")
            .arg(format!("{ROOT_DRIVER_ENV}=1"))
            .arg(std::env::current_exe().expect("resolve daemon lifecycle test executable"))
            .arg("--exact")
            .arg(ROOT_TEST_NAME)
            .arg("--nocapture")
            .arg("--test-threads=1");
        let output = bounded_output(&mut command, Duration::from_secs(120));
        assert!(
            output.status.success(),
            "LinuxProtected daemon root driver failed: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let fixture = create_protected_fixture();
    let identities = protected_identities(&fixture.namespace);
    assert_eq!(exact_names(&fixture.namespace), expected_protected_names());

    let first = bounded_output(
        &mut initializer_command(&fixture.namespace),
        Duration::from_secs(35),
    );
    assert!(
        first.status.success(),
        "fresh initializer failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(first.stdout, b"Initialized\n");
    assert_eq!(protected_identities(&fixture.namespace), identities);
    let database = fixture.namespace.join("state.sqlite");
    let wal = fixture.namespace.join("state.sqlite-wal");
    let selector = fixture.namespace.join("snapshot.selector");
    let first_database = fs::read(&database).expect("read initialized database");
    let first_wal = fs::read(&wal).expect("read initialized WAL");
    assert!(first_database.starts_with(b"SQLite format 3\0"));
    assert!(first_wal.is_empty());
    assert_eq!(
        fs::metadata(&selector)
            .expect("inspect initialized selector")
            .len(),
        256
    );
    assert!(!contains_bytes(&first_database, b"claw_schema_migrations"));
    assert!(!contains_bytes(&first_database, b"claw_writer_lock"));

    let second = bounded_output(
        &mut initializer_command(&fixture.namespace),
        Duration::from_secs(35),
    );
    assert!(
        second.status.success(),
        "idempotent initializer failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(second.stdout, b"AlreadyInitialized\n");
    assert_eq!(
        fs::read(&database).expect("reread initialized database"),
        first_database
    );
    assert_eq!(fs::read(&wal).expect("reread initialized WAL"), first_wal);
    assert_eq!(protected_identities(&fixture.namespace), identities);

    let probe = bounded_output(
        &mut protected_service_command(&fixture.namespace, true),
        Duration::from_secs(10),
    );
    assert!(
        probe.status.success(),
        "LinuxProtected service probe failed: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    assert!(String::from_utf8_lossy(&probe.stdout).starts_with("healthy runtime="));

    let migrated_before = fs::read(&database).expect("read migrated protected database");
    assert!(contains_bytes(&migrated_before, b"claw_schema_migrations"));
    let after_migration = bounded_output(
        &mut initializer_command(&fixture.namespace),
        Duration::from_secs(35),
    );
    assert!(after_migration.status.success());
    assert_eq!(after_migration.stdout, b"AlreadyInitialized\n");
    let migrated_after = fs::read(&database).expect("reread migrated protected database");
    assert!(contains_bytes(&migrated_after, b"claw_schema_migrations"));
    assert!(!migrated_after.is_empty());
    assert_eq!(protected_identities(&fixture.namespace), identities);

    for signal_name in ["TERM", "INT"] {
        let child = protected_service_command(&fixture.namespace, false)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("LinuxProtected daemon starts");
        let mut child = ChildGuard(child);
        let stdout = child.0.stdout.take().expect("protected stdout is piped");
        let lines = read_lines_bounded(stdout, 2, Duration::from_secs(10))
            .expect("read protected readiness and health");
        assert_eq!(lines[0], "ready protocol=1\n");
        assert!(lines[1].starts_with("healthy runtime="));

        let second_writer = bounded_output(
            &mut protected_service_command(&fixture.namespace, false),
            Duration::from_secs(5),
        );
        assert!(
            !second_writer.status.success(),
            "second LinuxProtected daemon unexpectedly acquired the writer lock"
        );

        signal(child.0.id(), signal_name);
        let status = wait_for_exit(&mut child.0, Duration::from_secs(5));
        if status.is_none() {
            child
                .0
                .kill()
                .expect("terminate unbounded protected shutdown");
        }
        assert!(
            status.is_some_and(|status| status.success()),
            "LinuxProtected daemon did not close cleanly after SIG{signal_name}"
        );

        let released = bounded_output(
            &mut protected_service_command(&fixture.namespace, true),
            Duration::from_secs(10),
        );
        assert!(
            released.status.success(),
            "LinuxProtected writer lock remained held after SIG{signal_name}: {}",
            String::from_utf8_lossy(&released.stderr)
        );
    }

    File::create(fixture.namespace.join("state.sqlite-shm")).expect("create unexpected SHM entry");
    let bad_namespace = bounded_output(
        &mut protected_service_command(&fixture.namespace, true),
        Duration::from_secs(10),
    );
    assert!(!bad_namespace.status.success());
    fs::remove_file(fixture.namespace.join("state.sqlite-shm"))
        .expect("remove unexpected SHM entry");

    {
        let partial = create_protected_fixture();
        let partial_identities = protected_identities(&partial.namespace);
        fs::write(partial.namespace.join("state.sqlite-wal"), b"partial")
            .expect("write partial WAL fixture");
        assert_initializer_rejected(&partial.namespace, "partial DB/WAL namespace");
        assert!(
            fs::read(partial.namespace.join("state.sqlite"))
                .expect("read rejected empty database")
                .is_empty()
        );
        assert_eq!(
            fs::read(partial.namespace.join("state.sqlite-wal"))
                .expect("read rejected partial WAL"),
            b"partial"
        );
        assert_eq!(protected_identities(&partial.namespace), partial_identities);
    }
    {
        let malformed = create_protected_fixture();
        fs::write(malformed.namespace.join("state.sqlite"), b"not sqlite")
            .expect("write malformed database fixture");
        fs::write(malformed.namespace.join("snapshot.selector"), [0_u8; 256])
            .expect("write initialized selector fixture");
        assert_initializer_rejected(&malformed.namespace, "malformed database namespace");
    }
    {
        let malformed_wal = create_protected_fixture();
        let initialized = bounded_output(
            &mut initializer_command(&malformed_wal.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        fs::write(malformed_wal.namespace.join("state.sqlite-wal"), b"bad WAL")
            .expect("write malformed WAL fixture");
        let before = fs::read(malformed_wal.namespace.join("state.sqlite-wal"))
            .expect("read malformed WAL fixture");
        assert_initializer_rejected(&malformed_wal.namespace, "malformed WAL namespace");
        assert_eq!(
            fs::read(malformed_wal.namespace.join("state.sqlite-wal"))
                .expect("reread malformed WAL fixture"),
            before
        );
    }
    {
        let wrong_owner = create_protected_fixture();
        chown(
            wrong_owner.namespace.join("state.writer.lock"),
            Some(0),
            Some(0),
        )
        .expect("change writer owner for rejection");
        assert_initializer_rejected(&wrong_owner.namespace, "wrong-owner namespace");
    }
    {
        let wrong_mode = create_protected_fixture();
        fs::set_permissions(
            wrong_mode.namespace.join("snapshot-0.meta"),
            fs::Permissions::from_mode(0o640),
        )
        .expect("change metadata mode for rejection");
        assert_initializer_rejected(&wrong_mode.namespace, "wrong-mode namespace");
    }
    {
        let symlinked = create_protected_fixture();
        fs::remove_file(symlinked.namespace.join("snapshot-1.meta"))
            .expect("remove symlink target entry");
        symlink(
            symlinked.namespace.join("snapshot-0.meta"),
            symlinked.namespace.join("snapshot-1.meta"),
        )
        .expect("install symlinked protected entry");
        assert_initializer_rejected(&symlinked.namespace, "symlinked namespace");
    }
    {
        let hard_linked = create_protected_fixture();
        fs::remove_file(hard_linked.namespace.join("snapshot-0.sqlite"))
            .expect("remove hard-link target entry");
        fs::hard_link(
            hard_linked.namespace.join("state.sqlite"),
            hard_linked.namespace.join("snapshot-0.sqlite"),
        )
        .expect("install hard-linked protected entry");
        assert_initializer_rejected(&hard_linked.namespace, "hard-linked namespace");
    }
    {
        let extra = create_protected_fixture();
        File::create(extra.namespace.join("state.sqlite-journal"))
            .expect("create unexpected journal entry");
        assert_initializer_rejected(&extra.namespace, "extra-entry namespace");
    }
    {
        let writable_parent = create_protected_fixture();
        fs::set_permissions(
            &writable_parent.namespace,
            fs::Permissions::from_mode(0o770),
        )
        .expect("make namespace service-writable");
        assert_initializer_rejected(&writable_parent.namespace, "service-writable namespace");
    }

    let disallowed_mount = if Path::new("/mnt/c").is_dir() {
        Path::new("/mnt/c")
    } else {
        Path::new("/proc")
    };
    let rejected = bounded_output(
        &mut initializer_command(disallowed_mount),
        Duration::from_secs(10),
    );
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("filesystem type is not in the ext/XFS/Btrfs/F2FS allowlist"),
        "disallowed-mount rejection did not report filesystem facts: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}

#[test]
fn invalid_profile_diagnostic_does_not_echo_rejected_value() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command.args([
        "--state-profile",
        "do-not-echo-this-value",
        "--state-path",
        if cfg!(windows) { r"C:\state" } else { "/state" },
    ]);
    let output = bounded_output(&mut command, Duration::from_secs(5));
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(!stderr.contains("do-not-echo-this-value"));
}

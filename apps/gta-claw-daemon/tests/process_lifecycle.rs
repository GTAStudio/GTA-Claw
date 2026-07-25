//! Process-level checks for daemon lifecycle modes.

#[cfg(any(unix, windows))]
use sqlx::Connection as _;
#[cfg(windows)]
use std::io::Write;
use std::io::{BufRead, BufReader, Read};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt as _, chown, symlink},
    os::unix::process::ExitStatusExt as _,
    time::SystemTime,
};
#[cfg(any(unix, windows))]
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(any(unix, windows))]
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
const ROOT_DRIVER_ENV: &str = "GTA_CLAW_LP3_DAEMON_ROOT_DRIVER";
#[cfg(target_os = "linux")]
const ROOT_BASE_ENV: &str = "GTA_CLAW_LP3_DAEMON_ROOT_BASE";
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

#[cfg(any(unix, windows))]
struct StateFixture {
    directory: PathBuf,
    database: PathBuf,
}

#[cfg(any(unix, windows))]
impl StateFixture {
    fn new() -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "gta-claw-daemon-state-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create daemon state fixture");
        #[cfg(unix)]
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("secure daemon state fixture");
        #[cfg(windows)]
        {
            let sid = Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
                ])
                .output()
                .expect("read current Windows test SID");
            assert!(sid.status.success());
            let sid = String::from_utf8(sid.stdout)
                .expect("current Windows SID is UTF-8")
                .trim()
                .to_owned();
            let output = Command::new("icacls.exe")
                .arg(&directory)
                .args(["/inheritance:r", "/grant:r"])
                .arg(format!("*{sid}:F"))
                .args(["*S-1-5-18:F", "*S-1-5-32-544:F"])
                .output()
                .expect("protect Windows daemon fixture directory");
            assert!(
                output.status.success(),
                "icacls failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let database = directory.join("state.sqlite");
        Self {
            directory,
            database,
        }
    }
}

#[cfg(any(unix, windows))]
impl Drop for StateFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[cfg(any(unix, windows))]
fn portable_arguments(database: &Path) -> Vec<std::ffi::OsString> {
    vec![
        "--state-profile".into(),
        "portable-private".into(),
        "--state-path".into(),
        database.as_os_str().to_owned(),
    ]
}

#[cfg(any(unix, windows))]
fn portable_serve_command(arguments: &[std::ffi::OsString]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0000_0200);
    }
    command
}

#[cfg(any(unix, windows))]
fn prepare_slow_portable_database(fixture: &StateFixture) {
    let mut probe_arguments = portable_arguments(&fixture.database);
    probe_arguments.insert(0, "--probe".into());
    let mut probe = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    probe.args(probe_arguments);
    let probe = bounded_output(&mut probe, Duration::from_secs(15));
    assert!(
        probe.status.success(),
        "initialize slow portable fixture: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let script = "import sqlite3,sys\np=sys.argv[1]\nc=sqlite3.connect(p)\nc.execute('PRAGMA journal_mode=DELETE')\nc.execute(\"INSERT INTO sessions(id,status,created_at_ms,updated_at_ms,version) VALUES ('opening-session','active',1,1,1)\")\nc.execute(\"INSERT INTO tasks(id,session_id,kind,payload,status,created_at_ms,updated_at_ms,version) VALUES ('opening-task','opening-session','fixture',CAST(zeroblob(33554432) AS TEXT),'pending',1,1,1)\")\nc.commit()\nc.close()\n";
    #[cfg(unix)]
    let python = "/usr/bin/python3";
    #[cfg(windows)]
    let python = "python.exe";
    let mut populate = Command::new(python);
    populate.arg("-c").arg(script).arg(&fixture.database);
    let populate = bounded_output(&mut populate, Duration::from_secs(30));
    assert!(
        populate.status.success(),
        "populate slow portable fixture: {}",
        String::from_utf8_lossy(&populate.stderr)
    );
}

#[cfg(any(unix, windows))]
fn spawn_portable_open_locker(fixture: &StateFixture) -> ChildGuard {
    let ready = fixture.directory.join("portable-locker.ready");
    let script = "import pathlib,sqlite3,sys,time\np,ready=sys.argv[1:]\nc=sqlite3.connect(p)\nc.execute('PRAGMA journal_mode=DELETE')\nc.execute('BEGIN EXCLUSIVE')\nc.execute(\"UPDATE sessions SET updated_at_ms=updated_at_ms WHERE id='opening-session'\")\npathlib.Path(ready).write_bytes(b'ready')\ntime.sleep(30)\n";
    #[cfg(unix)]
    let python = "/usr/bin/python3";
    #[cfg(windows)]
    let python = "python.exe";
    let child = Command::new(python)
        .arg("-c")
        .arg(script)
        .arg(&fixture.database)
        .arg(&ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start portable database locker");
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.is_file() {
        if let Some(status) = child.0.try_wait().expect("read portable locker status") {
            let mut stderr = Vec::new();
            child
                .0
                .stderr
                .take()
                .expect("portable locker stderr is piped")
                .read_to_end(&mut stderr)
                .expect("read portable locker stderr");
            panic!(
                "portable locker exited before readiness: {status}; {}",
                String::from_utf8_lossy(&stderr)
            );
        }
        assert!(
            Instant::now() < deadline,
            "portable locker did not reach its exclusive transaction"
        );
        thread::yield_now();
    }
    child
}

#[cfg(any(unix, windows))]
struct PortableCloseStall {
    runtime: tokio::runtime::Runtime,
    connection: Option<sqlx::SqliteConnection>,
}

#[cfg(any(unix, windows))]
impl PortableCloseStall {
    fn start(database: &Path) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("create close-stall runtime");
        let connection = runtime.block_on(async {
            let options = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(database)
                .create_if_missing(false)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .busy_timeout(Duration::from_secs(5));
            let mut connection = sqlx::SqliteConnection::connect_with(&options)
                .await
                .expect("open close-stall SQLite helper");
            sqlx::query(
                "INSERT INTO tasks(
                    id, session_id, kind, payload, status,
                    created_at_ms, updated_at_ms, version
                 ) VALUES (
                    'close-stall-task', 'opening-session', 'fixture', 'held',
                    'pending', 2, 2, 1
                 )",
            )
            .execute(&mut connection)
            .await
            .expect("commit close-stall WAL frame");
            sqlx::query("BEGIN")
                .execute(&mut connection)
                .await
                .expect("begin close-stall read transaction");
            let _: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE id = 'close-stall-task'")
                    .fetch_one(&mut connection)
                    .await
                    .expect("pin close-stall WAL snapshot");
            connection
        });
        Self {
            runtime,
            connection: Some(connection),
        }
    }

    fn release(mut self) {
        if let Some(mut connection) = self.connection.take() {
            self.runtime.block_on(async {
                let _ = sqlx::query("ROLLBACK").execute(&mut connection).await;
                let _ = connection.close().await;
            });
        }
    }
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

#[cfg(target_os = "linux")]
fn linux_process_descendants(root: u32) -> Vec<u32> {
    let mut descendants = Vec::new();
    let mut pending = vec![root];
    while let Some(process) = pending.pop() {
        let Ok(tasks) = fs::read_dir(format!("/proc/{process}/task")) else {
            continue;
        };
        for task in tasks.flatten() {
            let children = fs::read_to_string(task.path().join("children")).unwrap_or_default();
            for child in children
                .split_whitespace()
                .filter_map(|value| value.parse::<u32>().ok())
            {
                if !descendants.contains(&child) {
                    descendants.push(child);
                    pending.push(child);
                }
            }
        }
    }
    descendants
}

#[cfg(target_os = "linux")]
fn linux_process_identity(process: u32) -> Option<(u32, u64)> {
    let stat = fs::read_to_string(format!("/proc/{process}/stat")).ok()?;
    let fields = stat
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let start_time = fields.get(19)?.parse().ok()?;
    Some((process, start_time))
}

#[cfg(target_os = "linux")]
fn send_linux_signal(process: u32, signal: &str, group: bool, start_time: u64) {
    if linux_process_identity(process) != Some((process, start_time)) {
        return;
    }
    let target = if group {
        format!("-{process}")
    } else {
        process.to_string()
    };
    let output = Command::new("/usr/bin/kill")
        .args([signal, "--", &target])
        .output();
    if output.as_ref().is_ok_and(|output| output.status.success()) {
        return;
    }
    if linux_process_identity(process) != Some((process, start_time)) {
        return;
    }
    let _ = Command::new("/usr/bin/sudo")
        .args(["-n", "/usr/bin/kill", signal, "--", &target])
        .output();
}

#[cfg(target_os = "linux")]
fn terminate_linux_process_tree(root: u32, known: &[(u32, u64)]) {
    let mut processes = linux_process_descendants(root)
        .into_iter()
        .filter_map(linux_process_identity)
        .collect::<Vec<_>>();
    for process in known {
        if !processes.iter().any(|known| known.0 == process.0) {
            processes.push(*process);
        }
    }
    if let Some(root) = linux_process_identity(root)
        && !processes.iter().any(|known| known.0 == root.0)
    {
        processes.push(root);
    }
    for (process, start_time) in &processes {
        send_linux_signal(*process, "-STOP", false, *start_time);
    }
    for process in linux_process_descendants(root) {
        if let Some(process) = linux_process_identity(process)
            && !processes.iter().any(|known| known.0 == process.0)
        {
            processes.push(process);
        }
    }
    for (process, start_time) in processes.into_iter().rev() {
        send_linux_signal(process, "-KILL", true, start_time);
        send_linux_signal(process, "-KILL", false, start_time);
    }
}

const MAX_CAPTURED_CHILD_OUTPUT: usize = 4 * 1024 * 1024;

fn spawn_capped_output_reader(mut reader: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut retained = Vec::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let available = MAX_CAPTURED_CHILD_OUTPUT.saturating_sub(retained.len());
                    retained.extend_from_slice(&buffer[..read.min(available)]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => panic!("drain bounded child output: {error}"),
            }
        }
        let _ = sender.send(retained);
    });
    receiver
}

fn bounded_output(command: &mut Command, timeout: Duration) -> Output {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn bounded child");
    #[cfg(unix)]
    let root_process = child.id();
    let stdout_receiver =
        spawn_capped_output_reader(child.stdout.take().expect("bounded child stdout is piped"));
    let stderr_receiver =
        spawn_capped_output_reader(child.stderr.take().expect("bounded child stderr is piped"));
    #[cfg(target_os = "linux")]
    let (status, known_descendants) = {
        let deadline = Instant::now() + timeout;
        let mut known: Vec<(u32, u64)> = Vec::new();
        let status = loop {
            for process in linux_process_descendants(root_process) {
                if !known.iter().any(|known| known.0 == process)
                    && let Some(identity) = linux_process_identity(process)
                {
                    known.push(identity);
                }
            }
            if let Some(status) = child.try_wait().expect("read bounded child status") {
                break Some(status);
            }
            if Instant::now() >= deadline {
                break None;
            }
            thread::sleep(Duration::from_millis(10));
        };
        (status, known)
    };
    #[cfg(not(target_os = "linux"))]
    let status = wait_for_exit(&mut child, timeout);
    if status.is_none() {
        #[cfg(target_os = "linux")]
        terminate_linux_process_tree(root_process, &known_descendants);
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let _ = Command::new("/usr/bin/kill")
                .arg("-KILL")
                .arg(format!("-{}", child.id()))
                .status();
        }
        #[cfg(not(unix))]
        child.kill().expect("terminate unbounded child");
        let _ = child.wait();
        let _ = stdout_receiver.recv_timeout(Duration::from_secs(5));
        let _ = stderr_receiver.recv_timeout(Duration::from_secs(5));
        panic!("child exceeded its bounded process deadline");
    }
    let status = status.expect("bounded child exited");
    let stdout = stdout_receiver.recv_timeout(Duration::from_secs(5));
    let stderr = stderr_receiver.recv_timeout(Duration::from_secs(5));
    if stdout.is_err() || stderr.is_err() {
        #[cfg(target_os = "linux")]
        terminate_linux_process_tree(root_process, &known_descendants);
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let _ = Command::new("/usr/bin/kill")
                .arg("-KILL")
                .arg(format!("-{root_process}"))
                .status();
        }
        panic!("bounded child output readers did not terminate");
    }
    let stdout = stdout.expect("checked bounded stdout reader");
    let stderr = stderr.expect("checked bounded stderr reader");
    Output {
        status,
        stdout,
        stderr,
    }
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

#[cfg(any(unix, windows))]
fn spawn_line_receiver(reader: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) if sender.send(line).is_ok() => {}
                Ok(_) | Err(_) => break,
            }
        }
    });
    receiver
}

#[cfg(any(unix, windows))]
fn wait_for_lifecycle_phase(lines: &mpsc::Receiver<String>, phase: &str, timeout: Duration) {
    let expected = format!("gta-claw lifecycle {phase}\n");
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = lines
            .recv_timeout(remaining)
            .unwrap_or_else(|_| panic!("daemon did not report lifecycle phase {phase}"));
        if line.replace("\r\n", "\n") == expected {
            return;
        }
    }
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
fn process_is_stopped(process_id: u32) -> bool {
    fs::read_to_string(format!("/proc/{process_id}/status"))
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("State:"))
                .map(str::to_owned)
        })
        .is_some_and(|state| state.contains('T') || state.contains('t'))
}

#[cfg(target_os = "linux")]
fn process_has_pending_signal(process_id: u32, signal_number: u32) -> bool {
    let mask = 1_u64 << (signal_number - 1);
    fs::read_to_string(format!("/proc/{process_id}/status"))
        .ok()
        .is_some_and(|status| {
            status.lines().any(|line| {
                matches!(line.split_once(':'), Some(("SigPnd" | "ShdPnd", value))
                    if u64::from_str_radix(value.trim(), 16)
                        .is_ok_and(|pending| pending & mask != 0))
            })
        })
}

#[cfg(target_os = "linux")]
fn wait_for_process_fact(mut fact: impl FnMut() -> bool, timeout: Duration, failure: &'static str) {
    let deadline = Instant::now() + timeout;
    while !fact() {
        assert!(Instant::now() < deadline, "{failure}");
        thread::yield_now();
    }
}

#[cfg(target_os = "linux")]
fn deliver_consumed_signal(process_id: u32, signal_name: &str, signal_number: u32) {
    signal(process_id, "STOP");
    wait_for_process_fact(
        || process_is_stopped(process_id),
        Duration::from_secs(2),
        "daemon did not stop before queued signal delivery",
    );
    signal(process_id, signal_name);
    wait_for_process_fact(
        || process_has_pending_signal(process_id, signal_number),
        Duration::from_secs(2),
        "first shutdown signal was not observably queued",
    );
    signal(process_id, "CONT");
    wait_for_process_fact(
        || !process_has_pending_signal(process_id, signal_number),
        Duration::from_secs(2),
        "first shutdown signal was not consumed",
    );
}

#[cfg(windows)]
struct WindowsSignalBroker {
    child: Child,
    input: Option<std::process::ChildStdin>,
    output: mpsc::Receiver<String>,
}

#[cfg(windows)]
impl WindowsSignalBroker {
    fn new() -> Self {
        let script = "Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class ConsoleSignal { [DllImport(\"kernel32.dll\", SetLastError=true)] public static extern bool GenerateConsoleCtrlEvent(uint signal, uint group); }'; while (($line = [Console]::In.ReadLine()) -ne $null) { $ok = [ConsoleSignal]::GenerateConsoleCtrlEvent(1, [uint32]$line); [Console]::Out.WriteLine($(if ($ok) {'ok'} else {'error'})); [Console]::Out.Flush() }";
        let mut child = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start Windows console-signal broker");
        let input = child.stdin.take().expect("signal broker stdin is piped");
        let output =
            spawn_line_receiver(child.stdout.take().expect("signal broker stdout is piped"));
        Self {
            child,
            input: Some(input),
            output,
        }
    }

    fn send(&mut self, process_id: u32) {
        let input = self.input.as_mut().expect("signal broker stdin is open");
        writeln!(input, "{process_id}").expect("write console-signal request");
        input.flush().expect("flush console-signal request");
        let response = self
            .output
            .recv_timeout(Duration::from_secs(5))
            .expect("read bounded console-signal response");
        assert_eq!(response.trim_end(), "ok", "console signal delivery failed");
    }
}

#[cfg(windows)]
impl Drop for WindowsSignalBroker {
    fn drop(&mut self) {
        drop(self.input.take());
        let _ = self.child.kill();
        let _ = wait_for_exit(&mut self.child, Duration::from_secs(5));
    }
}

#[cfg(windows)]
std::thread_local! {
    static WINDOWS_SIGNAL_BROKER: std::cell::RefCell<Option<WindowsSignalBroker>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(windows)]
fn signal(process_id: u32, signal: &str) {
    assert_eq!(signal, "BREAK");
    WINDOWS_SIGNAL_BROKER.with(|broker| {
        broker
            .borrow_mut()
            .get_or_insert_with(WindowsSignalBroker::new)
            .send(process_id);
    });
}

#[cfg(windows)]
fn prepare_signal_broker() {
    WINDOWS_SIGNAL_BROKER.with(|broker| {
        broker
            .borrow_mut()
            .get_or_insert_with(WindowsSignalBroker::new);
    });
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
fn protected_bytes(path: &Path) -> Vec<(OsString, Vec<u8>)> {
    let mut bytes = PROTECTED_NAMES
        .iter()
        .map(|name| {
            (
                OsString::from(name),
                fs::read(path.join(name)).expect("read protected daemon entry bytes"),
            )
        })
        .collect::<Vec<_>>();
    bytes.sort_by(|left, right| left.0.cmp(&right.0));
    bytes
}

#[cfg(target_os = "linux")]
fn create_protected_fixture() -> ProtectedFixture {
    create_protected_fixture_with_depth(0)
}

#[cfg(target_os = "linux")]
fn create_protected_fixture_with_depth(depth: usize) -> ProtectedFixture {
    let mut identity_command = Command::new("/usr/bin/id");
    identity_command.arg("-u");
    let identity = bounded_output(&mut identity_command, Duration::from_secs(5));
    assert_eq!(identity.stdout, b"0\n");
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time follows Unix epoch")
        .as_nanos();
    let outer = std::env::var_os(ROOT_BASE_ENV)
        .map(PathBuf::from)
        .map(|base| base.join(format!("fixture-{}-{nonce}", std::process::id())))
        .unwrap_or_else(|| {
            PathBuf::from(format!(
                "/var/lib/gta-claw-lp3-daemon-{}-{nonce}",
                std::process::id()
            ))
        });
    fs::create_dir(&outer).expect("create protected daemon fixture ancestor");
    chown(&outer, Some(0), Some(0)).expect("own fixture ancestor as root");
    fs::set_permissions(&outer, fs::Permissions::from_mode(0o755))
        .expect("secure fixture ancestor");
    let mut parent = outer.clone();
    for _ in 0..depth {
        parent.push("d");
        fs::create_dir(&parent).expect("create deep protected fixture ancestor");
        chown(&parent, Some(0), Some(0)).expect("own deep fixture ancestor as root");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755))
            .expect("secure deep fixture ancestor");
    }
    let namespace = parent.join("state");
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
fn install_large_initialized_database(fixture: &ProtectedFixture) {
    let source = fixture.outer.join("large.sqlite");
    fs::copy(fixture.namespace.join("state.sqlite"), &source)
        .expect("copy migrated database for large fixture");
    let script = "import sqlite3, sys\npath = sys.argv[1]\nconnection = sqlite3.connect(path)\nconnection.execute('PRAGMA journal_mode=WAL')\nconnection.execute(\"INSERT INTO sessions(id,status,created_at_ms,updated_at_ms,version) VALUES ('large-session','active',1,1,1)\")\nconnection.execute(\"INSERT INTO devices(id,display_name,created_at_ms,updated_at_ms,version) VALUES ('large-device',?,1,1,1)\",('x'*1048577,))\nconnection.execute(\"INSERT INTO tasks(id,session_id,kind,payload,status,created_at_ms,updated_at_ms,version) VALUES ('large-task','large-session','fixture',CAST(zeroblob(16777216) AS TEXT),'pending',1,1,1)\")\nconnection.commit()\nconnection.execute('PRAGMA wal_checkpoint(TRUNCATE)')\nconnection.close()\n";
    let mut command = Command::new("/usr/bin/python3");
    command.arg("-c").arg(script).arg(&source);
    let output = bounded_output(&mut command, Duration::from_secs(30));
    assert!(
        output.status.success(),
        "create large initialized database: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = fs::read(&source).expect("read large initialized database");
    assert!(bytes.len() > 16 * 1024 * 1024);
    assert_eq!(&bytes[18..20], [2, 2]);
    fs::write(fixture.namespace.join("state.sqlite"), bytes)
        .expect("install large initialized database bytes");
    OpenOptions::new()
        .write(true)
        .open(fixture.namespace.join("state.sqlite-wal"))
        .expect("open held WAL for large fixture")
        .set_len(0)
        .expect("clear stale WAL bytes for large fixture");
    fs::remove_file(source).expect("remove large database source");
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = fixture.outer.join(format!("large.sqlite{suffix}"));
        if path.exists() {
            fs::remove_file(path).expect("remove large database sidecar");
        }
    }
}

#[cfg(target_os = "linux")]
fn install_out_of_order_btree(fixture: &ProtectedFixture, object: &str) {
    let source = fixture.outer.join(format!("{object}.sqlite"));
    fs::copy(fixture.namespace.join("state.sqlite"), &source)
        .expect("copy migrated database for ordering fixture");
    let script = "import sqlite3, sys\npath,obj=sys.argv[1:]\nc=sqlite3.connect(path)\nc.execute('PRAGMA journal_mode=WAL')\nfor i in range(512):\n c.execute(\"INSERT INTO sessions(id,status,created_at_ms,updated_at_ms,version) VALUES (?,?,?,?,1)\",(f'ordered-{i:04d}','active',i,i))\nc.commit()\nc.execute('PRAGMA wal_checkpoint(TRUNCATE)')\nroot=c.execute('SELECT rootpage FROM sqlite_schema WHERE name=?',(obj,)).fetchone()[0]\nc.close()\nprint(root)\n";
    let mut command = Command::new("/usr/bin/python3");
    command.arg("-c").arg(script).arg(&source).arg(object);
    let output = bounded_output(&mut command, Duration::from_secs(30));
    assert!(
        output.status.success(),
        "create ordered b-tree fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let root = String::from_utf8(output.stdout)
        .expect("ordering root page is UTF-8")
        .trim()
        .parse::<u32>()
        .expect("ordering root page is numeric");
    let mut bytes = fs::read(&source).expect("read ordered b-tree fixture");
    let encoded_page_size = u16::from_be_bytes([bytes[16], bytes[17]]);
    let page_size = if encoded_page_size == 1 {
        65_536
    } else {
        usize::from(encoded_page_size)
    };
    fs::write(fixture.namespace.join("state.sqlite"), &bytes)
        .expect("install valid multi-page b-tree fixture");
    OpenOptions::new()
        .write(true)
        .open(fixture.namespace.join("state.sqlite-wal"))
        .expect("open held WAL for valid multi-page fixture")
        .set_len(0)
        .expect("clear stale WAL bytes for valid multi-page fixture");
    let valid = bounded_output(
        &mut initializer_command(&fixture.namespace),
        Duration::from_secs(20),
    );
    assert!(
        valid.status.success(),
        "raw verifier rejected a valid multi-page {object} tree: {}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert_eq!(valid.stdout, b"AlreadyInitialized\n");
    let mut page = root;
    loop {
        let page_start = usize::try_from(page - 1).expect("page number fits usize") * page_size;
        match bytes[page_start] {
            0x05 | 0x02 => {
                let pointer = usize::from(u16::from_be_bytes([
                    bytes[page_start + 12],
                    bytes[page_start + 13],
                ]));
                page = u32::from_be_bytes(
                    bytes[page_start + pointer..page_start + pointer + 4]
                        .try_into()
                        .expect("interior child pointer is in bounds"),
                );
            }
            0x0d | 0x0a => {
                let cells = u16::from_be_bytes([bytes[page_start + 3], bytes[page_start + 4]]);
                assert!(cells >= 2, "ordering fixture leaf has at least two cells");
                bytes.swap(page_start + 8, page_start + 10);
                bytes.swap(page_start + 9, page_start + 11);
                break;
            }
            other => panic!("unexpected b-tree page type {other:#x}"),
        }
    }
    fs::write(fixture.namespace.join("state.sqlite"), bytes)
        .expect("install out-of-order b-tree fixture");
    OpenOptions::new()
        .write(true)
        .open(fixture.namespace.join("state.sqlite-wal"))
        .expect("open held WAL for ordering fixture")
        .set_len(0)
        .expect("clear stale WAL bytes for ordering fixture");
    fs::remove_file(source).expect("remove ordering database source");
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = fixture.outer.join(format!("{object}.sqlite{suffix}"));
        if path.exists() {
            fs::remove_file(path).expect("remove ordering database sidecar");
        }
    }
}

#[cfg(target_os = "linux")]
fn install_table_index_mismatch(fixture: &ProtectedFixture) {
    let source = fixture.outer.join("index-mismatch.sqlite");
    fs::copy(fixture.namespace.join("state.sqlite"), &source)
        .expect("copy migrated database for index mismatch");
    let script = "import sqlite3, sys\npath=sys.argv[1]\nc=sqlite3.connect(path)\nc.execute('PRAGMA journal_mode=WAL')\nc.execute(\"INSERT INTO sessions(id,status,created_at_ms,updated_at_ms,version) VALUES ('logical-original','active',1,1,1)\")\nc.commit()\nc.execute('PRAGMA wal_checkpoint(TRUNCATE)')\nroot=c.execute(\"SELECT rootpage FROM sqlite_schema WHERE name='sessions'\").fetchone()[0]\nc.close()\nprint(root)\n";
    let mut command = Command::new("/usr/bin/python3");
    command.arg("-c").arg(script).arg(&source);
    let output = bounded_output(&mut command, Duration::from_secs(30));
    assert!(
        output.status.success(),
        "create index mismatch fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let root = String::from_utf8(output.stdout)
        .expect("sessions root page is UTF-8")
        .trim()
        .parse::<usize>()
        .expect("sessions root page is numeric");
    let mut bytes = fs::read(&source).expect("read index mismatch fixture");
    let encoded_page_size = u16::from_be_bytes([bytes[16], bytes[17]]);
    let page_size = if encoded_page_size == 1 {
        65_536
    } else {
        usize::from(encoded_page_size)
    };
    let start = (root - 1) * page_size;
    let end = start + page_size;
    let original = b"logical-original";
    let replacement = b"logical-tampered";
    assert_eq!(original.len(), replacement.len());
    let offset = bytes[start..end]
        .windows(original.len())
        .position(|candidate| candidate == original)
        .expect("sessions table page contains the indexed identifier");
    bytes[start + offset..start + offset + original.len()].copy_from_slice(replacement);
    fs::write(fixture.namespace.join("state.sqlite"), bytes)
        .expect("install table/index mismatch fixture");
    OpenOptions::new()
        .write(true)
        .open(fixture.namespace.join("state.sqlite-wal"))
        .expect("open held WAL for index mismatch")
        .set_len(0)
        .expect("clear stale WAL bytes for index mismatch");
    fs::remove_file(source).expect("remove index mismatch source");
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = fixture.outer.join(format!("index-mismatch.sqlite{suffix}"));
        if path.exists() {
            fs::remove_file(path).expect("remove index mismatch sidecar");
        }
    }
}

#[cfg(target_os = "linux")]
fn install_noncanonical_identifier(fixture: &ProtectedFixture) {
    let source = fixture.outer.join("noncanonical-id.sqlite");
    fs::copy(fixture.namespace.join("state.sqlite"), &source)
        .expect("copy migrated database for noncanonical identifier");
    let script = "import sqlite3, sys\npath=sys.argv[1]\nc=sqlite3.connect(path)\nc.execute('PRAGMA journal_mode=WAL')\nc.execute(\"INSERT INTO sessions(id,status,created_at_ms,updated_at_ms,version) VALUES (' padded ','active',1,1,1)\")\nc.commit()\nc.execute('PRAGMA wal_checkpoint(TRUNCATE)')\nc.close()\n";
    let mut command = Command::new("/usr/bin/python3");
    command.arg("-c").arg(script).arg(&source);
    let output = bounded_output(&mut command, Duration::from_secs(30));
    assert!(
        output.status.success(),
        "create noncanonical identifier fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::write(
        fixture.namespace.join("state.sqlite"),
        fs::read(&source).expect("read noncanonical identifier fixture"),
    )
    .expect("install noncanonical identifier fixture");
    OpenOptions::new()
        .write(true)
        .open(fixture.namespace.join("state.sqlite-wal"))
        .expect("open held WAL for noncanonical identifier")
        .set_len(0)
        .expect("clear stale WAL bytes for noncanonical identifier");
    fs::remove_file(source).expect("remove noncanonical identifier source");
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = fixture
            .outer
            .join(format!("noncanonical-id.sqlite{suffix}"));
        if path.exists() {
            fs::remove_file(path).expect("remove noncanonical identifier sidecar");
        }
    }
}

#[cfg(target_os = "linux")]
fn install_uncommitted_rewind_database(fixture: &ProtectedFixture) {
    let source = fixture.outer.join("rewind.sqlite");
    let ready = fixture.outer.join("rewind.ready");
    fs::copy(fixture.namespace.join("state.sqlite"), &source)
        .expect("copy migrated database for rewind fixture");
    let script = "import os,sqlite3,sys,time\npath,ready=sys.argv[1:]\nc=sqlite3.connect(path)\nc.execute('PRAGMA journal_mode=WAL')\nc.execute('PRAGMA wal_autocheckpoint=0')\nc.execute('PRAGMA wal_checkpoint(TRUNCATE)')\nwal_inode=os.stat(path+'-wal').st_ino\nc.execute('PRAGMA cache_size=1')\nc.execute('BEGIN IMMEDIATE')\nc.execute('CREATE TABLE rewind_fixture(value BLOB NOT NULL)')\nfor _ in range(256):\n c.execute('INSERT INTO rewind_fixture VALUES (zeroblob(65536))')\n if os.path.exists(path+'-wal') and os.path.getsize(path+'-wal')>32:\n  assert os.stat(path+'-wal').st_ino==wal_inode\n  open(ready,'wb').write(str(wal_inode).encode())\n  break\ntime.sleep(30)\n";
    let child = Command::new("/usr/bin/python3")
        .arg("-c")
        .arg(script)
        .arg(&source)
        .arg(&ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start uncommitted WAL producer");
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.is_file() {
        if let Some(status) = child
            .0
            .try_wait()
            .expect("read uncommitted producer status")
        {
            let stderr = read_child_stderr(&mut child.0);
            panic!(
                "uncommitted WAL producer stopped early: {status}; {}",
                String::from_utf8_lossy(&stderr)
            );
        }
        assert!(
            Instant::now() < deadline,
            "uncommitted WAL producer did not spill before the deadline"
        );
        thread::yield_now();
    }
    child.0.kill().expect("SIGKILL uncommitted WAL producer");
    let status = child.0.wait().expect("reap uncommitted WAL producer");
    assert_eq!(status.signal(), Some(9));
    let wal = source.with_extension("sqlite-wal");
    let wal_bytes = fs::read(&wal).expect("read uncommitted rewind WAL");
    assert!(wal_bytes.len() > 32);
    fs::write(
        fixture.namespace.join("state.sqlite"),
        fs::read(&source).expect("read rewind main database"),
    )
    .expect("install rewind main database");
    fs::write(fixture.namespace.join("state.sqlite-wal"), wal_bytes)
        .expect("install uncommitted rewind WAL");
    for path in [
        source.clone(),
        source.with_extension("sqlite-wal"),
        source.with_extension("sqlite-shm"),
        ready,
    ] {
        if path.exists() {
            fs::remove_file(path).expect("remove rewind fixture artifact");
        }
    }
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
fn provision_command(namespace: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command.args([
        OsStr::new("--provision-linux-protected"),
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
fn prepare_command(namespace: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    command.args([
        OsStr::new("--prepare-linux-protected"),
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
fn gated_initializer_command(namespace: &Path, gate: &Path) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "while [ ! -e \"$1\" ]; do :; done; shift; exec \"$@\"",
            "gta-claw-init-gate",
        ])
        .arg(gate)
        .arg(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .args([
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
fn gated_protected_service_command(namespace: &Path, gate: &Path) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "while [ ! -e \"$1\" ]; do :; done; shift; exec \"$@\"",
            "gta-claw-service-gate",
        ])
        .arg(gate)
        .arg("/usr/bin/setpriv")
        .arg(format!("--reuid={SERVICE_UID}"))
        .arg(format!("--regid={SERVICE_GID}"))
        .arg("--clear-groups")
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_gta-claw-daemon"))
        .arg("--state-profile")
        .arg("linux-protected")
        .arg("--state-path")
        .arg(namespace);
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
    let before = protected_namespace_snapshot(namespace);
    let output = bounded_output(&mut initializer_command(namespace), Duration::from_secs(10));
    assert!(
        !output.status.success(),
        "{operation} unexpectedly passed offline initialization"
    );
    assert!(
        output.stdout.is_empty(),
        "{operation} returned success-shaped stdout"
    );
    assert_eq!(
        protected_namespace_snapshot(namespace),
        before,
        "{operation} mutated the rejected namespace"
    );
}

#[cfg(target_os = "linux")]
fn assert_provisioner_rejected(namespace: &Path, operation: &str) {
    let before = protected_namespace_snapshot(namespace);
    let output = bounded_output(&mut provision_command(namespace), Duration::from_secs(10));
    assert!(
        !output.status.success(),
        "{operation} unexpectedly passed offline provisioning"
    );
    assert!(
        output.stdout.is_empty(),
        "{operation} returned success-shaped stdout"
    );
    assert_eq!(
        protected_namespace_snapshot(namespace),
        before,
        "{operation} mutated the rejected namespace"
    );
}

#[cfg(target_os = "linux")]
#[derive(Debug, Eq, PartialEq)]
struct ProtectedEntrySnapshot {
    name: OsString,
    bytes: Vec<u8>,
    length: u64,
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Eq, PartialEq)]
struct ProtectedNamespaceSnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    entries: Vec<ProtectedEntrySnapshot>,
}

#[cfg(target_os = "linux")]
fn protected_namespace_snapshot(namespace: &Path) -> ProtectedNamespaceSnapshot {
    let directory = fs::symlink_metadata(namespace).expect("inspect protected namespace metadata");
    let mut names = fs::read_dir(namespace)
        .expect("read protected namespace snapshot")
        .map(|entry| entry.expect("read protected namespace entry").file_name())
        .collect::<Vec<_>>();
    names.sort();
    let entries = names
        .into_iter()
        .map(|name| {
            let path = namespace.join(&name);
            let metadata =
                fs::symlink_metadata(&path).expect("inspect protected snapshot entry metadata");
            let bytes = if metadata.file_type().is_file() {
                fs::read(&path).expect("read protected snapshot entry bytes")
            } else if metadata.file_type().is_symlink() {
                fs::read_link(&path)
                    .expect("read protected snapshot symlink")
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec()
            } else {
                Vec::new()
            };
            ProtectedEntrySnapshot {
                name,
                bytes,
                length: metadata.len(),
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                links: metadata.nlink(),
            }
        })
        .collect();
    ProtectedNamespaceSnapshot {
        device: directory.dev(),
        inode: directory.ino(),
        mode: directory.mode(),
        uid: directory.uid(),
        gid: directory.gid(),
        links: directory.nlink(),
        entries,
    }
}

#[cfg(target_os = "linux")]
fn spawn_writer_lock_stop_monitor(
    namespace: &Path,
    process_id: u32,
    acknowledgement: &Path,
) -> ChildGuard {
    let lock_inode = fs::metadata(namespace.join("state.writer.lock"))
        .expect("inspect writer lock contention identity")
        .ino();
    let ready = acknowledgement.with_extension("monitor-ready");
    let script = ": > \"$4\"; while [ -d /proc/\"$1\" ]; do for info in /proc/\"$1\"/fdinfo/*; do [ -r \"$info\" ] || continue; while read -r label _ _ _ kind _ identity _ _; do case \"$identity\" in *:\"$2\") if [ \"$label\" = lock: ] && [ \"$kind\" = WRITE ]; then kill -STOP \"$1\"; : > \"$3\"; exit 0; fi;; esac; done <\"$info\"; done; done; exit 3";
    let monitor = Command::new("/usr/bin/nice")
        .args([
            "-n",
            "-20",
            "/bin/sh",
            "-c",
            script,
            "gta-claw-lock-monitor",
        ])
        .arg(process_id.to_string())
        .arg(lock_inode.to_string())
        .arg(acknowledgement)
        .arg(&ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start writer lock stop monitor");
    let mut monitor = ChildGuard(monitor);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.is_file() {
        assert!(
            monitor
                .0
                .try_wait()
                .expect("read lock monitor startup status")
                .is_none(),
            "lock monitor stopped before startup acknowledgement"
        );
        assert!(
            Instant::now() < deadline,
            "lock monitor did not acknowledge startup"
        );
        thread::yield_now();
    }
    monitor
}

#[cfg(target_os = "linux")]
fn wait_for_writer_stop(
    acknowledgement: &Path,
    child: &mut Child,
    monitor: &mut Child,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    let mut monitor_completed = false;
    loop {
        if acknowledgement.is_file() {
            let process_id = child.id();
            let status = fs::read_to_string(format!("/proc/{process_id}/status"))
                .expect("read stopped child status");
            if status
                .lines()
                .find(|line| line.starts_with("State:"))
                .and_then(|line| line.split_once(':').map(|(_, state)| state.trim()))
                .is_some_and(|state| state.starts_with('T') || state.starts_with('t'))
            {
                if !monitor_completed {
                    let monitor_status = wait_for_exit(monitor, Duration::from_secs(2))
                        .expect("lock monitor exits after acknowledgement");
                    assert!(monitor_status.success());
                }
                return;
            }
        }
        if let Some(status) = child.try_wait().expect("read target process status") {
            let stderr = read_child_stderr(child);
            panic!(
                "target process completed before lock-stop acknowledgement: {status}; {}",
                String::from_utf8_lossy(&stderr)
            );
        }
        if !monitor_completed
            && let Some(status) = monitor.try_wait().expect("read lock monitor status")
        {
            if !status.success() {
                let stderr = read_child_stderr(monitor);
                panic!(
                    "lock monitor stopped before acknowledgement: {status}; {}",
                    String::from_utf8_lossy(&stderr)
                );
            }
            monitor_completed = true;
        }
        assert!(
            Instant::now() < deadline,
            "initializer did not acquire the writer lock before the deadline"
        );
        thread::yield_now();
    }
}

#[cfg(target_os = "linux")]
fn read_child_stdout(child: &mut Child) -> Vec<u8> {
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .expect("child stdout remains piped")
        .read_to_end(&mut output)
        .expect("read bounded child stdout");
    output
}

#[cfg(target_os = "linux")]
fn read_child_stderr(child: &mut Child) -> Vec<u8> {
    let mut output = Vec::new();
    child
        .stderr
        .take()
        .expect("child stderr remains piped")
        .read_to_end(&mut output)
        .expect("read bounded child stderr");
    output
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

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
#[test]
fn state_signal_at_opening_never_announces_ready() {
    let fixture = StateFixture::new();
    prepare_slow_portable_database(&fixture);
    let mut locker = spawn_portable_open_locker(&fixture);
    let arguments = portable_arguments(&fixture.database);
    #[cfg(windows)]
    prepare_signal_broker();
    let child = portable_serve_command(&arguments)
        .spawn()
        .expect("opening-phase daemon starts");
    let mut child = ChildGuard(child);
    let stderr_lines = spawn_line_receiver(child.0.stderr.take().expect("opening stderr is piped"));
    wait_for_lifecycle_phase(&stderr_lines, "state-open-pending", Duration::from_secs(5));
    #[cfg(unix)]
    signal(child.0.id(), "TERM");
    #[cfg(windows)]
    signal(child.0.id(), "BREAK");
    wait_for_lifecycle_phase(&stderr_lines, "shutdown-requested", Duration::from_secs(5));
    locker
        .0
        .kill()
        .expect("release portable opening database lock");
    locker.0.wait().expect("reap portable opening locker");
    let status = wait_for_exit(&mut child.0, Duration::from_secs(10));
    if status.is_none() {
        child
            .0
            .kill()
            .expect("terminate unbounded opening-phase shutdown");
    }
    assert!(
        status.is_some_and(|status| status.code() == Some(0)),
        "opening-phase shutdown did not exit cleanly with code 0"
    );
    let mut stdout = Vec::new();
    child
        .0
        .stdout
        .take()
        .expect("opening stdout is piped")
        .read_to_end(&mut stdout)
        .expect("read opening-phase stdout");
    assert!(
        !String::from_utf8_lossy(&stdout).contains("ready protocol="),
        "daemon announced readiness after opening-phase shutdown"
    );

    let mut probe_arguments = arguments;
    probe_arguments.insert(0, "--probe".into());
    let mut probe = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    probe.args(probe_arguments);
    let probe = bounded_output(&mut probe, Duration::from_secs(10));
    assert!(
        probe.status.success(),
        "opening-phase shutdown retained state ownership: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
}

#[cfg(any(unix, windows))]
#[test]
fn portable_serve_handles_signals_excludes_second_writer_and_releases_lock() {
    #[cfg(unix)]
    let signal_names = ["TERM", "INT"].as_slice();
    #[cfg(windows)]
    let signal_names = ["BREAK"].as_slice();
    for signal_name in signal_names {
        let fixture = StateFixture::new();
        let arguments = portable_arguments(&fixture.database);
        let child = portable_serve_command(&arguments)
            .spawn()
            .expect("state-backed daemon starts");
        let mut child = ChildGuard(child);
        let stdout = child.0.stdout.take().expect("daemon stdout is piped");
        let _stderr_lines =
            spawn_line_receiver(child.0.stderr.take().expect("daemon stderr is piped"));
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

    let fixture = StateFixture::new();
    prepare_slow_portable_database(&fixture);
    let arguments = portable_arguments(&fixture.database);
    let child = portable_serve_command(&arguments)
        .spawn()
        .expect("state-backed escalation daemon starts");
    let mut child = ChildGuard(child);
    let stdout = child.0.stdout.take().expect("daemon stdout is piped");
    let stderr_lines = spawn_line_receiver(child.0.stderr.take().expect("daemon stderr is piped"));
    let lines = read_lines_bounded(stdout, 2, Duration::from_secs(10))
        .expect("read escalation readiness and health");
    assert_eq!(lines[0], "ready protocol=1\n");
    let close_stall = PortableCloseStall::start(&fixture.database);
    #[cfg(unix)]
    let escalation_signal = "TERM";
    #[cfg(windows)]
    let escalation_signal = "BREAK";
    #[cfg(target_os = "linux")]
    deliver_consumed_signal(child.0.id(), escalation_signal, 15);
    #[cfg(not(target_os = "linux"))]
    signal(child.0.id(), escalation_signal);
    wait_for_lifecycle_phase(&stderr_lines, "shutdown-requested", Duration::from_secs(5));
    wait_for_lifecycle_phase(&stderr_lines, "state-close-pending", Duration::from_secs(5));
    assert!(
        child
            .0
            .try_wait()
            .expect("read close-stalled daemon status")
            .is_none(),
        "daemon exited while close was observably stalled"
    );
    let escalated_at = Instant::now();
    signal(child.0.id(), escalation_signal);
    let status = wait_for_exit(&mut child.0, Duration::from_secs(5));
    if status.is_none() {
        child
            .0
            .kill()
            .expect("terminate unbounded portable escalation");
    }
    assert!(
        status.is_some_and(|status| status.code() == Some(2)),
        "second portable shutdown signal did not produce exact exit code 2"
    );
    assert!(
        escalated_at.elapsed() < Duration::from_millis(450),
        "second portable shutdown signal did not exit immediately"
    );
    close_stall.release();
    let mut probe_arguments = arguments;
    probe_arguments.insert(0, "--probe".into());
    let mut probe_command = Command::new(env!("CARGO_BIN_EXE_gta-claw-daemon"));
    probe_command.args(probe_arguments);
    let probe = bounded_output(&mut probe_command, Duration::from_secs(10));
    assert!(
        probe.status.success(),
        "portable writer lock was retained after escalation: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_protected_initializer_probe_and_serve_lifecycle() {
    if std::env::var_os(ROOT_DRIVER_ENV).is_none() {
        let mut identity = Command::new("/usr/bin/id");
        identity.arg("-u");
        let identity = bounded_output(&mut identity, Duration::from_secs(5));
        if identity.stdout != b"0\n" {
            let nonce = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time follows Unix epoch")
                .as_nanos();
            let root_base = PathBuf::from(format!(
                "/var/lib/gta-claw-lp3-suite-{}-{nonce}",
                std::process::id()
            ));
            let mut command = Command::new("/usr/bin/sudo");
            command
                .arg("-n")
                .arg("/usr/bin/env")
                .arg(format!("{ROOT_DRIVER_ENV}=1"))
                .arg(format!("{}={}", ROOT_BASE_ENV, root_base.display()))
                .arg(std::env::current_exe().expect("resolve daemon lifecycle test executable"))
                .arg("--exact")
                .arg(ROOT_TEST_NAME)
                .arg("--nocapture")
                .arg("--test-threads=1");
            let output = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                bounded_output(&mut command, Duration::from_secs(120))
            }));
            let cleanup = Command::new("/usr/bin/sudo")
                .args(["-n", "/bin/rm", "-rf", "--"])
                .arg(&root_base)
                .status()
                .expect("remove bounded root fixture base");
            assert!(cleanup.success(), "root fixture base cleanup failed");
            let output = match output {
                Ok(output) => output,
                Err(panic) => std::panic::resume_unwind(panic),
            };
            assert!(
                output.status.success(),
                "LinuxProtected daemon root driver failed: status={} stdout={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
    }

    let root_base = std::env::var_os(ROOT_BASE_ENV).map(PathBuf::from);
    if let Some(root_base) = &root_base {
        fs::create_dir(root_base).expect("create root fixture base");
        chown(root_base, Some(0), Some(SERVICE_GID)).expect("assign root fixture base group");
        fs::set_permissions(root_base, fs::Permissions::from_mode(0o750))
            .expect("secure root fixture base");
    }

    {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time follows Unix epoch")
            .as_nanos();
        let outer = root_base
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib"))
            .join(format!(
                "gta-claw-lp4-provision-{}-{nonce}",
                std::process::id()
            ));
        fs::create_dir(&outer).expect("create provisioning fixture ancestor");
        chown(&outer, Some(0), Some(0)).expect("own provisioning fixture ancestor");
        fs::set_permissions(&outer, fs::Permissions::from_mode(0o755))
            .expect("secure provisioning fixture ancestor");
        let namespace = outer.join("state");
        let fixture = ProtectedFixture { outer, namespace };

        let prepared = bounded_output(
            &mut prepare_command(&fixture.namespace),
            Duration::from_secs(20),
        );
        assert!(
            prepared.status.success(),
            "fresh provision-and-initialize failed: {}",
            String::from_utf8_lossy(&prepared.stderr)
        );
        assert_eq!(prepared.stdout, b"Initialized\n");
        assert_eq!(exact_names(&fixture.namespace), expected_protected_names());
        let parent = fs::symlink_metadata(&fixture.namespace)
            .expect("inspect provisioned protected namespace");
        assert!(parent.file_type().is_dir());
        assert_eq!(parent.uid(), 0);
        assert_eq!(parent.gid(), SERVICE_GID);
        assert_eq!(parent.mode() & 0o7777, 0o750);
        for name in PROTECTED_NAMES {
            let metadata = fs::symlink_metadata(fixture.namespace.join(name))
                .unwrap_or_else(|error| panic!("inspect provisioned entry {name}: {error}"));
            assert!(metadata.file_type().is_file());
            assert_eq!(metadata.uid(), SERVICE_UID);
            assert_eq!(metadata.gid(), SERVICE_GID);
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        let identities = protected_identities(&fixture.namespace);
        let bytes = protected_bytes(&fixture.namespace);
        let repeated = bounded_output(
            &mut prepare_command(&fixture.namespace),
            Duration::from_secs(20),
        );
        assert!(
            repeated.status.success(),
            "idempotent provision-and-initialize failed: {}",
            String::from_utf8_lossy(&repeated.stderr)
        );
        assert_eq!(repeated.stdout, b"AlreadyInitialized\n");
        assert_eq!(protected_identities(&fixture.namespace), identities);
        assert_eq!(protected_bytes(&fixture.namespace), bytes);
    }

    {
        for (name, bytes, operation) in [
            ("state.sqlite", b"partial-db".as_slice(), "partial database"),
            ("state.sqlite-wal", b"partial-wal".as_slice(), "partial WAL"),
            ("snapshot.selector", b"\0".as_slice(), "partial selector"),
            (
                "snapshot-0.meta",
                b"unknown-marker".as_slice(),
                "unknown initializer marker",
            ),
        ] {
            let malformed = create_protected_fixture();
            fs::write(malformed.namespace.join(name), bytes)
                .unwrap_or_else(|error| panic!("write {operation} fixture: {error}"));
            assert_provisioner_rejected(&malformed.namespace, operation);
        }
    }

    {
        let partial = create_protected_fixture();
        for name in PROTECTED_NAMES.iter().skip(1) {
            fs::remove_file(partial.namespace.join(name))
                .unwrap_or_else(|error| panic!("remove partial fixture entry {name}: {error}"));
        }
        let before = protected_namespace_snapshot(&partial.namespace);
        let rejected = bounded_output(
            &mut prepare_command(&partial.namespace),
            Duration::from_secs(10),
        );
        assert!(
            !rejected.status.success(),
            "partial provisioned namespace unexpectedly passed"
        );
        assert!(rejected.stdout.is_empty());
        assert_eq!(protected_namespace_snapshot(&partial.namespace), before);
    }

    {
        let concurrent = create_protected_fixture_with_depth(128);
        let identities = protected_identities(&concurrent.namespace);
        let gate = concurrent.outer.join("initializers.start");
        let first = gated_initializer_command(&concurrent.namespace, &gate)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start first concurrent root initializer");
        let second = gated_initializer_command(&concurrent.namespace, &gate)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start second concurrent root initializer");
        let mut first = ChildGuard(first);
        let mut second = ChildGuard(second);
        let first_acknowledgement = concurrent.outer.join("initializer-first.locked");
        let second_acknowledgement = concurrent.outer.join("initializer-second.locked");
        let mut first_monitor = spawn_writer_lock_stop_monitor(
            &concurrent.namespace,
            first.0.id(),
            &first_acknowledgement,
        );
        let mut second_monitor = spawn_writer_lock_stop_monitor(
            &concurrent.namespace,
            second.0.id(),
            &second_acknowledgement,
        );
        File::create(&gate).expect("release concurrent initializer gate");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !first_acknowledgement.is_file() && !second_acknowledgement.is_file() {
            assert!(
                Instant::now() < deadline,
                "neither fresh initializer acquired the fixed writer lock"
            );
            assert!(
                first
                    .0
                    .try_wait()
                    .expect("read first initializer status")
                    .is_none()
                    || second
                        .0
                        .try_wait()
                        .expect("read second initializer status")
                        .is_none(),
                "both fresh initializers exited before the lock race was observed"
            );
            thread::yield_now();
        }
        let first_won = first_acknowledgement.is_file();
        assert_ne!(
            first_won,
            second_acknowledgement.is_file(),
            "exactly one fresh initializer must acquire the writer lock"
        );
        let (winner, loser, winner_monitor, loser_monitor) = if first_won {
            (
                &mut first.0,
                &mut second.0,
                &mut first_monitor.0,
                &mut second_monitor.0,
            )
        } else {
            (
                &mut second.0,
                &mut first.0,
                &mut second_monitor.0,
                &mut first_monitor.0,
            )
        };
        let winner_monitor_status = wait_for_exit(winner_monitor, Duration::from_secs(2))
            .expect("winner lock monitor exits after stopping the initializer");
        assert!(winner_monitor_status.success());
        let loser_status = wait_for_exit(loser, Duration::from_secs(10))
            .expect("fresh initializer loser is bounded");
        let loser_stdout = read_child_stdout(loser);
        let loser_stderr = read_child_stderr(loser);
        assert!(!loser_status.success());
        assert!(loser_stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&loser_stderr).contains("StoreLocked"),
            "concurrent initializer loser did not report StoreLocked: {}",
            String::from_utf8_lossy(&loser_stderr)
        );
        signal(winner.id(), "CONT");
        let winner_status =
            wait_for_exit(winner, Duration::from_secs(35)).expect("fresh winner is bounded");
        let winner_stdout = read_child_stdout(winner);
        let winner_stderr = read_child_stderr(winner);
        assert!(
            winner_status.success(),
            "fresh initializer winner failed: {}",
            String::from_utf8_lossy(&winner_stderr)
        );
        assert_eq!(winner_stdout, b"Initialized\n");
        assert_eq!(protected_identities(&concurrent.namespace), identities);
        let idempotent = bounded_output(
            &mut initializer_command(&concurrent.namespace),
            Duration::from_secs(10),
        );
        assert!(idempotent.status.success());
        assert_eq!(idempotent.stdout, b"AlreadyInitialized\n");
        let reopened = bounded_output(
            &mut protected_service_command(&concurrent.namespace, true),
            Duration::from_secs(20),
        );
        assert!(
            reopened.status.success(),
            "service could not reopen after fresh initializer race: {}",
            String::from_utf8_lossy(&reopened.stderr)
        );
        if loser_monitor
            .try_wait()
            .expect("read loser monitor status")
            .is_none()
        {
            loser_monitor
                .kill()
                .expect("terminate completed loser lock monitor");
        }
    }

    {
        let large = create_protected_fixture_with_depth(32);
        let seeded = bounded_output(
            &mut initializer_command(&large.namespace),
            Duration::from_secs(35),
        );
        assert!(seeded.status.success());
        let migrated = bounded_output(
            &mut protected_service_command(&large.namespace, true),
            Duration::from_secs(20),
        );
        assert!(
            migrated.status.success(),
            "migrate large initialized fixture through production probe: {}",
            String::from_utf8_lossy(&migrated.stderr)
        );
        install_large_initialized_database(&large);
        let identities = protected_identities(&large.namespace);
        let bytes = protected_bytes(&large.namespace);
        let unavailable_tmp = large
            .outer
            .join("offline-temporary-directory-must-not-exist");
        let mut verify = initializer_command(&large.namespace);
        verify
            .env("TMPDIR", &unavailable_tmp)
            .env("SQLITE_TMPDIR", &unavailable_tmp);
        let verify = bounded_output(&mut verify, Duration::from_secs(35));
        assert!(
            verify.status.success(),
            "large raw verification depended on temporary storage: {}",
            String::from_utf8_lossy(&verify.stderr)
        );
        assert_eq!(verify.stdout, b"AlreadyInitialized\n");
        assert!(!unavailable_tmp.exists());
        assert_eq!(protected_identities(&large.namespace), identities);
        assert_eq!(protected_bytes(&large.namespace), bytes);
    }

    {
        let slow_open = create_protected_fixture_with_depth(32);
        let initialized = bounded_output(
            &mut initializer_command(&slow_open.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        let gate = slow_open.outer.join("service.start");
        let child = gated_protected_service_command(&slow_open.namespace, &gate)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start slow-open protected daemon");
        let mut child = ChildGuard(child);
        let stderr_lines =
            spawn_line_receiver(child.0.stderr.take().expect("slow-open stderr is piped"));
        let acknowledgement = slow_open.outer.join("service.locked");
        let mut monitor =
            spawn_writer_lock_stop_monitor(&slow_open.namespace, child.0.id(), &acknowledgement);
        File::create(&gate).expect("release slow-open service gate");
        wait_for_lifecycle_phase(&stderr_lines, "state-open-pending", Duration::from_secs(5));
        wait_for_writer_stop(
            &acknowledgement,
            &mut child.0,
            &mut monitor.0,
            Duration::from_secs(10),
        );
        signal(child.0.id(), "TERM");
        signal(child.0.id(), "CONT");
        wait_for_lifecycle_phase(&stderr_lines, "shutdown-requested", Duration::from_secs(10));
        let status = wait_for_exit(&mut child.0, Duration::from_secs(10));
        if status.is_none() {
            child
                .0
                .kill()
                .expect("terminate unbounded pre-ready shutdown");
        }
        assert!(
            status.is_some_and(|status| status.success()),
            "pre-ready shutdown did not terminalize cleanly"
        );
        let stdout = read_child_stdout(&mut child.0);
        assert!(
            !String::from_utf8_lossy(&stdout).contains("ready protocol="),
            "daemon announced readiness after pre-ready shutdown"
        );
        let released = bounded_output(
            &mut protected_service_command(&slow_open.namespace, true),
            Duration::from_secs(15),
        );
        assert!(
            released.status.success(),
            "pre-ready shutdown retained the writer lock: {}",
            String::from_utf8_lossy(&released.stderr)
        );
    }

    {
        let uncheckpointed = create_protected_fixture();
        let initialized = bounded_output(
            &mut initializer_command(&uncheckpointed.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        let child = protected_service_command(&uncheckpointed.namespace, false)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start uncheckpointed protected daemon");
        let mut child = ChildGuard(child);
        let stdout = child.0.stdout.take().expect("protected stdout is piped");
        let lines = read_lines_bounded(stdout, 2, Duration::from_secs(10))
            .expect("read uncheckpointed daemon readiness");
        assert_eq!(lines[0], "ready protocol=1\n");
        let wal = uncheckpointed.namespace.join("state.sqlite-wal");
        assert!(
            fs::metadata(&wal)
                .expect("inspect live uncheckpointed WAL")
                .len()
                > 0,
            "runtime migrations must leave valid committed WAL frames"
        );
        child
            .0
            .kill()
            .expect("SIGKILL uncheckpointed daemon fixture");
        let status = child.0.wait().expect("reap uncheckpointed daemon");
        assert_eq!(status.signal(), Some(9));
        let bytes_before = protected_bytes(&uncheckpointed.namespace);
        let identities_before = protected_identities(&uncheckpointed.namespace);
        assert!(
            !fs::read(&wal)
                .expect("read uncheckpointed WAL evidence")
                .is_empty()
        );
        let verified = bounded_output(
            &mut initializer_command(&uncheckpointed.namespace),
            Duration::from_secs(10),
        );
        assert!(verified.status.success());
        assert_eq!(verified.stdout, b"AlreadyInitialized\n");
        assert_eq!(protected_bytes(&uncheckpointed.namespace), bytes_before);
        assert_eq!(
            protected_identities(&uncheckpointed.namespace),
            identities_before
        );
        let recovered = bounded_output(
            &mut protected_service_command(&uncheckpointed.namespace, true),
            Duration::from_secs(15),
        );
        assert!(
            recovered.status.success(),
            "service failed to recover verified uncheckpointed WAL: {}",
            String::from_utf8_lossy(&recovered.stderr)
        );
    }

    {
        let header_only = create_protected_fixture();
        let initialized = bounded_output(
            &mut initializer_command(&header_only.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        let child = protected_service_command(&header_only.namespace, false)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start header-only WAL fixture daemon");
        let mut child = ChildGuard(child);
        let stdout = child.0.stdout.take().expect("protected stdout is piped");
        read_lines_bounded(stdout, 2, Duration::from_secs(10))
            .expect("read header-only fixture readiness");
        child
            .0
            .kill()
            .expect("SIGKILL header-only WAL fixture daemon");
        let status = child.0.wait().expect("reap header-only WAL daemon");
        assert_eq!(status.signal(), Some(9));
        let wal = header_only.namespace.join("state.sqlite-wal");
        let wal_bytes = fs::read(&wal).expect("read complete WAL before header-only fixture");
        assert!(wal_bytes.len() > 32);
        fs::write(&wal, &wal_bytes[..32]).expect("retain valid WAL header without frames");
        let bytes_before = protected_bytes(&header_only.namespace);
        let verified = bounded_output(
            &mut initializer_command(&header_only.namespace),
            Duration::from_secs(10),
        );
        assert!(verified.status.success());
        assert_eq!(verified.stdout, b"AlreadyInitialized\n");
        assert_eq!(protected_bytes(&header_only.namespace), bytes_before);
        let mut partial_frame = wal_bytes[..32].to_vec();
        partial_frame.extend_from_slice(&wal_bytes[32..39]);
        fs::write(&wal, &partial_frame).expect("retain incomplete trailing WAL frame");
        let partial_before = protected_bytes(&header_only.namespace);
        let partial_verified = bounded_output(
            &mut initializer_command(&header_only.namespace),
            Duration::from_secs(10),
        );
        assert!(
            partial_verified.status.success(),
            "raw verifier rejected a recoverable incomplete WAL tail: {}",
            String::from_utf8_lossy(&partial_verified.stderr)
        );
        assert_eq!(partial_verified.stdout, b"AlreadyInitialized\n");
        assert_eq!(protected_bytes(&header_only.namespace), partial_before);
        let mut corrupt_header = partial_frame.clone();
        corrupt_header[24] ^= 0x80;
        fs::write(&wal, &corrupt_header).expect("corrupt complete WAL header checksum");
        assert_initializer_rejected(
            &header_only.namespace,
            "complete WAL header checksum corruption",
        );
        fs::write(&wal, partial_frame).expect("restore recoverable incomplete WAL tail");
        let reopened = bounded_output(
            &mut protected_service_command(&header_only.namespace, true),
            Duration::from_secs(15),
        );
        assert!(
            reopened.status.success(),
            "service rejected valid header-only WAL: {}",
            String::from_utf8_lossy(&reopened.stderr)
        );
    }

    {
        let rewind = create_protected_fixture();
        let seeded = bounded_output(
            &mut initializer_command(&rewind.namespace),
            Duration::from_secs(35),
        );
        assert!(seeded.status.success());
        let migrated = bounded_output(
            &mut protected_service_command(&rewind.namespace, true),
            Duration::from_secs(15),
        );
        assert!(migrated.status.success());
        install_uncommitted_rewind_database(&rewind);
        let bytes_before = protected_bytes(&rewind.namespace);
        let identities_before = protected_identities(&rewind.namespace);
        let verified = bounded_output(
            &mut initializer_command(&rewind.namespace),
            Duration::from_secs(10),
        );
        assert!(
            verified.status.success(),
            "raw verifier rejected SQLite rewind without a new commit: {}",
            String::from_utf8_lossy(&verified.stderr)
        );
        assert_eq!(verified.stdout, b"AlreadyInitialized\n");
        assert_eq!(protected_bytes(&rewind.namespace), bytes_before);
        assert_eq!(protected_identities(&rewind.namespace), identities_before);
        let recovered = bounded_output(
            &mut protected_service_command(&rewind.namespace, true),
            Duration::from_secs(15),
        );
        assert!(
            recovered.status.success(),
            "service failed to recover uncommitted rewind WAL: {}",
            String::from_utf8_lossy(&recovered.stderr)
        );
    }

    {
        let zero_count = create_protected_fixture();
        let seeded = bounded_output(
            &mut initializer_command(&zero_count.namespace),
            Duration::from_secs(35),
        );
        assert!(seeded.status.success());
        let database = zero_count.namespace.join("state.sqlite");
        let mut bytes = fs::read(&database).expect("read zero-count fixture");
        bytes[28..32].fill(0);
        fs::write(&database, bytes).expect("set valid zero SQLite page count");
        let before = protected_bytes(&zero_count.namespace);
        let verified = bounded_output(
            &mut initializer_command(&zero_count.namespace),
            Duration::from_secs(10),
        );
        assert!(verified.status.success());
        assert_eq!(verified.stdout, b"AlreadyInitialized\n");
        assert_eq!(protected_bytes(&zero_count.namespace), before);
        let opened = bounded_output(
            &mut protected_service_command(&zero_count.namespace, true),
            Duration::from_secs(15),
        );
        assert!(
            opened.status.success(),
            "SQLite rejected zero page-count fallback: {}",
            String::from_utf8_lossy(&opened.stderr)
        );
    }

    {
        let mismatched_count = create_protected_fixture();
        let seeded = bounded_output(
            &mut initializer_command(&mismatched_count.namespace),
            Duration::from_secs(35),
        );
        assert!(seeded.status.success());
        let migrated = bounded_output(
            &mut protected_service_command(&mismatched_count.namespace, true),
            Duration::from_secs(15),
        );
        assert!(migrated.status.success());
        let database = mismatched_count.namespace.join("state.sqlite");
        let mut bytes = fs::read(&database).expect("read version-valid fixture");
        assert!(bytes.len() > 4096);
        bytes[28..32].copy_from_slice(&1_u32.to_be_bytes());
        let change_counter = u32::from_be_bytes(
            bytes[24..28]
                .try_into()
                .expect("SQLite change counter is in bounds"),
        );
        bytes[92..96].copy_from_slice(&change_counter.wrapping_add(1).to_be_bytes());
        fs::write(&database, bytes).expect("set mismatched version-valid-for fixture");
        let before = protected_bytes(&mismatched_count.namespace);
        let verified = bounded_output(
            &mut initializer_command(&mismatched_count.namespace),
            Duration::from_secs(10),
        );
        assert!(verified.status.success());
        assert_eq!(verified.stdout, b"AlreadyInitialized\n");
        assert_eq!(protected_bytes(&mismatched_count.namespace), before);
        let opened = bounded_output(
            &mut protected_service_command(&mismatched_count.namespace, true),
            Duration::from_secs(15),
        );
        assert!(
            opened.status.success(),
            "SQLite rejected version-valid-for fallback: {}",
            String::from_utf8_lossy(&opened.stderr)
        );
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
    let initialized_bytes = protected_bytes(&fixture.namespace);
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
    assert_eq!(protected_bytes(&fixture.namespace), initialized_bytes);
    assert_eq!(protected_identities(&fixture.namespace), identities);
    let mut no_tmp = initializer_command(&fixture.namespace);
    let unavailable_tmp = fixture
        .outer
        .join("offline-temporary-directory-must-not-exist");
    no_tmp
        .env("TMPDIR", &unavailable_tmp)
        .env("SQLITE_TMPDIR", &unavailable_tmp);
    let no_tmp = bounded_output(&mut no_tmp, Duration::from_secs(10));
    assert!(
        no_tmp.status.success(),
        "initialized raw verification depended on TMPDIR: {}",
        String::from_utf8_lossy(&no_tmp.stderr)
    );
    assert_eq!(no_tmp.stdout, b"AlreadyInitialized\n");
    assert!(!unavailable_tmp.exists());
    assert_eq!(protected_bytes(&fixture.namespace), initialized_bytes);
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
    let migrated_entries_before = protected_bytes(&fixture.namespace);
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
    assert_eq!(protected_bytes(&fixture.namespace), migrated_entries_before);
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

        if signal_name == "TERM" {
            let namespace_before = protected_namespace_snapshot(&fixture.namespace);
            let provision = bounded_output(
                &mut provision_command(&fixture.namespace),
                Duration::from_secs(10),
            );
            assert!(!provision.status.success());
            assert!(provision.stdout.is_empty());
            assert!(
                String::from_utf8_lossy(&provision.stderr).contains("StoreLocked"),
                "live-service provisioner did not report StoreLocked: {}",
                String::from_utf8_lossy(&provision.stderr)
            );
            assert_eq!(
                protected_namespace_snapshot(&fixture.namespace),
                namespace_before
            );
            let initializer = bounded_output(
                &mut initializer_command(&fixture.namespace),
                Duration::from_secs(10),
            );
            assert!(!initializer.status.success());
            assert!(initializer.stdout.is_empty());
            assert!(
                String::from_utf8_lossy(&initializer.stderr).contains("StoreLocked"),
                "live-service initializer did not report StoreLocked: {}",
                String::from_utf8_lossy(&initializer.stderr)
            );
            assert_eq!(
                protected_namespace_snapshot(&fixture.namespace),
                namespace_before
            );
            assert!(
                child
                    .0
                    .try_wait()
                    .expect("read live daemon status")
                    .is_none(),
                "initializer contention stopped the live daemon"
            );
        }

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

    {
        let escalated = create_protected_fixture_with_depth(32);
        let initialized = bounded_output(
            &mut initializer_command(&escalated.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        let child = protected_service_command(&escalated.namespace, false)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start protected daemon for second-signal escalation");
        let mut child = ChildGuard(child);
        let stdout = child.0.stdout.take().expect("protected stdout is piped");
        let stderr_lines =
            spawn_line_receiver(child.0.stderr.take().expect("protected stderr is piped"));
        let lines = read_lines_bounded(stdout, 2, Duration::from_secs(10))
            .expect("read protected readiness before escalation");
        assert_eq!(lines[0], "ready protocol=1\n");
        signal(child.0.id(), "STOP");
        wait_for_process_fact(
            || process_is_stopped(child.0.id()),
            Duration::from_secs(2),
            "protected daemon did not stop before distinct queued signals",
        );
        signal(child.0.id(), "TERM");
        wait_for_process_fact(
            || process_has_pending_signal(child.0.id(), 15),
            Duration::from_secs(2),
            "SIGTERM was not observably pending",
        );
        signal(child.0.id(), "INT");
        wait_for_process_fact(
            || process_has_pending_signal(child.0.id(), 2),
            Duration::from_secs(2),
            "SIGINT was not observably pending",
        );
        let escalated_at = Instant::now();
        signal(child.0.id(), "CONT");
        wait_for_lifecycle_phase(&stderr_lines, "shutdown-requested", Duration::from_secs(5));
        let status = wait_for_exit(&mut child.0, Duration::from_secs(5));
        if status.is_none() {
            child
                .0
                .kill()
                .expect("terminate unbounded escalated shutdown");
        }
        let status = status.expect("escalated shutdown is bounded");
        assert_eq!(status.code(), Some(2));
        assert!(escalated_at.elapsed() < Duration::from_millis(450));
        let released = bounded_output(
            &mut protected_service_command(&escalated.namespace, true),
            Duration::from_secs(15),
        );
        assert!(
            released.status.success(),
            "escalated shutdown retained the writer lock: {}",
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
        let truncated = create_protected_fixture();
        let initialized = bounded_output(
            &mut initializer_command(&truncated.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        let database = truncated.namespace.join("state.sqlite");
        let bytes = fs::read(&database).expect("read initialized truncation fixture");
        fs::write(&database, &bytes[..100]).expect("truncate database to one header");
        let before = protected_bytes(&truncated.namespace);
        assert_initializer_rejected(&truncated.namespace, "truncated page-one namespace");
        assert_eq!(protected_bytes(&truncated.namespace), before);
    }
    {
        let whole_page_truncated = create_protected_fixture();
        let initialized = bounded_output(
            &mut initializer_command(&whole_page_truncated.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        let migrated = bounded_output(
            &mut protected_service_command(&whole_page_truncated.namespace, true),
            Duration::from_secs(15),
        );
        assert!(migrated.status.success());
        let database = whole_page_truncated.namespace.join("state.sqlite");
        let bytes = fs::read(&database).expect("read migrated truncation fixture");
        let encoded_page_size = u16::from_be_bytes([bytes[16], bytes[17]]);
        let page_size = if encoded_page_size == 1 {
            65_536
        } else {
            usize::from(encoded_page_size)
        };
        assert!(bytes.len() > page_size);
        fs::write(&database, &bytes[..page_size])
            .expect("truncate migrated database to one complete page");
        let before = protected_bytes(&whole_page_truncated.namespace);
        assert_initializer_rejected(
            &whole_page_truncated.namespace,
            "whole-page truncated namespace",
        );
        assert_eq!(protected_bytes(&whole_page_truncated.namespace), before);
    }
    {
        let corrupt_page = create_protected_fixture();
        let initialized = bounded_output(
            &mut initializer_command(&corrupt_page.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        let migrated = bounded_output(
            &mut protected_service_command(&corrupt_page.namespace, true),
            Duration::from_secs(15),
        );
        assert!(migrated.status.success());
        let database = corrupt_page.namespace.join("state.sqlite");
        let mut bytes = fs::read(&database).expect("read page-corruption fixture");
        let encoded_page_size = u16::from_be_bytes([bytes[16], bytes[17]]);
        let page_size = if encoded_page_size == 1 {
            65_536
        } else {
            usize::from(encoded_page_size)
        };
        assert!(bytes.len() > page_size);
        bytes[page_size] = 0xff;
        fs::write(&database, bytes).expect("corrupt non-root SQLite page");
        let before = protected_bytes(&corrupt_page.namespace);
        assert_initializer_rejected(&corrupt_page.namespace, "corrupt non-root page namespace");
        assert_eq!(protected_bytes(&corrupt_page.namespace), before);
    }
    for object in ["sessions", "sessions_creation_order"] {
        let ordering = create_protected_fixture();
        let initialized = bounded_output(
            &mut initializer_command(&ordering.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        let migrated = bounded_output(
            &mut protected_service_command(&ordering.namespace, true),
            Duration::from_secs(15),
        );
        assert!(migrated.status.success());
        install_out_of_order_btree(&ordering, object);
        assert_initializer_rejected(
            &ordering.namespace,
            if object == "sessions" {
                "out-of-order table b-tree"
            } else {
                "out-of-order index b-tree"
            },
        );
    }
    {
        let index_mismatch = create_protected_fixture();
        let initialized = bounded_output(
            &mut initializer_command(&index_mismatch.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        let migrated = bounded_output(
            &mut protected_service_command(&index_mismatch.namespace, true),
            Duration::from_secs(15),
        );
        assert!(migrated.status.success());
        install_table_index_mismatch(&index_mismatch);
        assert_initializer_rejected(
            &index_mismatch.namespace,
            "table value without matching index entry",
        );
    }
    {
        let noncanonical_id = create_protected_fixture();
        let initialized = bounded_output(
            &mut initializer_command(&noncanonical_id.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        let migrated = bounded_output(
            &mut protected_service_command(&noncanonical_id.namespace, true),
            Duration::from_secs(15),
        );
        assert!(migrated.status.success());
        install_noncanonical_identifier(&noncanonical_id);
        assert_initializer_rejected(
            &noncanonical_id.namespace,
            "noncanonical persisted identifier",
        );
    }
    {
        let malformed_schema = create_protected_fixture();
        let initialized = bounded_output(
            &mut initializer_command(&malformed_schema.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        let migrated = bounded_output(
            &mut protected_service_command(&malformed_schema.namespace, true),
            Duration::from_secs(15),
        );
        assert!(migrated.status.success());
        let database = malformed_schema.namespace.join("state.sqlite");
        let mut bytes = fs::read(&database).expect("read schema-coherence fixture");
        let needle = b"CREATE TABLE sessions";
        let offset = bytes
            .windows(needle.len())
            .position(|candidate| candidate == needle)
            .expect("canonical sessions SQL is stored in sqlite_schema");
        bytes[offset] = b'X';
        fs::write(&database, bytes).expect("corrupt sqlite_schema SQL");
        OpenOptions::new()
            .write(true)
            .open(malformed_schema.namespace.join("state.sqlite-wal"))
            .expect("open held WAL for schema fixture")
            .set_len(0)
            .expect("clear stale WAL bytes for schema fixture");
        assert_initializer_rejected(&malformed_schema.namespace, "incoherent sqlite_schema SQL");
    }
    {
        let torn_wal = create_protected_fixture();
        let initialized = bounded_output(
            &mut initializer_command(&torn_wal.namespace),
            Duration::from_secs(35),
        );
        assert!(initialized.status.success());
        fs::write(torn_wal.namespace.join("state.sqlite-wal"), b"bad WAL")
            .expect("write torn WAL header fixture");
        let before = protected_namespace_snapshot(&torn_wal.namespace);
        let verified = bounded_output(
            &mut initializer_command(&torn_wal.namespace),
            Duration::from_secs(10),
        );
        assert!(
            verified.status.success(),
            "raw verifier rejected SQLite's recoverable torn WAL header: {}",
            String::from_utf8_lossy(&verified.stderr)
        );
        assert_eq!(verified.stdout, b"AlreadyInitialized\n");
        assert_eq!(protected_namespace_snapshot(&torn_wal.namespace), before);
        let recovered = bounded_output(
            &mut protected_service_command(&torn_wal.namespace, true),
            Duration::from_secs(15),
        );
        assert!(
            recovered.status.success(),
            "service did not recover SQLite's torn WAL header: {}",
            String::from_utf8_lossy(&recovered.stderr)
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
        let wrong_type = create_protected_fixture();
        let path = wrong_type.namespace.join("snapshot-1.sqlite");
        fs::remove_file(&path).expect("remove wrong-type target entry");
        fs::create_dir(&path).expect("install directory at protected file name");
        assert_initializer_rejected(&wrong_type.namespace, "wrong-type namespace");
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
    drop(fixture);
    if let Some(root_base) = root_base {
        fs::remove_dir(root_base).expect("remove empty root fixture base");
    }
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

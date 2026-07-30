//! Crash, failure and interleaving coverage for the updater's durable swap.
//!
//! Each case here runs the real updater in a child process, because the states
//! it has to survive only exist *inside* one library call: a journal that is
//! durable before the target moves, a target slot a crashed run already owned,
//! a staging directory another run is holding. The child is stopped or failed
//! at that exact point and the parent then inspects the filesystem the child
//! left behind, or runs a second child over it.
//!
//! Every case needs the updater to actually perform a swap, so the whole file
//! is compiled out where it refuses to: see `windows_fail_closed.rs` for the
//! contract that holds there instead.
#![cfg(not(windows))]

use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use gta_claw_updater::{
    ArtifactKind, InstallMode, InstallTarget, ReleaseArtifact, ReleaseManifest, SignedManifest,
    UpdateDecision, Updater,
};
use semver::Version;
use sha2::{Digest as _, Sha256};
use url::Url;

const FIXTURE: &str = env!("CARGO_BIN_EXE_gta-claw-updater-fixture");
const INJECTED_FAULT_EXIT_CODE: i32 = 91;
const TARGET_TRIPLE: &str = "x86_64-fixture-target";
const CURRENT_VERSION: &str = "1.0.0";
const RELEASE_VERSION: &str = "2.0.0";
const RELEASE_SEQUENCE: u64 = 7;
const WAIT_BUDGET: Duration = Duration::from_mins(1);

static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(1);

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "gta-claw-updater-durable-{label}-{}-{sequence}",
            std::process::id()
        ));
        if path.exists() {
            std::fs::remove_dir_all(&path).expect("remove stale test directory");
        }
        std::fs::create_dir(&path).expect("create isolated test directory");
        #[cfg(unix)]
        let path = std::fs::canonicalize(path).expect("resolve system temporary directory aliases");
        Self { path }
    }

    fn state(&self) -> PathBuf {
        self.path.join("updater-state")
    }

    fn target(&self) -> PathBuf {
        self.path.join("gta-claw")
    }

    fn stage(&self) -> PathBuf {
        self.path.join(".gta-claw.gta-claw-stage")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[derive(Default)]
struct ServerCounts {
    artifact_requests: usize,
    released: bool,
}

struct ServerState {
    manifest: Vec<u8>,
    artifact: Vec<u8>,
    stall_after: Option<usize>,
    counts: Mutex<ServerCounts>,
    changed: Condvar,
}

/// A loopback release server whose first artifact response can be held open.
///
/// Holding one response open is what puts a child process inside `download`
/// for as long as the test needs, which is how the staging lock is observed
/// without depending on timing.
struct ArtifactServer {
    address: SocketAddr,
    state: Arc<ServerState>,
}

impl ArtifactServer {
    fn spawn(
        listener: TcpListener,
        address: SocketAddr,
        manifest: Vec<u8>,
        artifact: Vec<u8>,
        stall_after: Option<usize>,
    ) -> Self {
        let state = Arc::new(ServerState {
            manifest,
            artifact,
            stall_after,
            counts: Mutex::new(ServerCounts::default()),
            changed: Condvar::new(),
        });
        let accept_state = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else {
                    return;
                };
                let state = Arc::clone(&accept_state);
                std::thread::spawn(move || serve(&stream, &state));
            }
        });
        Self { address, state }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}/{path}", self.address)
    }

    fn artifact_requests(&self) -> usize {
        self.state
            .counts
            .lock()
            .expect("server counts")
            .artifact_requests
    }

    fn wait_for_artifact_request(&self) {
        let (guard, timeout) = self
            .state
            .changed
            .wait_timeout_while(
                self.state.counts.lock().expect("server counts"),
                WAIT_BUDGET,
                |counts| counts.artifact_requests == 0,
            )
            .expect("server counts");
        drop(guard);
        assert!(!timeout.timed_out(), "the artifact was never requested");
    }

    fn release(&self) {
        self.state.counts.lock().expect("server counts").released = true;
        self.state.changed.notify_all();
    }
}

fn serve(stream: &TcpStream, state: &ServerState) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone request stream"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let mut range_offset = 0_u64;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() || header == "\r\n" || header.is_empty() {
            break;
        }
        if let Some(value) = header.to_ascii_lowercase().strip_prefix("range: bytes=") {
            range_offset = value
                .trim()
                .trim_end_matches('-')
                .parse()
                .expect("test range header offset");
        }
    }
    let path = request_line
        .split_ascii_whitespace()
        .nth(1)
        .expect("request path")
        .to_owned();

    let mut writer = stream.try_clone().expect("clone response stream");
    if path.starts_with("/manifest") {
        write_response(&mut writer, "200 OK", None, &state.manifest, state, false);
        return;
    }

    let index = {
        let mut counts = state.counts.lock().expect("server counts");
        counts.artifact_requests += 1;
        state.changed.notify_all();
        counts.artifact_requests
    };
    let offset = usize::try_from(range_offset).expect("small test offset");
    let total = state.artifact.len();
    let (status, content_range) = if offset == 0 {
        ("200 OK", None)
    } else {
        (
            "206 Partial Content",
            Some(format!("bytes {offset}-{}/{total}", total - 1)),
        )
    };
    let stall = index == 1 && state.stall_after.is_some();
    write_response(
        &mut writer,
        status,
        content_range,
        &state.artifact[offset..],
        state,
        stall,
    );
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_range: Option<String>,
    body: &[u8],
    state: &ServerState,
    stall: bool,
) {
    let mut head = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(content_range) = content_range {
        write!(head, "Content-Range: {content_range}\r\n").expect("format into String");
    }
    head.push_str("\r\n");
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    if stall {
        let prefix = state.stall_after.unwrap_or(0).min(body.len());
        if stream.write_all(&body[..prefix]).is_err() || stream.flush().is_err() {
            return;
        }
        let (guard, timeout) = state
            .changed
            .wait_timeout_while(
                state.counts.lock().expect("server counts"),
                WAIT_BUDGET,
                |counts| !counts.released,
            )
            .expect("server counts");
        drop(guard);
        assert!(
            !timeout.timed_out(),
            "the stalled response was never released"
        );
        let _ = stream.write_all(&body[prefix..]);
    } else {
        let _ = stream.write_all(body);
    }
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
    let mut drain = Vec::new();
    let _ = stream.read_to_end(&mut drain);
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[37_u8; 32])
}

fn public_key_hex() -> String {
    encode_hex(&signing_key().verifying_key().to_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("format into String");
    }
    encoded
}

fn signed_manifest(artifact_url: &str, artifact: &[u8]) -> Vec<u8> {
    let manifest = ReleaseManifest {
        version: RELEASE_VERSION.to_owned(),
        sequence: RELEASE_SEQUENCE,
        published_at_unix: 1_700_000_000,
        expires_at_unix: 4_102_444_800,
        revoked_versions: Vec::new(),
        artifacts: vec![ReleaseArtifact {
            release_sequence: RELEASE_SEQUENCE,
            target: TARGET_TRIPLE.to_owned(),
            url: artifact_url.to_owned(),
            sha256: sha256_hex(artifact),
            size: u64::try_from(artifact.len()).expect("small test artifact"),
            kind: ArtifactKind::Executable,
        }],
    };
    let canonical = serde_json::to_vec(&manifest).expect("canonical test manifest");
    let signature = signing_key().sign(&canonical);
    serde_json::to_vec(&SignedManifest {
        manifest,
        signature: STANDARD.encode(signature.to_bytes()),
    })
    .expect("signed test envelope")
}

/// A release server plus the artifact bytes it serves.
struct Release {
    server: ArtifactServer,
    bytes: Vec<u8>,
}

impl Release {
    fn spawn(stall_after: Option<usize>) -> Self {
        Self::with_bytes(b"verified replacement executable".to_vec(), stall_after)
    }

    fn with_bytes(bytes: Vec<u8>, stall_after: Option<usize>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback release server");
        let address = listener.local_addr().expect("loopback address");
        let manifest = signed_manifest(&format!("http://{address}/artifact"), &bytes);
        let server = ArtifactServer::spawn(listener, address, manifest, bytes.clone(), stall_after);
        Self { server, bytes }
    }
}

fn fixture(mode: &str, directory: &TestDir, release: &Release) -> Command {
    let mut command = Command::new(FIXTURE);
    command
        .arg(mode)
        .arg("--state")
        .arg(directory.state())
        .arg("--target")
        .arg(directory.target())
        .arg("--manifest")
        .arg(release.server.url("manifest.json"))
        .arg("--current")
        .arg(CURRENT_VERSION)
        .arg("--public-key")
        .arg(public_key_hex());
    command
}

fn run(command: &mut Command) -> Output {
    command.output().expect("run the updater fixture")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("fixture output is UTF-8")
}

fn wait_until(description: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT_BUDGET;
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {description}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn journal(directory: &TestDir) -> PathBuf {
    directory.stage().join("swap-journal.json")
}

fn durable_marker(directory: &TestDir) -> PathBuf {
    directory.state().join(".gta-claw-durable")
}

fn rollback_object(directory: &TestDir) -> PathBuf {
    directory.path.join(".gta-claw.gta-claw.rollback")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn a_crash_before_the_swap_keeps_the_previous_installation() {
    let directory = TestDir::new("pre-swap-crash");
    let release = Release::spawn(None);
    std::fs::write(directory.target(), b"previous install").expect("write previous install");

    let crashed = run(fixture("install", &directory, &release)
        .arg("--fault")
        .arg("exit-after-swap-prepared"));

    assert_eq!(
        crashed.status.code(),
        Some(INJECTED_FAULT_EXIT_CODE),
        "the child must stop at the armed fault: {}",
        stdout(&crashed)
    );
    assert!(
        journal(&directory).exists(),
        "the swap journal must be durable before the target moves"
    );
    assert!(
        !rollback_object(&directory).exists(),
        "nothing may be moved aside before the journal is durable"
    );
    assert_eq!(read(&directory.target()), b"previous install");

    // Recovery alone must leave the installation it found in place: this is the
    // run that used to delete an intact old install because the journal could
    // not say that nothing had moved yet.
    let recovered = run(&mut fixture("download", &directory, &release));

    assert!(
        recovered.status.success(),
        "recovery must not fail on a journal written before the swap: {}",
        stdout(&recovered)
    );
    assert_eq!(
        read(&directory.target()),
        b"previous install",
        "a crash before the swap must not cost the previous installation"
    );
    assert!(!journal(&directory).exists());

    let installed = run(&mut fixture("install", &directory, &release));

    assert!(
        installed.status.success(),
        "the interrupted update must still be installable: {}",
        stdout(&installed)
    );
    assert_eq!(read(&directory.target()), release.bytes);
    assert!(!journal(&directory).exists());
    assert!(!rollback_object(&directory).exists());
}

#[test]
fn a_stale_fresh_install_journal_never_deletes_an_independent_reinstall() {
    let directory = TestDir::new("stale-fresh-journal");
    let release = Release::spawn(None);

    let crashed = run(fixture("install", &directory, &release)
        .arg("--fault")
        .arg("exit-after-swap-committed"));

    assert_eq!(
        crashed.status.code(),
        Some(INJECTED_FAULT_EXIT_CODE),
        "the child must stop at the armed fault: {}",
        stdout(&crashed)
    );
    assert!(journal(&directory).exists());
    assert!(
        !directory.target().exists(),
        "a fresh install has nothing at the target yet"
    );

    std::fs::write(directory.target(), b"independent reinstall")
        .expect("write independent reinstall");
    let conflicted = run(&mut fixture("install", &directory, &release));

    assert!(
        stdout(&conflicted).contains("interrupted update conflicts with an unknown local object"),
        "a stale fresh-install journal must not claim an unknown target: {}",
        stdout(&conflicted)
    );
    assert_eq!(read(&directory.target()), b"independent reinstall");
}

#[test]
fn a_parent_sync_failure_after_the_swap_restores_the_target() {
    let directory = TestDir::new("parent-sync-failure");
    let release = Release::spawn(None);
    std::fs::write(directory.target(), b"previous install").expect("write previous install");

    let rolled_back = run(fixture("install", &directory, &release)
        .arg("--fault")
        .arg("fail-parent-sync-after-swap"));

    assert!(
        stdout(&rolled_back).contains("update installation failed; previous version was restored"),
        "a failed parent sync must roll the target back: {}",
        stdout(&rolled_back)
    );
    assert_eq!(
        read(&directory.target()),
        b"previous install",
        "the install must never return with the target missing"
    );
    assert!(!rollback_object(&directory).exists());
    assert!(!journal(&directory).exists());
}

#[test]
fn concurrent_downloads_serialize_on_the_staging_lock() {
    let directory = TestDir::new("concurrent-download");
    let release = Release::with_bytes(vec![0x5a_u8; 4096], Some(16));
    let marker = directory.path.join("second-run-started");

    let mut holder = fixture("download", &directory, &release)
        .spawn()
        .expect("spawn the holding download");
    release.server.wait_for_artifact_request();

    let mut waiter = fixture("download", &directory, &release)
        .arg("--marker")
        .arg(&marker)
        .spawn()
        .expect("spawn the waiting download");
    wait_until("the second run to enter download", || marker.exists());

    release.server.release();
    let holder = holder.wait().expect("holding download exits");
    let waiter = waiter.wait().expect("waiting download exits");

    assert!(holder.success(), "the holding download must succeed");
    assert!(waiter.success(), "the waiting download must succeed");
    assert_eq!(
        release.server.artifact_requests(),
        1,
        "a second run must wait for the staging lock and reuse the verified artifact"
    );
    assert_eq!(
        read(&directory.stage().join("artifact.verified")),
        release.bytes
    );
}

#[cfg(unix)]
#[test]
fn an_unconfirmed_state_tree_is_confirmed_again_on_the_next_run() {
    let directory = TestDir::new("state-first-use");
    let release = Release::spawn(None);

    let failed = run(fixture("check", &directory, &release)
        .arg("--fault")
        .arg("fail-new-state-directory-sync@last-state-level"));

    assert!(
        stdout(&failed).contains("update filesystem operation failed"),
        "an unconfirmed state tree must not be reported as usable: {}",
        stdout(&failed)
    );
    assert!(
        directory.state().is_dir(),
        "the levels are created before any of them is confirmed"
    );
    assert!(
        !durable_marker(&directory).exists(),
        "a tree with a failed sync must not be recorded as confirmed"
    );

    // The directories are deliberately left in place: after a crash they look
    // exactly like confirmed ones, so the guarantee has to come from the
    // missing marker. A second run must therefore confirm again — and fail the
    // same way while the sync keeps failing.
    let repeated = run(fixture("check", &directory, &release)
        .arg("--fault")
        .arg("fail-new-state-directory-sync@last-state-level"));

    assert!(
        stdout(&repeated).contains("update filesystem operation failed"),
        "an existing but unconfirmed state tree must be confirmed again, not skipped: {}",
        stdout(&repeated)
    );

    let accepted = run(&mut fixture("check", &directory, &release));

    assert!(
        accepted.status.success(),
        "first use must succeed once the parents can be synced: {}",
        stdout(&accepted)
    );
    assert!(
        durable_marker(&directory).is_file(),
        "a confirmed tree records the fact durably"
    );
    let target_state = std::fs::read_dir(directory.state())
        .expect("read protected state root")
        .map(|entry| entry.expect("state entry").path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("target-"))
        })
        .expect("per-target state directory");
    assert!(
        std::fs::read_dir(target_state)
            .expect("read per-target state")
            .any(|entry| {
                entry
                    .expect("floor entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with("release-floor-")
            }),
        "the accepted anti-rollback floor must be on disk"
    );
}

#[test]
fn install_refuses_a_destination_the_artifact_was_not_verified_for() {
    let directory = TestDir::new("redirected-install");
    let release = Release::spawn(None);
    let redirected = directory.path.join("other-install");
    std::fs::write(&redirected, b"other install").expect("write other install");

    let rejected = run(fixture("install", &directory, &release)
        .arg("--install-target")
        .arg(&redirected));

    assert!(
        stdout(&rejected).contains("verified artifact belongs to a different install target"),
        "a redirected destination must be rejected: {}",
        stdout(&rejected)
    );
    assert_eq!(read(&redirected), b"other install");
    assert!(
        !directory.target().exists(),
        "the rejected install must not touch the verified destination either"
    );
}

#[test]
fn a_crash_between_the_move_aside_and_the_committed_phase_restores_the_original() {
    let directory = TestDir::new("moved-aside-crash");
    let release = Release::spawn(None);
    std::fs::write(directory.target(), b"previous install").expect("write previous install");

    let crashed = run(fixture("install", &directory, &release)
        .arg("--fault")
        .arg("exit-after-target-moved-aside"));

    assert_eq!(
        crashed.status.code(),
        Some(INJECTED_FAULT_EXIT_CODE),
        "the child must stop at the armed fault: {}",
        stdout(&crashed)
    );
    assert!(
        !directory.target().exists(),
        "the target is moved aside at this point"
    );
    assert_eq!(
        read(&rollback_object(&directory)),
        b"previous install",
        "the installation this run measured must be in the rollback object"
    );
    assert!(journal(&directory).exists());

    // The move aside was made durable before the journal claimed it, so
    // recovery has an intact original to put back.
    let recovered = run(&mut fixture("download", &directory, &release));

    assert!(
        recovered.status.success(),
        "recovery must restore the moved-aside installation: {}",
        stdout(&recovered)
    );
    assert_eq!(read(&directory.target()), b"previous install");
    assert!(!rollback_object(&directory).exists());
    assert!(!journal(&directory).exists());
}

#[test]
fn a_crash_between_a_restore_and_its_journal_removal_is_recoverable() {
    let directory = TestDir::new("restore-crash");
    let release = Release::spawn(None);
    std::fs::write(directory.target(), b"previous install").expect("write previous install");

    let moved_aside = run(fixture("install", &directory, &release)
        .arg("--fault")
        .arg("exit-after-target-moved-aside"));
    assert_eq!(moved_aside.status.code(), Some(INJECTED_FAULT_EXIT_CODE));

    // Recovery restores the original and makes it durable, then stops before
    // the journal is removed.
    let restored = run(fixture("download", &directory, &release)
        .arg("--fault")
        .arg("exit-after-recovery-restore"));

    assert_eq!(
        restored.status.code(),
        Some(INJECTED_FAULT_EXIT_CODE),
        "the child must stop at the armed fault: {}",
        stdout(&restored)
    );
    assert_eq!(
        read(&directory.target()),
        b"previous install",
        "the restore must be durable before the journal that describes it is removed"
    );
    assert!(!rollback_object(&directory).exists());
    assert!(
        journal(&directory).exists(),
        "the journal may only go away once the restored install cannot be lost"
    );

    let settled = run(&mut fixture("install", &directory, &release));

    assert!(
        settled.status.success(),
        "a journal left over from a completed restore must settle cleanly: {}",
        stdout(&settled)
    );
    assert_eq!(read(&directory.target()), release.bytes);
    assert!(!journal(&directory).exists());
    assert!(!rollback_object(&directory).exists());
}

#[test]
fn a_contended_staging_lock_leaves_the_runtime_free_to_make_progress() {
    let directory = TestDir::new("lock-runtime");
    let release = Release::with_bytes(vec![0x27_u8; 4096], Some(16));

    // A child holds the staging lock for as long as its download is stalled.
    let mut holder = fixture("download", &directory, &release)
        .spawn()
        .expect("spawn the holding download");
    release.server.wait_for_artifact_request();

    let manifest = release.server.url("manifest.json");
    let state = directory.state();
    let target_path = directory.target();
    let (progress, progress_rx) = mpsc::channel();
    let (completion, completion_rx) = mpsc::channel();
    let runtime_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async move {
            let updater = Updater::with_public_key_and_state(
                signing_key().verifying_key().to_bytes(),
                TARGET_TRIPLE,
                state,
            )
            .expect("test updater");
            let url = Url::parse(&manifest).expect("manifest URL");
            let current = Version::parse(CURRENT_VERSION).expect("current version");
            let update = match updater.check(&url, &current).await.expect("signed check") {
                UpdateDecision::Available { update, .. } => update,
                UpdateDecision::Current { version } => panic!("unexpected current {version}"),
            };
            let target =
                InstallTarget::new(target_path, InstallMode::Executable).expect("install target");

            // A download that waits for the contended staging lock must leave
            // the runtime free: if it blocked the thread instead, this timer
            // would never fire and nothing would ever be reported.
            let waiting = updater.download(&update, &target);
            tokio::pin!(waiting);
            let mut ticks = 0_u32;
            let downloaded = loop {
                tokio::select! {
                    result = &mut waiting => break result.is_ok(),
                    () = tokio::time::sleep(Duration::from_millis(5)) => {
                        ticks += 1;
                        if ticks == 4 {
                            let _ = progress.send(ticks);
                        }
                    }
                }
            };
            let _ = completion.send(downloaded);
        });
    });

    let progressed = progress_rx.recv_timeout(WAIT_BUDGET);
    release.server.release();
    let holder = holder.wait().expect("holding download exits");
    let completed = completion_rx.recv_timeout(WAIT_BUDGET);
    let _ = runtime_thread.join();

    assert_eq!(
        progressed,
        Ok(4),
        "a current-thread runtime must keep driving its own timers while a download waits \
         for the staging lock another run is holding"
    );
    assert!(holder.success(), "the holding download must succeed");
    assert_eq!(
        completed,
        Ok(true),
        "the waiting download must complete once the lock is released"
    );
    assert_eq!(
        release.server.artifact_requests(),
        1,
        "the waiting run must reuse the verified artifact the first run staged"
    );
}

#[test]
fn an_unreadable_moved_aside_install_never_returns_with_the_target_missing() {
    let directory = TestDir::new("unreadable-move-aside");
    let release = Release::spawn(None);
    std::fs::write(directory.target(), b"previous install").expect("write previous install");

    let rolled_back = run(fixture("install", &directory, &release)
        .arg("--fault")
        .arg("fail-moved-aside-digest"));

    assert!(
        stdout(&rolled_back)
            .contains("update installation failed; previous version was restored"),
        "a failure to read back the moved-aside install must roll back, not escape: {}",
        stdout(&rolled_back)
    );
    assert_eq!(
        read(&directory.target()),
        b"previous install",
        "the install must never return with the target missing"
    );
    assert!(!rollback_object(&directory).exists());
    assert!(!journal(&directory).exists());
}

#[test]
fn a_stale_fresh_install_journal_never_retires_an_unrelated_rollback_object() {
    let directory = TestDir::new("unowned-rollback");
    let release = Release::spawn(None);

    let crashed = run(fixture("install", &directory, &release)
        .arg("--fault")
        .arg("exit-after-swap-committed"));
    assert_eq!(
        crashed.status.code(),
        Some(INJECTED_FAULT_EXIT_CODE),
        "the child must stop at the armed fault: {}",
        stdout(&crashed)
    );
    assert!(journal(&directory).exists());
    assert!(
        !directory.target().exists(),
        "a fresh install has nothing at the target yet"
    );

    // The interrupted run's replacement lands at the target, and something
    // unrelated occupies the rollback name. A fresh-install journal records no
    // original, so that object was never this run's to retire.
    std::fs::write(directory.target(), &release.bytes).expect("place the replacement");
    std::fs::write(rollback_object(&directory), b"an unrelated rollback object")
        .expect("place an unrelated rollback object");

    let conflicted = run(&mut fixture("install", &directory, &release));

    assert!(
        stdout(&conflicted).contains("interrupted update conflicts with an unknown local object"),
        "an unowned rollback object must be a conflict, never a deletion: {}",
        stdout(&conflicted)
    );
    assert_eq!(
        read(&rollback_object(&directory)),
        b"an unrelated rollback object"
    );
}

#[cfg(unix)]
#[test]
fn a_marker_that_could_not_be_made_durable_is_reconfirmed_next_run() {
    let directory = TestDir::new("retracted-marker");
    let release = Release::spawn(None);

    let failed = run(fixture("check", &directory, &release)
        .arg("--fault")
        .arg("fail-new-state-directory-sync@state-marker"));

    assert!(
        !stdout(&failed).starts_with("ok:"),
        "an unconfirmed marker must not be reported as success: {}",
        stdout(&failed)
    );
    let marker = durable_marker(&directory);
    assert!(
        !marker.exists() || std::fs::metadata(&marker).expect("marker metadata").len() == 0,
        "a marker whose entry was never made durable must be retracted or emptied"
    );

    let accepted = run(&mut fixture("check", &directory, &release));

    assert!(
        accepted.status.success(),
        "the next run must confirm the tree again: {}",
        stdout(&accepted)
    );
    assert!(
        marker.is_file() && std::fs::metadata(&marker).expect("marker metadata").len() > 0,
        "a confirmed tree records the fact durably"
    );
}


#[cfg(unix)]
#[test]
fn a_crash_while_the_marker_is_still_empty_leaves_the_tree_unconfirmed() {
    let directory = TestDir::new("empty-marker-crash");
    let release = Release::spawn(None);

    let crashed = run(fixture("check", &directory, &release)
        .arg("--fault")
        .arg("exit-after-empty-durability-marker"));

    assert_eq!(
        crashed.status.code(),
        Some(INJECTED_FAULT_EXIT_CODE),
        "the child must stop while the marker is still empty: {}",
        stdout(&crashed)
    );
    let marker = durable_marker(&directory);
    assert!(marker.is_file(), "the marker is published before it is filled");
    assert_eq!(
        std::fs::metadata(&marker).expect("marker metadata").len(),
        0,
        "the first publication phase leaves an empty marker, which reads as unconfirmed"
    );

    // The next run must finish the publication rather than trust the leftover.
    let accepted = run(&mut fixture("check", &directory, &release));

    assert!(
        accepted.status.success(),
        "the next run must complete the interrupted publication: {}",
        stdout(&accepted)
    );
    assert!(
        std::fs::metadata(&marker).expect("marker metadata").len() > 0,
        "a confirmed tree records the fact durably"
    );
}

/// A crash after the quarantine is journalled but before anything has moved.
#[test]
fn a_crash_before_the_quarantine_moves_leaves_the_backup_where_it_was() {
    let directory = TestDir::new("quarantine-planned");
    let release = Release::spawn(None);
    std::fs::write(directory.target(), b"previous install").expect("write previous install");

    let crashed = run(fixture("install", &directory, &release)
        .arg("--fault")
        .arg("exit-after-quarantine-planned"));

    assert_eq!(
        crashed.status.code(),
        Some(INJECTED_FAULT_EXIT_CODE),
        "the child must stop before the quarantine moves: {}",
        stdout(&crashed)
    );
    assert_eq!(
        read(&directory.target()),
        release.bytes,
        "the replacement is already published at this point"
    );
    assert_eq!(
        read(&rollback_object(&directory)),
        b"previous install",
        "a planned-but-unmoved quarantine leaves the object under its own name"
    );

    // Recovery must reconcile "planned, nothing moved" without deleting.
    let recovered = run(&mut fixture("download", &directory, &release));

    assert!(
        recovered.status.success(),
        "a planned quarantine must reconcile cleanly: {}",
        stdout(&recovered)
    );
}

/// A crash after the quarantine has moved but before the object is deleted.
#[test]
fn a_crash_after_the_quarantine_moves_finishes_the_deletion_next_run() {
    let directory = TestDir::new("quarantine-moved");
    let release = Release::spawn(None);
    std::fs::write(directory.target(), b"previous install").expect("write previous install");

    let crashed = run(fixture("install", &directory, &release)
        .arg("--fault")
        .arg("exit-after-quarantine-moved"));

    assert_eq!(
        crashed.status.code(),
        Some(INJECTED_FAULT_EXIT_CODE),
        "the child must stop with the object quarantined: {}",
        stdout(&crashed)
    );
    assert!(
        !rollback_object(&directory).exists(),
        "the object has left its own name at this point"
    );
    let quarantined: Vec<_> = std::fs::read_dir(directory.stage())
        .expect("read staging directory")
        .map(|entry| entry.expect("staging entry").file_name())
        .filter(|name| name.to_string_lossy().starts_with(".retired-backup-"))
        .collect();
    assert_eq!(
        quarantined.len(),
        1,
        "exactly the journalled quarantine should be present"
    );

    let recovered = run(&mut fixture("download", &directory, &release));

    assert!(
        recovered.status.success(),
        "a moved quarantine must be finished, not reported as a conflict: {}",
        stdout(&recovered)
    );
    assert_eq!(
        std::fs::read_dir(directory.stage())
            .expect("read staging directory")
            .filter(|entry| {
                entry
                    .as_ref()
                    .expect("staging entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".retired-backup-")
            })
            .count(),
        0,
        "the journalled quarantine must be deleted once its identity is confirmed"
    );
    assert_eq!(read(&directory.target()), release.bytes);
}

/// The rollback path, reached from a child process rather than a direct call.
#[test]
fn a_publication_failure_rolls_back_and_reports_through_a_child_process() {
    let directory = TestDir::new("publication-rollback");
    let release = Release::spawn(None);
    std::fs::write(directory.target(), b"previous install").expect("write previous install");

    // Two faults in order: fail the publication identity check so rollback runs,
    // then fail the sync inside that rollback. The target must still come back.
    let reported = run(fixture("install", &directory, &release)
        .arg("--fault")
        .arg("fail-published-identity")
        .arg("--fault")
        .arg("fail-parent-sync-during-rollback"));

    assert!(
        !reported.status.success(),
        "a failed publication must not report success: {}",
        stdout(&reported)
    );
    assert_eq!(
        read(&directory.target()),
        b"previous install",
        "the install must never return with the target missing"
    );
}

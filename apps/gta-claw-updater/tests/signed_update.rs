//! Local-only adversarial updater integration coverage.

#[cfg(windows)]
use std::fs::OpenOptions;
#[cfg(windows)]
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(windows)]
use std::sync::{Barrier, mpsc};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use gta_claw_updater::{
    ArtifactKind, AvailableUpdate, InstallMode, InstallOutcome, InstallTarget, ReleaseArtifact,
    ReleaseManifest, SignedManifest, UpdateDecision, UpdateOutcome, Updater,
};
use semver::Version;
#[cfg(not(windows))]
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(1);

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "gta-claw-updater-{label}-{}-{sequence}",
            std::process::id()
        ));
        if path.exists() {
            std::fs::remove_dir_all(&path).expect("remove stale test directory");
        }
        std::fs::create_dir(&path).expect("create isolated test directory");
        #[cfg(unix)]
        let path = std::fs::canonicalize(path).expect("resolve system temporary directory aliases");
        #[cfg(windows)]
        Self::lock_test_directory(&path);
        Self { path }
    }

    #[cfg(windows)]
    fn lock_test_directory(path: &Path) {
        use windows_acl::acl::{ACL, AceType};
        use windows_acl::helper::{current_user, name_to_sid, sid_to_string};

        const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
        let user = current_user().expect("current test user");
        let current_sid = name_to_sid(&user, None).expect("current test SID");
        let current_sid_pointer = current_sid.as_ptr().cast_mut().cast();
        let current_sid_string = sid_to_string(current_sid_pointer).expect("current SID string");
        let mut acl = ACL::from_file_path(path.to_str().expect("Unicode test path"), false)
            .expect("test ACL");
        acl.remove(current_sid_pointer, Some(AceType::AccessDeny), None)
            .expect("remove current-user deny entries");
        assert!(
            acl.allow(current_sid_pointer, true, FILE_ALL_ACCESS)
                .expect("allow current test user"),
            "current-user ACL must be applied"
        );
        for entry in acl.all().expect("test ACL entries") {
            if entry.string_sid == current_sid_string {
                continue;
            }
            let sid = entry.sid.expect("test ACE SID");
            acl.remove(sid.as_ptr().cast_mut().cast(), None, None)
                .expect("remove non-user test ACE");
        }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Request {
    path: String,
    range: Option<String>,
}

struct ResponsePlan {
    status: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    write_bytes: usize,
}

type Handler = Arc<dyn Fn(Request, usize) -> ResponsePlan + Send + Sync>;
struct LocalServer {
    url: Url,
    requests: Arc<Mutex<Vec<Request>>>,
    task: tokio::task::JoinHandle<()>,
}

impl LocalServer {
    async fn spawn(handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback server");
        let address = listener.local_addr().expect("loopback address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task_requests = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let mut index = 0;
            while let Ok((stream, _)) = listener.accept().await {
                let handler = Arc::clone(&handler);
                let requests = Arc::clone(&task_requests);
                index += 1;
                handle_connection(stream, handler, requests, index).await;
            }
        });
        Self {
            url: Url::parse(&format!("http://{address}/")).expect("local URL"),
            requests,
            task,
        }
    }

    fn url(&self, path: &str) -> Url {
        self.url.join(path).expect("local path URL")
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    handler: Handler,
    requests: Arc<Mutex<Vec<Request>>>,
    index: usize,
) {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let count = stream.read(&mut chunk).await.expect("read local request");
        if count == 0 {
            return;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8(bytes).expect("HTTP request is UTF-8");
    let mut lines = text.split("\r\n");
    let request_line = lines.next().expect("request line");
    let path = request_line
        .split_ascii_whitespace()
        .nth(1)
        .expect("request path")
        .to_owned();
    let range = lines.find_map(|line| {
        line.strip_prefix("range: ")
            .or_else(|| line.strip_prefix("Range: "))
            .map(ToOwned::to_owned)
    });
    let request = Request { path, range };
    requests
        .lock()
        .expect("request log lock")
        .push(request.clone());
    let plan = handler(request, index);
    let mut response = format!(
        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        plan.status,
        plan.body.len()
    );
    for (name, value) in plan.headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    stream
        .write_all(response.as_bytes())
        .await
        .expect("write local response headers");
    stream
        .write_all(&plan.body[..plan.write_bytes.min(plan.body.len())])
        .await
        .expect("write local response body");
    stream.flush().await.expect("flush local response");
    if plan.write_bytes < plan.body.len() {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

fn handler<F>(handler: F) -> Handler
where
    F: Fn(Request, usize) -> ResponsePlan + Send + Sync + 'static,
{
    Arc::new(handler)
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[19_u8; 32])
}

fn updater(directory: &Path) -> Updater {
    Updater::with_public_key_and_state(
        signing_key().verifying_key().to_bytes(),
        "x86_64-test-target",
        directory.join("updater-state"),
    )
    .expect("test updater")
}

fn signed_bytes(manifest: ReleaseManifest) -> Vec<u8> {
    let canonical = serde_json::to_vec(&manifest).expect("canonical test manifest");
    let signature = signing_key().sign(&canonical);
    serde_json::to_vec(&SignedManifest {
        manifest,
        signature: STANDARD.encode(signature.to_bytes()),
    })
    .expect("signed envelope")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn artifact(url: Url, bytes: &[u8], kind: ArtifactKind) -> ReleaseArtifact {
    ReleaseArtifact {
        release_sequence: 1,
        target: "x86_64-test-target".to_owned(),
        url: url.to_string(),
        sha256: sha256_hex(bytes),
        size: u64::try_from(bytes.len()).expect("small test artifact"),
        kind,
    }
}

fn manifest(
    version: &str,
    sequence: u64,
    revoked_versions: Vec<String>,
    mut artifacts: Vec<ReleaseArtifact>,
) -> ReleaseManifest {
    for artifact in &mut artifacts {
        artifact.release_sequence = sequence;
    }
    ReleaseManifest {
        version: version.to_owned(),
        sequence,
        published_at_unix: 1_700_000_000,
        expires_at_unix: 4_102_444_800,
        revoked_versions,
        artifacts,
    }
}

fn executable_target(directory: &Path) -> InstallTarget {
    InstallTarget::new(directory.join("gta-claw.exe"), InstallMode::Executable)
        .expect("test executable target")
}

fn authorized_update(updater: &Updater, artifact: ReleaseArtifact) -> AvailableUpdate {
    let sequence = artifact.release_sequence;
    let version = format!("2.0.{sequence}");
    let decision = updater
        .check_manifest_bytes(
            &signed_bytes(manifest(
                &version,
                sequence,
                Vec::new(),
                vec![artifact.clone()],
            )),
            &Version::parse("1.0.0").expect("current version"),
        )
        .expect("signed artifact authorization");
    match decision {
        UpdateDecision::Available {
            version: accepted,
            update,
        } => {
            assert_eq!(accepted, Version::parse(&version).expect("release version"));
            assert_eq!(update.artifact(), &artifact);
            update
        }
        UpdateDecision::Current { version } => {
            panic!("expected available update, got current {version}")
        }
    }
}

#[test]
fn verifies_independent_ed25519_signature_vector() {
    let directory = TestDir::new("signature-vector");
    let envelope = br#"{"manifest":{"version":"2.1.0","sequence":21,"published_at_unix":1700000000,"expires_at_unix":4102444800,"revoked_versions":[],"artifacts":[{"release_sequence":21,"target":"x86_64-test-target","url":"https://updates.example.invalid/gta-claw.exe","sha256":"a4d451ec23463726f72c43d64c710968f6b602cd653b4de8adee1b556240a829","size":7,"kind":"executable"}]},"signature":"duXf91inDKUMn98jsOLVWkQcQg2gi5671SZ+yMJhreU9Du/iyx5AtLxWqnnaayZfTQ1YC2O0OQYNfY6n3VQYAA=="}"#;
    let verified = updater(&directory.path)
        .verify_manifest(envelope)
        .expect("independent signer vector verifies");
    assert_eq!(
        verified,
        manifest(
            "2.1.0",
            21,
            Vec::new(),
            vec![ReleaseArtifact {
                release_sequence: 21,
                target: "x86_64-test-target".to_owned(),
                url: "https://updates.example.invalid/gta-claw.exe".to_owned(),
                sha256: "a4d451ec23463726f72c43d64c710968f6b602cd653b4de8adee1b556240a829"
                    .to_owned(),
                size: 7,
                kind: ArtifactKind::Executable,
            }],
        )
    );
}

#[tokio::test]
async fn checks_valid_signed_manifest_and_rejects_forged_or_unsigned_data() {
    let directory = TestDir::new("manifest");
    let release_bytes = b"release";
    let manifest = ReleaseManifest {
        version: "2.1.0".to_owned(),
        sequence: 21,
        published_at_unix: 1_700_000_000,
        expires_at_unix: 4_102_444_800,
        revoked_versions: Vec::new(),
        artifacts: vec![ReleaseArtifact {
            release_sequence: 21,
            target: "x86_64-test-target".to_owned(),
            url: "https://updates.example.invalid/gta-claw.exe".to_owned(),
            sha256: sha256_hex(release_bytes),
            size: u64::try_from(release_bytes.len()).expect("small release"),
            kind: ArtifactKind::Executable,
        }],
    };
    let envelope = signed_bytes(manifest.clone());
    let server_envelope = envelope.clone();
    let server = LocalServer::spawn(handler(move |request, _| {
        assert_eq!(
            request,
            Request {
                path: "/manifest.json".to_owned(),
                range: None,
            }
        );
        ResponsePlan {
            status: "200 OK",
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            write_bytes: server_envelope.len(),
            body: server_envelope.clone(),
        }
    }))
    .await;
    let decision = updater(&directory.path)
        .check(
            &server.url("manifest.json"),
            &Version::parse("2.0.0").expect("current version"),
        )
        .await
        .expect("valid manifest check");
    match decision {
        UpdateDecision::Available { version, update } => {
            assert_eq!(version, Version::parse("2.1.0").expect("release version"));
            assert_eq!(update.artifact(), &manifest.artifacts[0]);
        }
        UpdateDecision::Current { version } => {
            panic!("expected available update, got current {version}")
        }
    }

    let mut forged: SignedManifest =
        serde_json::from_slice(&envelope).expect("decode signed envelope");
    forged.manifest.version = "9.9.9".to_owned();
    let forged_error = updater(&directory.path)
        .verify_manifest(&serde_json::to_vec(&forged).expect("encode forged envelope"))
        .expect_err("forged signature rejected");
    assert_eq!(
        forged_error.to_string(),
        "release manifest signature is invalid"
    );

    forged.signature.clear();
    let unsigned_error = updater(&directory.path)
        .verify_manifest(&serde_json::to_vec(&forged).expect("encode unsigned envelope"))
        .expect_err("unsigned manifest rejected");
    assert_eq!(
        unsigned_error.to_string(),
        "release manifest signature encoding is invalid"
    );
}

#[tokio::test]
async fn persists_anti_rollback_floor_and_enforces_expiry_and_revocation() {
    let directory = TestDir::new("anti-rollback");
    let release = artifact(
        Url::parse("https://updates.example.invalid/gta-claw.exe").expect("artifact URL"),
        b"release",
        ArtifactKind::Executable,
    );
    let newest = signed_bytes(manifest("3.0.0", 30, Vec::new(), vec![release.clone()]));
    let replay = signed_bytes(manifest("2.0.0", 20, Vec::new(), vec![release.clone()]));
    let server = LocalServer::spawn(handler(move |_, index| {
        let body = if index == 1 {
            newest.clone()
        } else {
            replay.clone()
        };
        ResponsePlan {
            status: "200 OK",
            headers: Vec::new(),
            write_bytes: body.len(),
            body,
        }
    }))
    .await;
    let updater = updater(&directory.path);
    let first = updater
        .check(
            &server.url("manifest"),
            &Version::parse("1.0.0").expect("current version"),
        )
        .await
        .expect("newest manifest accepted");
    match first {
        UpdateDecision::Available { version, update } => {
            assert_eq!(version, Version::parse("3.0.0").expect("new version"));
            assert_eq!(
                update.artifact(),
                &ReleaseArtifact {
                    release_sequence: 30,
                    ..release.clone()
                }
            );
        }
        UpdateDecision::Current { version } => {
            panic!("expected available update, got current {version}")
        }
    }
    let replay_error = updater
        .check(
            &server.url("manifest"),
            &Version::parse("1.0.0").expect("current version"),
        )
        .await
        .expect_err("older signed manifest rejected");
    assert_eq!(
        replay_error.to_string(),
        "signed release sequence 20 is below verified floor 30"
    );

    let mut expired = manifest("4.0.0", 40, Vec::new(), vec![release.clone()]);
    expired.published_at_unix = 1;
    expired.expires_at_unix = 2;
    let expired_error = updater
        .verify_manifest(&signed_bytes(expired))
        .expect_err("expired signed manifest rejected");
    assert_eq!(
        expired_error.to_string(),
        "signed release manifest has expired"
    );

    let withdrawn = signed_bytes(manifest("3.0.0", 31, vec!["1.0.0".to_owned()], Vec::new()));
    let withdrawn_server = LocalServer::spawn(handler(move |_, _| ResponsePlan {
        status: "200 OK",
        headers: Vec::new(),
        write_bytes: withdrawn.len(),
        body: withdrawn.clone(),
    }))
    .await;
    let revoked_error = updater
        .check(
            &withdrawn_server.url("manifest"),
            &Version::parse("1.0.0").expect("current version"),
        )
        .await
        .expect_err("withdrawn installed release is surfaced");
    assert_eq!(
        revoked_error.to_string(),
        "installed release has been withdrawn"
    );
}

#[tokio::test]
async fn interrupted_verified_upgrade_cannot_install_after_a_newer_persisted_floor() {
    let directory = TestDir::new("interrupted-floor");
    let replacement = b"sequence 30 replacement".to_vec();
    let server_bytes = replacement.clone();
    let server = LocalServer::spawn(handler(move |_, _| ResponsePlan {
        status: "200 OK",
        headers: Vec::new(),
        write_bytes: server_bytes.len(),
        body: server_bytes.clone(),
    }))
    .await;
    let mut release_30 = artifact(
        server.url("artifact"),
        &replacement,
        ArtifactKind::Executable,
    );
    release_30.release_sequence = 30;
    let updater_30 = updater(&directory.path);
    let decision_30 = updater_30
        .check_manifest_bytes(
            &signed_bytes(manifest("3.0.0", 30, Vec::new(), vec![release_30.clone()])),
            &Version::parse("1.0.0").expect("current version"),
        )
        .expect("sequence 30 accepted");
    let update_30 = match decision_30 {
        UpdateDecision::Available { version, update } => {
            assert_eq!(version, Version::parse("3.0.0").expect("release version"));
            update
        }
        UpdateDecision::Current { version } => {
            panic!("expected available update, got current {version}")
        }
    };
    let target = executable_target(&directory.path);
    std::fs::write(target.path(), b"known good").expect("write existing target");
    let verified_30 = updater_30
        .download(&update_30, &target)
        .await
        .expect("sequence 30 verifies before interruption");
    drop(updater_30);

    let mut release_40 = release_30;
    release_40.release_sequence = 40;
    let updater_40 = updater(&directory.path);
    let decision_40 = updater_40
        .check_manifest_bytes(
            &signed_bytes(manifest("4.0.0", 40, Vec::new(), vec![release_40])),
            &Version::parse("1.0.0").expect("current version"),
        )
        .expect("sequence 40 persists after interruption");
    match decision_40 {
        UpdateDecision::Available { version, update } => {
            assert_eq!(version, Version::parse("4.0.0").expect("release version"));
            assert_eq!(update.artifact().release_sequence, 40);
        }
        UpdateDecision::Current { version } => {
            panic!("expected available update, got current {version}")
        }
    }

    let stale_error = updater_40
        .install(verified_30, &target)
        .await
        .expect_err("stale verified artifact rejected at install");
    assert_eq!(
        stale_error.to_string(),
        "signed release sequence 30 is below verified floor 40"
    );
    assert_eq!(
        std::fs::read(target.path()).expect("read untouched target"),
        b"known good"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn windows_restart_required_redownloads_after_verified_path_replacement() {
    use std::os::windows::fs::OpenOptionsExt as _;

    let directory = TestDir::new("windows-restart-rename-replacement");
    let signed_artifact = b"signed executable replacement".to_vec();
    let attacker_bytes = b"attacker-controlled replacement".to_vec();
    let server_artifact = signed_artifact.clone();
    let server = LocalServer::spawn(handler(move |request, _| {
        assert_eq!(
            request,
            Request {
                path: "/artifact".to_owned(),
                range: None,
            }
        );
        ResponsePlan {
            status: "200 OK",
            headers: Vec::new(),
            write_bytes: server_artifact.len(),
            body: server_artifact.clone(),
        }
    }))
    .await;
    let target = executable_target(&directory.path);
    std::fs::write(target.path(), b"running executable").expect("write existing target");
    let release = artifact(
        server.url("artifact"),
        &signed_artifact,
        ArtifactKind::Executable,
    );
    let first_updater = updater(&directory.path);
    let first_update = authorized_update(&first_updater, release.clone());
    let verified = first_updater
        .download(&first_update, &target)
        .await
        .expect("first signed download verifies");
    assert_eq!(
        server.requests.lock().expect("request log lock").as_slice(),
        &[Request {
            path: "/artifact".to_owned(),
            range: None,
        }]
    );

    // This is same-account concurrent-process hardening inside owner-only staging, not a remote or
    // cross-user integrity boundary.
    let staged_path = verified.path().to_owned();
    let moved_path = staged_path.with_file_name("artifact.moved");
    let start = Arc::new(Barrier::new(2));
    let attacker_start = Arc::clone(&start);
    let attacker_staged_path = staged_path.clone();
    let attacker_moved_path = moved_path.clone();
    let attacker_replacement = attacker_bytes.clone();
    let (completed_tx, completed_rx) = mpsc::channel();
    let attacker = std::thread::spawn(move || {
        attacker_start.wait();
        std::fs::rename(&attacker_staged_path, &attacker_moved_path)
            .expect("FILE_SHARE_DELETE permits moving the verified pathname");
        let moved_bytes =
            std::fs::read(&attacker_moved_path).expect("read renamed verified object");
        let mut replacement = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&attacker_staged_path)
            .expect("create replacement at original verified pathname");
        replacement
            .write_all(&attacker_replacement)
            .expect("write attacker replacement");
        replacement.sync_all().expect("sync attacker replacement");
        drop(replacement);
        let replacement_bytes =
            std::fs::read(&attacker_staged_path).expect("read attacker replacement");
        completed_tx
            .send((moved_bytes, replacement_bytes))
            .expect("report completed pathname replacement");
    });

    start.wait();
    let (moved_bytes, replacement_bytes) = completed_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("pathname replacement completes before installation");
    attacker.join().expect("attacker thread");
    assert_eq!(
        moved_bytes, signed_artifact,
        "rename must move verified bytes"
    );
    assert_eq!(
        replacement_bytes, attacker_bytes,
        "replacement must be created and written at the original pathname"
    );
    assert!(moved_path.is_file(), "renamed verified pathname must exist");
    assert_eq!(
        std::fs::read(&staged_path).expect("read original verified pathname"),
        attacker_bytes
    );

    let mut target_lock = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(target.path())
        .expect("lock running executable");
    let first_outcome = first_updater
        .install(verified, &target)
        .await
        .expect("locked target is restart-required");
    assert_eq!(first_outcome, InstallOutcome::RestartRequired);
    target_lock
        .seek(SeekFrom::Start(0))
        .expect("rewind locked target");
    let mut locked_target_bytes = Vec::new();
    target_lock
        .read_to_end(&mut locked_target_bytes)
        .expect("read locked target handle");
    assert_eq!(locked_target_bytes, b"running executable");
    assert_eq!(
        std::fs::read(&staged_path).expect("read attacker pathname after locked install"),
        attacker_bytes
    );

    drop(target_lock);
    drop(first_update);
    drop(first_updater);
    let second_updater = updater(&directory.path);
    let second_update = authorized_update(&second_updater, release);
    let second_verified = second_updater
        .download(&second_update, &target)
        .await
        .expect("fresh signed download verifies");
    assert_eq!(
        server.requests.lock().expect("request log lock").as_slice(),
        &[
            Request {
                path: "/artifact".to_owned(),
                range: None,
            },
            Request {
                path: "/artifact".to_owned(),
                range: None,
            },
        ],
        "rerun must issue an independent artifact request"
    );
    assert_eq!(
        std::fs::read(second_verified.path()).expect("read freshly verified pathname"),
        signed_artifact
    );
    assert_ne!(
        std::fs::read(second_verified.path()).expect("reread freshly verified pathname"),
        attacker_bytes
    );

    let second_outcome = second_updater
        .install(second_verified, &target)
        .await
        .expect("unlocked target installs");
    assert_eq!(second_outcome, InstallOutcome::Installed);
    let installed = std::fs::read(target.path()).expect("read installed target");
    assert_eq!(installed, signed_artifact);
    assert_ne!(installed, attacker_bytes);
    assert!(
        !staged_path.exists(),
        "successful rerun must remove the replaced staging pathname"
    );
}

#[tokio::test]
async fn rejects_tampered_artifact_and_removes_untrusted_partial() {
    let directory = TestDir::new("tampered");
    let trusted = b"verified update bytes".to_vec();
    let mut tampered = trusted.clone();
    tampered[3] ^= 0x55;
    let server_body = tampered.clone();
    let server = LocalServer::spawn(handler(move |request, _| {
        assert_eq!(
            request,
            Request {
                path: "/artifact".to_owned(),
                range: None,
            }
        );
        ResponsePlan {
            status: "200 OK",
            headers: Vec::new(),
            write_bytes: server_body.len(),
            body: server_body.clone(),
        }
    }))
    .await;
    let release = artifact(server.url("artifact"), &trusted, ArtifactKind::Executable);
    let target = executable_target(&directory.path);
    let updater = updater(&directory.path);
    let update = authorized_update(&updater, release);
    let error = updater
        .download(&update, &target)
        .await
        .expect_err("tampered artifact rejected");
    assert_eq!(error.to_string(), "artifact SHA-256 mismatch");
    assert_eq!(
        std::fs::read_dir(&directory.path)
            .expect("read test directory")
            .count(),
        2
    );
    assert_eq!(
        std::fs::read_dir(directory.path.join(".gta-claw.exe.gta-claw-stage"))
            .expect("read protected staging directory")
            .count(),
        0
    );
}

#[tokio::test]
async fn rejects_mismatched_content_range_and_cross_artifact_resume() {
    let directory = TestDir::new("resume-binding");
    let first_bytes = b"first artifact payload".to_vec();
    let second_bytes = b"entirely different replacement".to_vec();
    let first_response = first_bytes.clone();
    let second_response = second_bytes.clone();
    let server = LocalServer::spawn(handler(move |request, index| match index {
        1 => ResponsePlan {
            status: "200 OK",
            headers: Vec::new(),
            body: first_response.clone(),
            write_bytes: 6,
        },
        2 => {
            assert_eq!(request.range, Some("bytes=6-".to_owned()));
            ResponsePlan {
                status: "206 Partial Content",
                headers: vec![(
                    "Content-Range".to_owned(),
                    format!(
                        "bytes 7-{}/{}",
                        first_response.len() - 1,
                        first_response.len()
                    ),
                )],
                body: first_response[6..].to_vec(),
                write_bytes: first_response.len() - 6,
            }
        }
        3 => {
            assert_eq!(
                request,
                Request {
                    path: "/second".to_owned(),
                    range: None,
                }
            );
            ResponsePlan {
                status: "200 OK",
                headers: Vec::new(),
                body: second_response.clone(),
                write_bytes: second_response.len(),
            }
        }
        _ => panic!("unexpected request {index}"),
    }))
    .await;
    let target = executable_target(&directory.path);
    let first = artifact(server.url("first"), &first_bytes, ArtifactKind::Executable);
    let updater = updater(&directory.path);
    let first_update = authorized_update(&updater, first);
    let interrupted = updater
        .download(&first_update, &target)
        .await
        .expect_err("first artifact interrupted");
    assert_eq!(interrupted.to_string(), "update HTTP transfer failed");
    let range_error = updater
        .download(&first_update, &target)
        .await
        .expect_err("mismatched range rejected");
    assert_eq!(range_error.to_string(), "resume response range is invalid");

    let mut second = artifact(
        server.url("second"),
        &second_bytes,
        ArtifactKind::Executable,
    );
    second.release_sequence = 2;
    let second_update = authorized_update(&updater, second);
    let verified = updater
        .download(&second_update, &target)
        .await
        .expect("different artifact starts from zero");
    assert_eq!(
        std::fs::read(verified.path()).expect("verified second artifact"),
        second_bytes
    );
}

#[tokio::test]
async fn interrupted_download_resumes_from_exact_persisted_offset() {
    let directory = TestDir::new("resume");
    let bytes = b"0123456789abcdefghijklmnopqrstuvwxyz".to_vec();
    let response_bytes = bytes.clone();
    let server = LocalServer::spawn(handler(move |request, index| {
        if index == 1 {
            assert_eq!(
                request,
                Request {
                    path: "/artifact".to_owned(),
                    range: None,
                }
            );
            ResponsePlan {
                status: "200 OK",
                headers: Vec::new(),
                body: response_bytes.clone(),
                write_bytes: 8,
            }
        } else {
            assert_eq!(
                request,
                Request {
                    path: "/artifact".to_owned(),
                    range: Some("bytes=8-".to_owned()),
                }
            );
            ResponsePlan {
                status: "206 Partial Content",
                headers: vec![(
                    "Content-Range".to_owned(),
                    format!(
                        "bytes 8-{}/{}",
                        response_bytes.len() - 1,
                        response_bytes.len()
                    ),
                )],
                body: response_bytes[8..].to_vec(),
                write_bytes: response_bytes.len() - 8,
            }
        }
    }))
    .await;
    let release = artifact(server.url("artifact"), &bytes, ArtifactKind::Executable);
    let target = executable_target(&directory.path);
    let updater = updater(&directory.path);
    let update = authorized_update(&updater, release);
    let first_error = updater
        .download(&update, &target)
        .await
        .expect_err("first transfer is interrupted");
    assert_eq!(first_error.to_string(), "update HTTP transfer failed");
    let part = directory
        .path
        .join(".gta-claw.exe.gta-claw-stage")
        .join("artifact.part");
    assert_eq!(std::fs::read(&part).expect("persisted partial"), bytes[..8]);

    let verified = updater
        .download(&update, &target)
        .await
        .expect("resumed artifact verifies");
    assert_eq!(
        std::fs::read(verified.path()).expect("verified staged bytes"),
        bytes
    );
    assert_eq!(
        server.requests.lock().expect("request log lock").as_slice(),
        [
            Request {
                path: "/artifact".to_owned(),
                range: None,
            },
            Request {
                path: "/artifact".to_owned(),
                range: Some("bytes=8-".to_owned()),
            },
        ]
    );
}

#[tokio::test]
async fn complete_partial_is_verified_without_an_invalid_range_request() {
    let directory = TestDir::new("complete-partial");
    let bytes = b"complete artifact bytes".to_vec();
    let target = executable_target(&directory.path);
    let mut incomplete_response = bytes.clone();
    incomplete_response.push(0xff);
    let response = incomplete_response.clone();
    let server = LocalServer::spawn(handler(move |request, index| {
        assert_eq!(
            index, 1,
            "complete persisted partial must avoid a second request"
        );
        assert_eq!(
            request,
            Request {
                path: "/artifact".to_owned(),
                range: None,
            }
        );
        ResponsePlan {
            status: "200 OK",
            headers: Vec::new(),
            body: response.clone(),
            write_bytes: response.len() - 1,
        }
    }))
    .await;
    let release = artifact(server.url("artifact"), &bytes, ArtifactKind::Executable);
    let updater = updater(&directory.path);
    let update = authorized_update(&updater, release);
    let first_error = updater
        .download(&update, &target)
        .await
        .expect_err("framing interruption leaves all expected bytes");
    assert_eq!(first_error.to_string(), "update HTTP transfer failed");

    let verified = updater
        .download(&update, &target)
        .await
        .expect("complete partial verifies locally");
    assert_eq!(
        std::fs::read(verified.path()).expect("verified complete partial"),
        bytes
    );
    assert_eq!(
        server.requests.lock().expect("request log lock").as_slice(),
        [Request {
            path: "/artifact".to_owned(),
            range: None,
        }]
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn installs_complete_macos_bundle_and_rejects_archive_traversal() {
    let directory = TestDir::new("bundle");
    let target_path = directory.path.join("GTA Claw.app");
    std::fs::create_dir(&target_path).expect("create old bundle");
    std::fs::write(target_path.join("old.txt"), b"old").expect("write old bundle");
    let bundle = serde_json::to_vec(&json!({
        "format": "gta-claw-bundle-v1",
        "files": [
            {
                "path": "Contents/MacOS/gta-claw",
                "mode": 493,
                "contents": STANDARD.encode(b"new executable")
            },
            {
                "path": "Contents/Info.plist",
                "mode": 420,
                "contents": STANDARD.encode(b"plist")
            }
        ]
    }))
    .expect("bundle archive");
    let server_bundle = bundle.clone();
    let server = LocalServer::spawn(handler(move |_, _| ResponsePlan {
        status: "200 OK",
        headers: Vec::new(),
        write_bytes: server_bundle.len(),
        body: server_bundle.clone(),
    }))
    .await;
    let release = artifact(server.url("bundle"), &bundle, ArtifactKind::MacOsBundle);
    let target = InstallTarget::new(target_path.clone(), InstallMode::MacOsBundle)
        .expect("macOS bundle target");
    let updater = updater(&directory.path);
    let update = authorized_update(&updater, release);
    let verified = updater
        .download(&update, &target)
        .await
        .expect("download bundle");
    let outcome = updater
        .install(verified, &target)
        .await
        .expect("install bundle");
    assert_eq!(outcome, InstallOutcome::Installed);
    assert_eq!(
        std::fs::read(target_path.join("Contents/MacOS/gta-claw")).expect("new bundle executable"),
        b"new executable"
    );
    assert_eq!(
        std::fs::read(target_path.join("Contents/Info.plist")).expect("new bundle metadata"),
        b"plist"
    );
    assert!(!target_path.join("old.txt").exists());

    let unsafe_bundle = serde_json::to_vec(&json!({
        "format": "gta-claw-bundle-v1",
        "files": [{
            "path": "../escaped",
            "mode": 420,
            "contents": STANDARD.encode(b"escape")
        }]
    }))
    .expect("unsafe bundle archive");
    let unsafe_server_body = unsafe_bundle.clone();
    let unsafe_server = LocalServer::spawn(handler(move |_, _| ResponsePlan {
        status: "200 OK",
        headers: Vec::new(),
        write_bytes: unsafe_server_body.len(),
        body: unsafe_server_body.clone(),
    }))
    .await;
    let mut unsafe_release = artifact(
        unsafe_server.url("bundle"),
        &unsafe_bundle,
        ArtifactKind::MacOsBundle,
    );
    unsafe_release.release_sequence = 2;
    let unsafe_update = authorized_update(&updater, unsafe_release);
    let verified = updater
        .download(&unsafe_update, &target)
        .await
        .expect("unsafe archive bytes still verify");
    let error = updater
        .install(verified, &target)
        .await
        .expect_err("archive traversal rejected");
    assert_eq!(error.to_string(), "macOS bundle archive is invalid");
    assert!(!directory.path.join("escaped").exists());
}

#[tokio::test]
async fn linux_package_mode_is_network_and_filesystem_noop() {
    let directory = TestDir::new("linux-noop");
    let target_path = directory.path.join("gta-claw");
    std::fs::write(&target_path, b"unchanged").expect("write package binary");
    let target = InstallTarget::new(target_path.clone(), InstallMode::LinuxPackage)
        .expect("Linux package target");
    let outcome = updater(&directory.path)
        .execute(
            &Url::parse("http://198.51.100.1/never-requested").expect("test URL"),
            &Version::parse("1.0.0").expect("current version"),
            &target,
        )
        .await
        .expect("Linux path is a no-op");
    assert_eq!(outcome, UpdateOutcome::SystemManaged);
    assert_eq!(
        std::fs::read(target_path).expect("unchanged package binary"),
        b"unchanged"
    );
    assert_eq!(
        std::fs::read_dir(&directory.path)
            .expect("read Linux test directory")
            .count(),
        1
    );
}

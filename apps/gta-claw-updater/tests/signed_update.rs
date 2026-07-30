//! Local-only adversarial updater integration coverage.

#[cfg(not(windows))]
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(not(windows))]
use std::sync::{Arc, Mutex};

#[cfg(not(windows))]
use base64::Engine as _;
#[cfg(not(windows))]
use base64::engine::general_purpose::STANDARD;
#[cfg(not(windows))]
use ed25519_dalek::Signer as _;
use ed25519_dalek::SigningKey;
use gta_claw_updater::{
    ArtifactKind, InstallMode, InstallTarget, ReleaseArtifact, ReleaseManifest, UpdateOutcome,
    Updater,
};
#[cfg(not(windows))]
use gta_claw_updater::{AvailableUpdate, SignedManifest, UpdateDecision};
use semver::Version;
#[cfg(not(windows))]
use sha2::{Digest as _, Sha256};
#[cfg(not(windows))]
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
#[cfg(not(windows))]
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

#[cfg(not(windows))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct Request {
    path: String,
    range: Option<String>,
}

#[cfg(not(windows))]
struct ResponsePlan {
    status: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    write_bytes: usize,
}

#[cfg(not(windows))]
type Handler = Arc<dyn Fn(Request, usize) -> ResponsePlan + Send + Sync>;
#[cfg(not(windows))]
struct LocalServer {
    url: Url,
    requests: Arc<Mutex<Vec<Request>>>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(not(windows))]
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

#[cfg(not(windows))]
impl Drop for LocalServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(not(windows))]
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
        write!(response, "{name}: {value}\r\n").expect("format into String is infallible");
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

#[cfg(not(windows))]
fn handler<F>(handler: F) -> Handler
where
    F: Fn(Request, usize) -> ResponsePlan + Send + Sync + 'static,
{
    Arc::new(handler)
}

/// Lists the staging directory without the lock that serializes concurrent runs.
///
/// The lock is the staging directory's own mutex: it outlives every download
/// and install, so it is never part of what a run cleans up.
#[cfg(not(windows))]
fn staging_entries(stage: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(stage)
        .expect("read staging directory")
        .map(|entry| {
            entry
                .expect("staging entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name != "stage.lock")
        .collect();
    names.sort();
    names
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

#[cfg(not(windows))]
fn signed_bytes(manifest: ReleaseManifest) -> Vec<u8> {
    let canonical = serde_json::to_vec(&manifest).expect("canonical test manifest");
    let signature = signing_key().sign(&canonical);
    serde_json::to_vec(&SignedManifest {
        manifest,
        signature: STANDARD.encode(signature.to_bytes()),
    })
    .expect("signed envelope")
}

#[cfg(not(windows))]
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("format into String is infallible");
    }
    encoded
}

#[cfg(not(windows))]
fn artifact(url: &Url, bytes: &[u8], kind: ArtifactKind) -> ReleaseArtifact {
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

#[cfg(not(windows))]
fn executable_target(directory: &Path) -> InstallTarget {
    InstallTarget::new(directory.join("gta-claw.exe"), InstallMode::Executable)
        .expect("test executable target")
}

#[cfg(not(windows))]
fn authorized_update(updater: &Updater, artifact: &ReleaseArtifact) -> AvailableUpdate {
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
            assert_eq!(update.artifact(), artifact);
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

#[cfg(not(windows))]
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

#[cfg(not(windows))]
#[tokio::test]
async fn persists_anti_rollback_floor_and_enforces_expiry_and_revocation() {
    let directory = TestDir::new("anti-rollback");
    let release = artifact(
        &Url::parse("https://updates.example.invalid/gta-claw.exe").expect("artifact URL"),
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

#[cfg(not(windows))]
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
        &server.url("artifact"),
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
    let authorized_30 = match decision_30 {
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
        .download(&authorized_30, &target)
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

#[cfg(not(windows))]
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
    let release = artifact(&server.url("artifact"), &trusted, ArtifactKind::Executable);
    let target = executable_target(&directory.path);
    let updater = updater(&directory.path);
    let update = authorized_update(&updater, &release);
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
        staging_entries(&directory.path.join(".gta-claw.exe.gta-claw-stage")),
        Vec::<String>::new()
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn verified_stage_is_reused_without_redownload_and_cleaned_after_install() {
    let directory = TestDir::new("verified-reuse");
    let bytes = b"verified replacement bytes".to_vec();
    let response = bytes.clone();
    let server = LocalServer::spawn(handler(move |request, index| {
        assert_eq!(index, 1, "verified retry must not reach the network");
        assert_eq!(request.path, "/artifact");
        ResponsePlan {
            status: "200 OK",
            headers: Vec::new(),
            write_bytes: response.len(),
            body: response.clone(),
        }
    }))
    .await;
    let release = artifact(&server.url("artifact"), &bytes, ArtifactKind::Executable);
    let target = executable_target(&directory.path);
    std::fs::write(target.path(), b"old executable").expect("write old executable");
    let updater = updater(&directory.path);
    let update = authorized_update(&updater, &release);

    let first = updater
        .download(&update, &target)
        .await
        .expect("first verified download");
    let staged_path = first.path().to_owned();
    drop(first);
    let reused = updater
        .download(&update, &target)
        .await
        .expect("reuse verified stage");
    assert_eq!(reused.path(), staged_path);
    updater
        .install(reused, &target)
        .await
        .expect("install reused stage");

    assert_eq!(
        std::fs::read(target.path()).expect("read installed executable"),
        bytes
    );
    assert_eq!(server.requests.lock().expect("request log lock").len(), 1);
    assert_eq!(
        staging_entries(&directory.path.join(".gta-claw.exe.gta-claw-stage")),
        Vec::<String>::new(),
        "successful install must remove verified, partial, binding, and journal files"
    );
}

#[cfg(not(windows))]
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
    let first = artifact(&server.url("first"), &first_bytes, ArtifactKind::Executable);
    let updater = updater(&directory.path);
    let first_update = authorized_update(&updater, &first);
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
        &server.url("second"),
        &second_bytes,
        ArtifactKind::Executable,
    );
    second.release_sequence = 2;
    let second_update = authorized_update(&updater, &second);
    let verified = updater
        .download(&second_update, &target)
        .await
        .expect("different artifact starts from zero");
    assert_eq!(
        std::fs::read(verified.path()).expect("verified second artifact"),
        second_bytes
    );
}

#[cfg(not(windows))]
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
    let release = artifact(&server.url("artifact"), &bytes, ArtifactKind::Executable);
    let target = executable_target(&directory.path);
    let updater = updater(&directory.path);
    let update = authorized_update(&updater, &release);
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

#[cfg(not(windows))]
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
    let release = artifact(&server.url("artifact"), &bytes, ArtifactKind::Executable);
    let updater = updater(&directory.path);
    let update = authorized_update(&updater, &release);
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
#[test]
fn advancing_release_floor_prunes_obsolete_state_files() {
    let directory = TestDir::new("floor-cleanup");
    let updater = updater(&directory.path);
    let url = Url::parse("http://127.0.0.1/artifact").expect("loopback URL");
    let release = artifact(&url, b"release", ArtifactKind::Executable);
    let current = Version::parse("1.0.0").expect("current version");

    updater
        .check_manifest_bytes(
            &signed_bytes(manifest("2.0.0", 1, Vec::new(), vec![release.clone()])),
            &current,
        )
        .expect("accept first floor");
    updater
        .check_manifest_bytes(
            &signed_bytes(manifest("3.0.0", 2, Vec::new(), vec![release])),
            &current,
        )
        .expect("accept second floor");

    let state_root = directory.path.join("updater-state");
    let target_state = std::fs::read_dir(&state_root)
        .expect("read state root")
        .map(|entry| entry.expect("state entry").path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("target-"))
        })
        .expect("target state directory");
    let floors = std::fs::read_dir(target_state)
        .expect("read target state")
        .map(|entry| entry.expect("floor entry").file_name())
        .filter(|name| {
            name.to_str()
                .is_some_and(|name| name.starts_with("release-floor-"))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        floors,
        vec![std::ffi::OsString::from(
            "release-floor-00000000000000000002.json"
        )]
    );
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

/// A directory bundle is refused before any staging state exists.
///
/// Publishing a tree needs guarantees this crate does not have — the signed
/// archive hashed once and expanded from that same buffer, every nested
/// directory made durable, and a tree digest that separates shapes a flat walk
/// conflates. Rather than publish on weaker evidence than the executable path
/// gets, the bundle is refused at the boundary, and this asserts the refusal
/// leaves the existing installation and the filesystem untouched.
#[cfg(not(windows))]
#[tokio::test]
async fn a_directory_bundle_is_refused_before_anything_is_staged() {
    let directory = TestDir::new("bundle-refused");
    let target_path = directory.path.join("GTA Claw.app");
    std::fs::create_dir(&target_path).expect("create the existing bundle");
    std::fs::write(target_path.join("old.txt"), b"old").expect("write the existing bundle");
    let target =
        InstallTarget::new(target_path.clone(), InstallMode::MacOsBundle).expect("bundle target");
    let updater = updater(&directory.path);
    let bundle = artifact(
        &Url::parse("http://127.0.0.1:1/bundle").expect("bundle URL"),
        b"bundle",
        ArtifactKind::MacOsBundle,
    );
    let update = authorized_update(&updater, &bundle);

    let error = updater
        .download(&update, &target)
        .await
        .expect_err("a bundle cannot be installed by this crate");

    assert_eq!(
        error.to_string(),
        "this updater cannot install directory bundles safely"
    );
    assert!(
        !directory.path.join(".GTA Claw.app.gta-claw-stage").exists(),
        "refusing must precede creating the staging directory"
    );
    assert_eq!(
        std::fs::read(target_path.join("old.txt")).expect("the installation is untouched"),
        b"old"
    );
}

/// Discarded staging forces the next run to fetch and verify the release again.
///
/// This is the half of the restart contract that is observable from outside:
/// once the verified staging is gone, nothing on disk can stand in for a
/// download, so the updater goes back to the network and re-checks the
/// signature, size and digest of what it receives. An install that could be
/// completed from leftover bytes would be installing something no run of this
/// process ever verified against the release it is installing.
#[cfg(not(windows))]
#[tokio::test]
async fn discarded_staging_forces_a_fresh_verified_download() {
    let directory = TestDir::new("restart-redownload");
    let bytes = b"verified replacement payload".to_vec();
    let response = bytes.clone();
    let server = LocalServer::spawn(handler(move |_request, _index| ResponsePlan {
        status: "200 OK",
        headers: Vec::new(),
        body: response.clone(),
        write_bytes: response.len(),
    }))
    .await;
    let release = artifact(&server.url("artifact"), &bytes, ArtifactKind::Executable);
    let target = executable_target(&directory.path);
    std::fs::write(target.path(), b"old executable").expect("write old executable");
    let updater = updater(&directory.path);
    let update = authorized_update(&updater, &release);

    let first = updater
        .download(&update, &target)
        .await
        .expect("first verified download");
    drop(first);
    assert_eq!(server.requests.lock().expect("request log lock").len(), 1);

    // Stand in for the discard an interrupted install performs: everything a
    // rerun could resume from is gone.
    let stage = directory.path.join(".gta-claw.exe.gta-claw-stage");
    for name in ["artifact.verified", "artifact.part", "artifact.resume.json"] {
        let path = stage.join(name);
        if path.exists() {
            std::fs::remove_file(&path).expect("discard staged artifact");
        }
    }

    let refetched = updater
        .download(&update, &target)
        .await
        .expect("a discarded stage is downloaded again");
    updater
        .install(refetched, &target)
        .await
        .expect("install the freshly verified bytes");

    assert_eq!(
        server.requests.lock().expect("request log lock").len(),
        2,
        "a discarded stage must be fetched again, not reconstructed from disk"
    );
    assert_eq!(
        std::fs::read(target.path()).expect("read installed executable"),
        bytes,
        "only bytes this run verified may be installed"
    );
}

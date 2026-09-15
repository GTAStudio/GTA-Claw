//! Process-level Gateway health diagnostic coverage over a real WebSocket.

#[expect(
    dead_code,
    reason = "the Gateway test double is shared with claw-gateway-client, which owns the file; \
              this binary exercises only the subset the CLI diagnostic needs"
)]
#[path = "../../../crates/claw-gateway-client/tests/support/mod.rs"]
mod support;

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, ClientId, ClientMode, Codec, ConnectParams, RequestId,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::{Child, Command};
use tokio::sync::watch;

use support::{
    TestGateway, handler, receive_connect, receive_request, send_challenge, send_connect_error,
    send_json, send_raw_text, wait_for_close,
};

const TOKEN: &str = "stdin-only-diagnostic-token";
const TOKEN_WRAPPED: &str = "prefix-stdin-only-diagnostic-token-suffix";

#[cfg(windows)]
struct ProfileCleanup {
    endpoint: String,
    alias: String,
    root: PathBuf,
}

#[cfg(windows)]
impl Drop for ProfileCleanup {
    fn drop(&mut self) {
        if let Ok(store) = claw_platform::identity::native_store()
            && let Ok(profile) = claw_platform::identity::DeviceProfile::new(
                &self.endpoint,
                &self.alias,
                self.root.join("gta-claw-device-locks-v1"),
            )
        {
            let _ = profile.forget(store.as_ref());
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_memory_encrypted_export_collects_approved_pages_and_never_publishes_bad_data() {
    const PASSPHRASE: &str = "fixture archive passphrase only";
    let archive = json!({"schemaVersion":1,"notebook":{"revision":7,"entries":[{"id":"Note","kind":"fact","content":format!("private-archive-marker {}", "\u{4e2d}\u{6587}".repeat(1_000)),"sourceSession":"source-session","revision":7}]}}).to_string();
    let digest = |bytes: &[u8]| {
        use std::fmt::Write as _;
        let mut text = String::with_capacity(64);
        for byte in ring::digest::digest(&ring::digest::SHA256, bytes).as_ref() {
            write!(text, "{byte:02x}").expect("string write");
        }
        text
    };
    let sha256 = digest(archive.as_bytes());
    let mut pages = Vec::new();
    let mut offset = 0;
    while offset < archive.len() {
        let mut end = archive.len().min(offset + 2_048);
        while !archive.is_char_boundary(end) {
            end -= 1;
        }
        pages.push(json!({"archiveSchemaVersion":1,"notebookRevision":7,"sha256":sha256,"totalBytes":archive.len(),"offset":offset,"data":&archive[offset..end],"nextOffset":(end < archive.len()).then_some(end),"plaintext":true,"untrustedContent":true,"grantsAuthority":false}));
        offset = end;
    }
    for mode in [
        "valid",
        "tampered",
        "revision-changed",
        "wrong-run",
        "timeout",
        "existing-target",
        "unsupported",
    ] {
        let submitted = Arc::new(AtomicUsize::new(0));
        let captured = Arc::clone(&submitted);
        let server_pages = pages.clone();
        let server_archive = archive.clone();
        let gateway = TestGateway::spawn(handler(move |mut socket, connection_index| {
            let submitted = Arc::clone(&captured);
            let pages = server_pages.clone();
            let archive = server_archive.clone();
            async move {
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                support::verify_connect_proof(&params);
                assert_eq!(serde_json::to_value(&params).expect("handshake")["auth"]["token"], TOKEN);
                send_hello(&mut socket, connect.id(), "archive-native-fixture", 4, AUTHENTICATED_MAX_FRAME_BYTES, "operator", &["operator.read", "operator.write"]).await;
                if mode == "valid" && connection_index == 1 {
                    let health = receive_request(&mut socket).await;
                    assert_eq!(health.method().as_str(), "health");
                    send_json(&mut socket, json!({"type":"res","id":health.id().as_str(),"ok":true,"payload":{"ok":true,"protocol":4,"native":{"schemaVersion":1,"directTool":{"version":1,"prefix":"!tool ","modelInvoked":false,"authenticated":true,"durableRuns":true,"approvalPolicy":"per-tool","accepting":true},"explicitMemory":{"enabled":true,"accepting":true,"requiresApproval":true,"partition":"source/subject/account","automaticContextInjection":false,"archiveSchemaVersion":1}}}})).await;
                    let request = receive_request(&mut socket).await;
                    assert_eq!(request.method().as_str(), "chat.send");
                    let params: Value = serde_json::from_str(request.params().value().expect("import parameters").as_json()).expect("JSON");
                    assert_eq!(params["idempotencyKey"], "archive-import-key");
                    let envelope: Value = serde_json::from_str(params["message"].as_str().expect("import message").strip_prefix("!tool ").expect("direct prefix")).expect("envelope");
                    assert_eq!(envelope, json!({"name":"memory_notes","arguments":{"action":"import","expectedRevision":7,"overwrite":true,"archive":serde_json::from_str::<Value>(&archive).expect("original archive")}}));
                    submitted.fetch_add(1, Ordering::SeqCst);
                    send_json(&mut socket, json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":{"status":"accepted","durable":true,"sessionId":"memory-export-session","runId":"b".repeat(64),"revision":1,"phase":"queued"}})).await;
                    wait_for_close(&mut socket).await;
                    return;
                }
                for (index, page) in pages.into_iter().enumerate() {
                    let health = receive_request(&mut socket).await;
                    assert_eq!(health.method().as_str(), "health");
                    let capabilities = if mode == "unsupported" { json!({"ok":true,"protocol":4}) } else { json!({"ok":true,"protocol":4,"native":{"schemaVersion":1,"directTool":{"version":1,"prefix":"!tool ","modelInvoked":false,"authenticated":true,"durableRuns":true,"approvalPolicy":"per-tool","accepting":true},"explicitMemory":{"enabled":true,"accepting":true,"requiresApproval":true,"partition":"source/subject/account","automaticContextInjection":false,"archiveSchemaVersion":1}}}) };
                    send_json(&mut socket, json!({"type":"res","id":health.id().as_str(),"ok":true,"payload":capabilities})).await;
                    if mode == "unsupported" { break; }
                    let request = receive_request(&mut socket).await;
                    assert_eq!(request.method().as_str(), "chat.send");
                    let params: Value = serde_json::from_str(request.params().value().expect("params").as_json()).expect("JSON");
                    let expected_key = if index == 0 { "archive-original-key".to_owned() } else { format!("memory-export-{}", digest(json!(["memory-export/v1", "archive-original-key", "memory-export-session", 7, page["offset"]]).to_string().as_bytes())) };
                    assert_eq!(params["idempotencyKey"], expected_key);
                    assert_eq!(params["sessionKey"], "memory-export-session");
                    let envelope: Value = serde_json::from_str(params["message"].as_str().expect("direct message").strip_prefix("!tool ").expect("direct prefix")).expect("tool envelope");
                    assert_eq!(envelope, json!({"name":"memory_notes","arguments":{"action":"export","revision":7,"offset":page["offset"]}}));
                    submitted.fetch_add(1, Ordering::SeqCst);
                    let run_id = format!("{:064x}", index + 1);
                    send_json(&mut socket, json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":{"durable":true,"sessionId":"memory-export-session","runId":run_id,"status":"accepted","revision":1,"phase":"executing"}})).await;
                    let waiting = receive_request(&mut socket).await;
                    assert_eq!(waiting.method().as_str(), "agent.wait");
                    send_json(&mut socket, json!({"type":"res","id":waiting.id().as_str(),"ok":true,"payload":{"durable":true,"sessionId":"memory-export-session","runId":run_id,"revision":2,"phase":"executing","result":null}})).await;
                    if mode == "timeout" { break; }
                    send_json(&mut socket, json!({"type":"event","event":"chat","seq":index + 1,"payload":{"sessionId":"memory-export-session","runId":run_id,"resultAvailable":true}})).await;
                    let complete = receive_request(&mut socket).await;
                    assert_eq!(complete.method().as_str(), "agent.wait");
                    assert_ne!(waiting.id(), complete.id());
                    let mut page = page;
                    if mode == "tampered" { page["sha256"] = json!("0".repeat(64)); }
                    if mode == "revision-changed" && index == 1 { page["notebookRevision"] = json!(8); }
                    send_json(&mut socket, json!({"type":"res","id":complete.id().as_str(),"ok":true,"payload":{"durable":true,"sessionId":"memory-export-session","runId":if mode == "wrong-run" { "f".repeat(64) } else { run_id },"revision":3,"phase":"finished","result":{"status":"completed","text":page.to_string()}}})).await;
                    if mode == "wrong-run" || mode == "revision-changed" && index == 1 { break; }
                }
                loop {
                    match socket.read_frame().await {
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => { submitted.fetch_add(1, Ordering::SeqCst); }
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        })).await;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let cleanup = ProfileCleanup {
            endpoint: gateway.url.as_str().to_owned(),
            alias: format!("archive-{}-{nonce}", std::process::id()),
            root: std::env::temp_dir()
                .join(format!("claw-cli-archive-{}-{nonce}", std::process::id())),
        };
        fs::create_dir_all(&cleanup.root).expect("owned archive root");
        let destination = cleanup.root.join("memory.age");
        if mode == "existing-target" {
            fs::write(&destination, b"existing target must survive").expect("existing target");
        }
        let arguments = vec![
            "gateway".into(),
            "memory".into(),
            "export".into(),
            "memory-export-session".into(),
            "--revision".into(),
            "7".into(),
            "--device-profile".into(),
            cleanup.alias.clone().into(),
            "--idempotency-key".into(),
            "archive-original-key".into(),
            "--endpoint".into(),
            gateway.url.as_str().trim_end_matches('/').into(),
            "--destination".into(),
            destination.clone().into_os_string(),
            "--request-stdin".into(),
            "--timeout-ms".into(),
            if mode == "timeout" { "1000" } else { "5000" }.into(),
        ];
        let output = run_cli_in(
            arguments,
            Some(&json!({"token":TOKEN,"passphrase":PASSPHRASE}).to_string()),
            Some(&cleanup.root),
        )
        .await;
        let document = parse_json(&output);
        assert_eq!(
            output.status.success(),
            mode == "valid",
            "{mode}: {document}"
        );
        assert_eq!(document["operation"], "memory.export_file");
        assert_eq!(document["originalIdempotencyKey"], "archive-original-key");
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(
                !text.contains(TOKEN)
                    && !text.contains(PASSPHRASE)
                    && !text.contains("private-archive-marker")
            );
        }
        if mode == "valid" {
            assert_eq!(document["result"]["archiveValidated"], true);
            assert_eq!(document["result"]["fileCreated"], true);
            assert_eq!(document["result"]["sha256"], sha256);
            assert_eq!(document["result"]["pages"], pages.len());
            let ciphertext = fs::read(&destination).expect("encrypted archive exists");
            assert!(ciphertext.starts_with(b"age-encryption.org/v1\n"));
            assert!(
                !ciphertext
                    .windows(b"private-archive-marker".len())
                    .any(|bytes| bytes == b"private-archive-marker")
            );
            let decryptor = age::Decryptor::new(ciphertext.as_slice()).expect("age header");
            let mut identity =
                age::scrypt::Identity::new(age::secrecy::SecretString::from(PASSPHRASE.to_owned()));
            identity.set_max_work_factor(18);
            let mut decrypted = decryptor
                .decrypt(std::iter::once(&identity as &dyn age::Identity))
                .expect("independent age decryption");
            let mut plaintext = Vec::new();
            std::io::Read::read_to_end(&mut decrypted, &mut plaintext)
                .expect("authenticated plaintext");
            assert_eq!(plaintext, archive.as_bytes());
            let import_arguments = |source: &std::path::Path| {
                vec![
                    "gateway".into(),
                    "memory".into(),
                    "import".into(),
                    "memory-export-session".into(),
                    "--expected-revision".into(),
                    "7".into(),
                    "--overwrite".into(),
                    "--device-profile".into(),
                    cleanup.alias.clone().into(),
                    "--idempotency-key".into(),
                    "archive-import-key".into(),
                    "--endpoint".into(),
                    gateway.url.as_str().trim_end_matches('/').into(),
                    "--archive-file".into(),
                    source.to_path_buf().into_os_string(),
                    "--request-stdin".into(),
                    "--timeout-ms".into(),
                    "5000".into(),
                ]
            };
            let tampered_file = cleanup.root.join("tampered.age");
            let mut tampered = ciphertext.clone();
            *tampered.last_mut().expect("encrypted payload") ^= 1;
            fs::write(&tampered_file, tampered).expect("owned corrupt fixture");
            let oversized_file = cleanup.root.join("oversized.age");
            fs::File::create(&oversized_file)
                .expect("owned oversized fixture")
                .set_len(4 * 1024 * 1024 + 128 * 1024 + 1)
                .expect("bounded oversized length");
            for (source, passphrase) in [
                (&destination, "wrong fixture passphrase only"),
                (&tampered_file, PASSPHRASE),
                (&oversized_file, PASSPHRASE),
            ] {
                let output = run_cli_in(
                    import_arguments(source),
                    Some(&json!({"token":TOKEN,"passphrase":passphrase}).to_string()),
                    Some(&cleanup.root),
                )
                .await;
                let document = parse_json(&output);
                assert!(!output.status.success());
                assert_eq!(document["operation"], "memory.import_file");
                assert_eq!(document["delivery"], "not_sent");
                assert_eq!(
                    gateway.connections.load(Ordering::SeqCst),
                    1,
                    "bad archive must be refused before connecting"
                );
            }
            let output = run_cli_in(
                import_arguments(&destination),
                Some(&json!({"token":TOKEN,"passphrase":PASSPHRASE}).to_string()),
                Some(&cleanup.root),
            )
            .await;
            let document = parse_json(&output);
            assert!(output.status.success(), "encrypted import: {document}");
            assert_eq!(document["operation"], "memory.import_file");
            assert_eq!(document["sourceModified"], false);
            assert_eq!(document["result"]["durable"], true);
            for bytes in [&output.stdout, &output.stderr] {
                let text = String::from_utf8_lossy(bytes);
                assert!(
                    !text.contains(TOKEN)
                        && !text.contains(PASSPHRASE)
                        && !text.contains("private-archive-marker")
                );
            }
            assert_eq!(
                fs::read(&destination).expect("unchanged encrypted source"),
                ciphertext
            );
        } else if mode == "existing-target" {
            assert_eq!(
                fs::read(&destination).expect("retained target"),
                b"existing target must survive"
            );
        } else {
            assert!(!destination.exists(), "{mode} must not publish an archive");
        }
        let expected = match mode {
            "valid" => pages.len() + 1,
            "unsupported" => 0,
            "wrong-run" | "timeout" => 1,
            "revision-changed" => 2,
            _ => pages.len(),
        };
        assert_eq!(submitted.load(Ordering::SeqCst), expected, "{mode}");
        gateway.shutdown().await;
        drop(cleanup);
    }
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_memory_commands_verify_capabilities_before_sending_once() {
    const ARCHIVE: &str = r#"{"schemaVersion":1,"notebook":{"revision":2,"entries":[{"id":"units","kind":"preference","content":"private-cli-memory import","sourceSession":"source","revision":1}]}}"#;
    for mode in [
        "list",
        "save",
        "save-auth",
        "export",
        "import",
        "import-auth",
        "archive-missing",
        "unsupported",
        "disabled",
        "model",
        "bad-receipt",
    ] {
        let submissions = Arc::new(AtomicUsize::new(0));
        let submitted = Arc::clone(&submissions);
        let permitted = matches!(
            mode,
            "list" | "save" | "save-auth" | "export" | "import" | "import-auth" | "bad-receipt"
        );
        let framed = matches!(mode, "save-auth" | "import-auth");
        let action = match mode {
            "save" | "save-auth" => "save",
            "export" => "export",
            "import" | "import-auth" | "archive-missing" => "import",
            _ => "list",
        };
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let submitted = Arc::clone(&submitted);
            async move {
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                support::verify_connect_proof(&params);
                let handshake = serde_json::to_value(&params).expect("handshake JSON");
                assert_eq!(handshake["auth"]["token"], if framed { json!(TOKEN) } else { Value::Null });
                let scopes: Vec<_> = params.scopes.as_ref().expect("memory scopes").iter().map(claw_protocol::gateway::Name::as_str).collect();
                assert_eq!(scopes, ["operator.read", "operator.write"]);
                send_hello(&mut socket, connect.id(), "memory-native-fixture", 4, AUTHENTICATED_MAX_FRAME_BYTES, "operator", &["operator.read", "operator.write"]).await;
                let health = receive_request(&mut socket).await;
                assert_eq!(health.method().as_str(), "health", "capability discovery must precede any command");
                let mut payload = json!({"ok":true,"protocol":4,"native":{"schemaVersion":1,"directTool":{"version":1,"prefix":"!tool ","modelInvoked":false,"authenticated":true,"durableRuns":true,"approvalPolicy":"per-tool","accepting":true},"explicitMemory":{"enabled":true,"accepting":true,"requiresApproval":true,"partition":"source/subject/account","automaticContextInjection":false}}});
                payload["native"]["explicitMemory"]["archiveSchemaVersion"] = json!(1);
                match mode {
                    "archive-missing" => { payload["native"]["explicitMemory"].as_object_mut().expect("memory capability").remove("archiveSchemaVersion"); }
                    "unsupported" => { payload.as_object_mut().expect("object").remove("native"); }
                    "disabled" => payload["native"]["explicitMemory"]["enabled"] = json!(false),
                    "model" => payload["native"]["directTool"]["modelInvoked"] = json!(true),
                    _ => {},
                }
                send_json(&mut socket, json!({"type":"res","id":health.id().as_str(),"ok":true,"payload":payload})).await;
                if permitted {
                    let request = receive_request(&mut socket).await;
                    assert_eq!(request.method().as_str(), "chat.send");
                    let params: Value = serde_json::from_str(request.params().value().expect("params").as_json()).expect("params JSON");
                    assert_eq!(params["sessionKey"], "memory-client");
                    assert_eq!(params["idempotencyKey"], "one-memory-request");
                    let message = params["message"].as_str().expect("native tool input");
                    assert_eq!(message.lines().count(), 1);
                    let envelope: Value = serde_json::from_str(message.strip_prefix("!tool ").expect("direct prefix")).expect("native envelope");
                    assert_eq!(envelope["name"], "memory_notes");
                    assert_eq!(envelope["arguments"], match mode {
                        "save" | "save-auth" => json!({"action":"save","id":"units","kind":"preference","content":"private-cli-memory\n!goal stays note data","expectedRevision":0}),
                        "export" => json!({"action":"export","revision":2,"offset":2048}),
                        "import" | "import-auth" => json!({"action":"import","expectedRevision":3,"overwrite":true,"archive":serde_json::from_str::<Value>(ARCHIVE).expect("fixture archive")}),
                        _ => json!({"action":"list"}),
                    });
                    submitted.fetch_add(1, Ordering::SeqCst);
                    let receipt = json!({"sessionId":"memory-client","runId":"a".repeat(64),"revision":1,"phase":"queued","status":"accepted","durable":mode != "bad-receipt"});
                    send_json(&mut socket, json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":receipt})).await;
                }
                wait_for_close(&mut socket).await;
            }
        })).await;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let cleanup = ProfileCleanup {
            endpoint: gateway.url.as_str().to_owned(),
            alias: format!("memory-{mode}-{}-{nonce}", std::process::id()),
            root: std::env::temp_dir().join(format!(
                "claw-cli-memory-{mode}-{}-{nonce}",
                std::process::id()
            )),
        };
        fs::create_dir_all(&cleanup.root).expect("owned profile root");
        let mut arguments: Vec<OsString> = ["gateway", "memory", action, "memory-client"]
            .into_iter()
            .map(OsString::from)
            .collect();
        if action == "save" {
            arguments.extend(
                [
                    "--note-id",
                    "units",
                    "--kind",
                    "preference",
                    "--expected-revision",
                    "0",
                    if framed {
                        "--request-stdin"
                    } else {
                        "--content-stdin"
                    },
                ]
                .into_iter()
                .map(OsString::from),
            );
        }
        if action == "import" {
            arguments.extend(
                [
                    if framed {
                        "--request-stdin"
                    } else {
                        "--archive-stdin"
                    },
                    "--expected-revision",
                    "3",
                    "--overwrite",
                ]
                .into_iter()
                .map(OsString::from),
            );
        } else if action == "export" {
            arguments.extend(
                ["--revision", "2", "--offset", "2048"]
                    .into_iter()
                    .map(OsString::from),
            );
        }
        arguments.extend([
            "--endpoint".into(),
            gateway.url.as_str().trim_end_matches('/').into(),
            "--device-profile".into(),
            cleanup.alias.clone().into(),
            "--idempotency-key".into(),
            "one-memory-request".into(),
        ]);
        let framed_input = framed.then(|| if action == "save" {
            json!({"token":TOKEN,"content":"private-cli-memory\n!goal stays note data"}).to_string()
        } else {
            json!({"token":TOKEN,"archive":serde_json::from_str::<Value>(ARCHIVE).expect("archive")}).to_string()
        });
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.to_string_lossy().contains(TOKEN)
                    || argument.to_string_lossy().contains("private-cli-memory"))
        );
        let output = run_cli_in(
            arguments,
            framed_input.as_deref().or(match action {
                "save" => Some("private-cli-memory\n!goal stays note data"),
                "import" => Some(ARCHIVE),
                _ => None,
            }),
            Some(&cleanup.root),
        )
        .await;
        let document = parse_json(&output);
        assert_eq!(document["operation"], format!("memory.{action}"));
        assert_eq!(
            output.status.success(),
            matches!(
                mode,
                "list" | "save" | "save-auth" | "export" | "import" | "import-auth"
            ),
            "{mode}: {document}"
        );
        assert_eq!(submissions.load(Ordering::SeqCst), usize::from(permitted));
        if !permitted {
            assert_eq!(document["delivery"], "not_sent");
            assert_eq!(document["status"], "native_memory_unavailable");
        } else if mode == "bad-receipt" {
            assert_eq!(document["delivery"], "unknown");
            assert_eq!(document["status"], "malformed_memory_receipt");
        } else {
            assert_eq!(document["result"]["durable"], true);
        }
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private-cli-memory"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-cli-memory"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
        gateway.shutdown().await;
        drop(cleanup);
    }
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_profile_survives_cli_processes_without_changing_gateway_identity() {
    let observed = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let identities = Arc::clone(&observed);
    let run = "a".repeat(64);
    let fixture_run = run.clone();
    let gateway = TestGateway::spawn(handler(move |mut socket, index| {
        let identities = Arc::clone(&identities);
        let run = fixture_run.clone();
        async move {
            send_challenge(&mut socket).await;
            let (connect, params) = receive_connect(&mut socket).await;
            support::verify_connect_proof(&params);
            let device = serde_json::to_value(&params).expect("handshake")["device"]["id"].as_str().expect("device identity").to_owned();
            identities.lock().expect("identity list").push(device);
            let scope = if index == 0 { "operator.write" } else { "operator.read" };
            send_hello(&mut socket, connect.id(), "persistent-native-fixture", 4, AUTHENTICATED_MAX_FRAME_BYTES, "operator", &[scope]).await;
            let request = receive_request(&mut socket).await;
            assert_eq!(request.method().as_str(), if index == 0 { "chat.send" } else { "agent.wait" });
            let result = if index == 0 { json!({"runId": run, "status": "accepted", "durable": true}) } else { json!({"runId": run, "phase": "finished", "result": {"status": "completed", "text": "retained result"}, "durable": true}) };
            send_json(&mut socket, json!({"type": "res", "id": request.id().as_str(), "ok": true, "payload": result})).await;
            wait_for_close(&mut socket).await;
        }
    })).await;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let cleanup = ProfileCleanup {
        endpoint: gateway.url.as_str().to_owned(),
        alias: format!("test-{}-{nonce}", std::process::id()),
        root: std::env::temp_dir().join(format!("claw-cli-profile-{}-{nonce}", std::process::id())),
    };
    fs::create_dir_all(&cleanup.root).expect("isolated profile coordination root");
    let options = || {
        vec![
            "--endpoint".into(),
            gateway.url.as_str().trim_end_matches('/').into(),
            "--device-profile".into(),
            cleanup.alias.clone().into(),
            "--token-stdin".into(),
        ]
    };
    for mut arguments in [
        vec![
            "send".into(),
            "profile-session".into(),
            "first request".into(),
            "--idempotency-key".into(),
            "message-one".into(),
        ],
        vec!["gateway".into(), "run".into(), run.into()],
    ] {
        arguments.extend(options());
        let output = run_cli_in(arguments, Some(TOKEN), Some(&cleanup.root)).await;
        assert!(
            output.status.success(),
            "profile command: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(parse_json(&output)["result"]["durable"], true);
    }
    let captured = observed.lock().expect("captured identities").clone();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0], captured[1]);
    let mut forget = vec!["gateway".into(), "forget-device".into()];
    forget.extend(
        options()
            .into_iter()
            .filter(|argument: &OsString| argument != "--token-stdin"),
    );
    let output = run_cli_in(forget, None, Some(&cleanup.root)).await;
    assert!(output.status.success());
    assert_eq!(parse_json(&output)["result"]["removed"], true);
    assert_eq!(parse_json(&output)["result"]["remoteGrantsRevoked"], false);
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_business_commands_use_real_rpc_and_the_minimum_exact_scope() {
    let baseline = Arc::new(
        claw_conformance::ReleaseBaseline::load(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../compat/releases/v2026.9.4"),
        )
        .expect("reviewed candidate request schemas"),
    );
    let cases = [
        (
            vec![
                "gateway",
                "run",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--wait-ms",
                "1000",
            ],
            "agent.wait",
            "operator.read",
            json!({"runId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "timeoutMs": 1000}),
            json!({"phase": "finished", "result": {"status": "completed", "text": "durable result"}, "revision": 4}),
        ),
        (
            vec![
                "gateway",
                "ack-run",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "4",
            ],
            "agent.wait",
            "operator.read",
            json!({"runId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "acknowledgeRevision": 4}),
            json!({"acknowledged": true}),
        ),
        (
            vec![
                "gateway",
                "partial-run",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "4",
            ],
            "agent.wait",
            "operator.read",
            json!({"runId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","partialPage":{"revision":4,"offset":0}}),
            json!({"runId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sessionId":"owned-session","revision":4,"turn":0,"status":"outcome_unknown","durable":true,"acknowledged":false,"automaticReplay":false,
                "partial":{"available":true,"text":"abc","offset":0,"nextOffset":null,"totalBytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","messageComplete":false,"untrusted":true,"reasoningIncluded":false,"toolArgumentsIncluded":false}}),
        ),
        (
            vec![
                "gateway",
                "partial-run",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "4",
                "--offset",
                "2048",
                "--sha256",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
            "agent.wait",
            "operator.read",
            json!({"runId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","partialPage":{"revision":4,"offset":2048,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}),
            json!({"runId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sessionId":"owned-session","revision":4,"turn":0,"status":"outcome_unknown","durable":true,"acknowledged":false,"automaticReplay":false,
                "partial":{"available":true,"text":"last","offset":2048,"nextOffset":null,"totalBytes":2052,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","messageComplete":false,"untrusted":true,"reasoningIncluded":false,"toolArgumentsIncluded":false}}),
        ),
        (
            vec!["gateway", "results", "native-session"],
            "sessions.get",
            "operator.read",
            json!({"sessionKey": "native-session"}),
            json!({"pendingRuns": [], "nextCursor": null}),
        ),
        (
            vec!["gateway", "sessions"],
            "sessions.list",
            "operator.read",
            json!({}),
            json!({"sessions": []}),
        ),
        (
            vec!["gateway", "history", "native-session"],
            "chat.history",
            "operator.read",
            json!({"sessionKey": "native-session"}),
            json!({"messages": [{"role": "user", "text": "stored history"}]}),
        ),
        (
            vec!["gateway", "describe", "native-session"],
            "sessions.describe",
            "operator.read",
            json!({"key":"native-session"}),
            json!({"session":{"key":"native-session","state":"completed"},"durable":true,"contentIncluded":false}),
        ),
        (
            vec!["gateway", "history", "native-session", "--limit", "1"],
            "chat.history",
            "operator.read",
            json!({"sessionKey": "native-session", "limit": 1}),
            json!({"messages": [{"role": "assistant", "text": "latest entry"}], "windowLimit": 1}),
        ),
        (
            vec!["gateway", "abort", "native-session"],
            "chat.abort",
            "operator.write",
            json!({"sessionKey": "native-session"}),
            json!({"aborted": true}),
        ),
        (
            vec!["gateway", "approvals", "native-session"],
            "exec.approval.list",
            "operator.approvals",
            json!({"sessionId": "native-session"}),
            json!({"requests": [], "nextCursor": null}),
        ),
        (
            vec!["gateway", "approval", "approval-1"],
            "exec.approval.get",
            "operator.approvals",
            json!({"id": "approval-1"}),
            json!({"id": "approval-1", "prompt": "safe preview", "previewComplete": true}),
        ),
        (
            vec!["gateway", "approve", "approval-1"],
            "exec.approval.resolve",
            "operator.approvals",
            json!({"id": "approval-1", "decision": "approve"}),
            json!({"ok": true, "scope": "once"}),
        ),
        (
            vec!["gateway", "deny", "approval-1"],
            "exec.approval.resolve",
            "operator.approvals",
            json!({"id": "approval-1", "decision": "deny"}),
            json!({"ok": true, "scope": "once"}),
        ),
        (
            vec![
                "send",
                "native-session",
                "native message",
                "--idempotency-key",
                "once-1",
            ],
            "chat.send",
            "operator.write",
            json!({"sessionKey": "native-session", "message": "native message", "idempotencyKey": "once-1"}),
            json!({"runId": "server-run", "status": "accepted", "durable": false}),
        ),
    ];
    for (arguments, method, scope, expected, result) in cases {
        let returned = result.clone();
        let baseline = Arc::clone(&baseline);
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let mut expected = expected.clone();
            let result = result.clone();
            let baseline = Arc::clone(&baseline);
            async move {
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                support::verify_connect_proof(&params);
                let scopes: Vec<_> = params.scopes.as_ref().expect("requested scopes").iter().map(claw_protocol::gateway::Name::as_str).collect();
                assert_eq!(scopes, [scope]);
                send_hello(&mut socket, connect.id(), "native-fixture", 4, AUTHENTICATED_MAX_FRAME_BYTES, "operator", &[scope]).await;
                if method == "exec.approval.resolve" {
                    let preview = receive_request(&mut socket).await;
                    assert_eq!(preview.method().as_str(), "exec.approval.get");
                    let token = "b".repeat(64);
                    let fingerprint = claw_security::authorization::approval_preview_fingerprint(&token).expect("fixture fingerprint");
                    let mut payload = json!({"id": expected["id"], "sessionId": "native-session", "tool": "fs_write", "previewComplete": true, "bindingToken": token, "previewFingerprint": fingerprint,
                        "toolPublication": "workspace-fixture", "toolRevision": 1, "resourceScope": "workspace: reviewed.txt",
                        "caller": {"source": "Http", "subject": "verified-device", "account": null, "permissionGeneration": 0, "owner": true}});
                    payload["prompt"] = json!(format!("{}fs_write\n{{}}", claw_protocol::native_approval::bound_approval_context_header(&payload).expect("context")));
                    send_json(&mut socket, json!({"type": "res", "id": preview.id().as_str(), "ok": true, "payload": payload})).await;
                    expected["bindingToken"] = json!(token);
                }
                let request = receive_request(&mut socket).await;
                assert_eq!(request.method().as_str(), method);
                let actual: Value = serde_json::from_str(request.params().value().expect("params").as_json()).expect("request JSON");
                assert_eq!(actual, expected);
                if method == "agent.wait" && (actual.get("acknowledgeRevision").is_some() || actual.get("partialPage").is_some()) {
                    assert!(baseline.validate_gateway_request(method, &actual).is_err(), "native ACK and partial paging remain distinct extensions");
                } else if matches!(method, "chat.send" | "chat.abort" | "chat.history" | "agent.wait" | "sessions.describe") {
                    baseline.validate_gateway_request(method, &actual).expect("actual CLI request matches reviewed upstream parameters");
                }
                send_json(&mut socket, json!({"type": "res", "id": request.id().as_str(), "ok": true, "payload": result})).await;
                wait_for_close(&mut socket).await;
            }
        })).await;
        let mut args: Vec<OsString> = arguments.into_iter().map(OsString::from).collect();
        if method == "exec.approval.resolve" {
            args.extend([
                "--preview-fingerprint".into(),
                claw_security::authorization::approval_preview_fingerprint(&"b".repeat(64))
                    .expect("fixture fingerprint")
                    .into(),
            ]);
        }
        args.extend(gateway_arguments(gateway.url.as_str()).into_iter().skip(2));
        let output = run_cli(args, Some(TOKEN)).await;
        assert!(
            output.status.success(),
            "native CLI failed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let document: Value = serde_json::from_slice(&output.stdout).expect("pure JSON stdout");
        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["method"], method);
        assert_eq!(document["result"], returned);
        assert_eq!(document["shutdown_clean"], true);
        assert!(output.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
        gateway.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_export_cli_collects_verified_pages_without_ack_or_overwriting_files() {
    use std::fmt::Write as _;

    for mode in [
        "valid",
        "empty",
        "corrupt",
        "identity-changed",
        "disconnect",
        "existing-target",
        "absent",
    ] {
        let text = if mode == "empty" {
            String::new()
        } else {
            format!(
                "{}\u{754c}private-partial-must-not-render",
                "x".repeat(2047)
            )
        };
        let mut sha256 = String::new();
        for byte in ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref() {
            write!(sha256, "{byte:02x}").expect("digest");
        }
        let first_end = text.len().min(2047);
        let mut pages = vec![
            json!({"runId":"a".repeat(64),"sessionId":"owned-session","revision":4,"turn":0,"status":"outcome_unknown","durable":true,"acknowledged":false,"automaticReplay":false,
            "partial":{"available":true,"text":&text[..first_end],"offset":0,"nextOffset":(first_end < text.len()).then_some(first_end),"totalBytes":text.len(),"sha256":sha256,"messageComplete":false,"untrusted":true,"reasoningIncluded":false,"toolArgumentsIncluded":false}}),
        ];
        if first_end < text.len() {
            let mut last = pages[0].clone();
            last["partial"]["text"] = json!(&text[first_end..]);
            last["partial"]["offset"] = json!(first_end);
            last["partial"]["nextOffset"] = Value::Null;
            if mode == "corrupt" {
                last["partial"]["text"] = json!("q".repeat(text.len() - first_end));
            }
            if mode == "identity-changed" {
                last["sessionId"] = json!("other-session");
            }
            pages.push(last);
        }
        if mode == "absent" {
            pages.truncate(1);
            pages[0]["turn"] = Value::Null;
            pages[0]["partial"] = json!({"available":false});
        }
        let expected_pages = pages.len();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let digest = sha256.clone();
        let gateway = TestGateway::spawn(handler(move |mut socket, connection| {
            let pages = pages.clone();
            let calls = Arc::clone(&observed);
            let digest = digest.clone();
            async move {
                assert_eq!(connection, 0, "export cannot reconnect");
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                support::verify_connect_proof(&params);
                let scopes: Vec<_> = params.scopes.as_ref().expect("scopes").iter().map(claw_protocol::gateway::Name::as_str).collect();
                assert_eq!(scopes, ["operator.read"]);
                send_hello(&mut socket, connect.id(), "partial-export-fixture", 4, AUTHENTICATED_MAX_FRAME_BYTES, "operator", &["operator.read"]).await;
                for (index, page) in pages.into_iter().enumerate() {
                    let request = receive_request(&mut socket).await;
                    calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(request.method().as_str(), "agent.wait");
                    let actual: Value = serde_json::from_str(request.params().value().expect("parameters").as_json()).expect("JSON");
                    let mut expected = json!({"runId":"a".repeat(64),"partialPage":{"revision":4,"offset":if index == 0 { 0 } else { first_end }}});
                    if index > 0 { expected["partialPage"]["sha256"] = json!(digest); }
                    assert_eq!(actual, expected, "no ACK, wait, or unrelated operation");
                    if mode == "disconnect" && index == 1 { return; }
                    send_json(&mut socket, json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":page})).await;
                }
                wait_for_close(&mut socket).await;
            }
        })).await;
        let destination = log_path(&format!("partial-export-{mode}-{}.txt", std::process::id()));
        if mode == "existing-target" {
            fs::write(&destination, b"keep-original-output").expect("owned existing file");
        }
        let mut arguments = vec![
            "gateway".into(),
            "export-partial".into(),
            "a".repeat(64).into(),
            "4".into(),
            "--destination".into(),
            destination.as_os_str().to_owned(),
        ];
        arguments.extend(gateway_arguments(gateway.url.as_str()).into_iter().skip(2));
        let output = run_cli(arguments, Some(TOKEN)).await;
        let success = matches!(mode, "valid" | "empty");
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let document = parse_json(&output);
        assert_eq!(document["operation"], "run.export_partial");
        assert_eq!(document["sourceModified"], false);
        assert_eq!(document["acknowledged"], false);
        assert_eq!(document["automaticReplay"], false);
        assert_eq!(calls.load(Ordering::SeqCst), expected_pages);
        if success {
            assert_eq!(
                fs::read(&destination).expect("verified file"),
                text.as_bytes()
            );
            assert_eq!(document["result"]["sha256"], sha256);
            assert_eq!(document["result"]["fileCreated"], true);
            assert_eq!(document["result"]["plaintext"], true);
            assert_eq!(document["result"]["messageComplete"], false);
        } else if mode == "existing-target" {
            assert_eq!(
                fs::read(&destination).expect("original file"),
                b"keep-original-output"
            );
        } else {
            assert!(
                !destination.exists(),
                "unverified export must create no target"
            );
            assert_eq!(document["fileMayExist"], false);
        }
        let stdout = String::from_utf8(output.stdout).expect("JSON output");
        assert!(!stdout.contains("private-partial-must-not-render"));
        assert!(!stdout.contains(TOKEN));
        assert!(output.stderr.is_empty());
        let _ = fs::remove_file(destination);
        gateway.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accounting_run_cli_verifies_pages_with_one_read_and_no_ack_or_replay() {
    use std::fmt::Write as _;
    for scenario in [
        "complete",
        "zero",
        "missing",
        "unreported",
        "journal",
        "continuation",
        "bad-digest",
        "bad-count",
        "extra-content",
    ] {
        let expected_success = !matches!(scenario, "bad-digest" | "bad-count" | "extra-content");
        let zero = matches!(scenario, "zero" | "unreported");
        let tokens = json!({"inputTokens":if zero {0} else {5},"outputTokens":if zero {0} else {2},"totalTokens":if zero {0} else {7},"cachedInputTokens":0,"reasoningTokens":0});
        let summary = json!({
            "available":true,"recordedRounds":1,"completeCounterRounds":u16::from(!matches!(scenario,"unreported" | "journal")),
            "partialCounterRounds":u16::from(scenario == "journal"),"unreportedRounds":u16::from(scenario == "unreported"),
            "allPrimaryCountersReported":!matches!(scenario,"unreported" | "journal"),"observedTokens":tokens,
            "aggregationOverflow":false,"costCalculated":false,"billingReconciled":false,
            "recordSource":"terminal_turn","attemptsMayBeUnsent":true,
        });
        let response = json!({"provider":"fixture","model":"untrusted-model-fixture","responseId":"synthetic-response",
            "usageReporting":if scenario == "journal" {"partial"} else {"complete"},"finishReason":"length","observedTokens":tokens});
        let mut snapshot = json!({"summary":summary,"rounds":[{"round":0,"response":if scenario == "unreported" {Value::Null} else {response.clone()}}]});
        if scenario == "journal" {
            snapshot["summary"]["recordSource"] = json!("provider_journal");
            snapshot["summary"]["journalRevision"] = json!(2);
            snapshot["summary"]["journalClosed"] = json!(false);
        } else if scenario == "continuation" {
            snapshot["summary"]["recordedRounds"] = json!(17);
            snapshot["summary"]["unreportedRounds"] = json!(16);
            snapshot["summary"]["allPrimaryCountersReported"] = json!(false);
            snapshot["rounds"] = json!((0..17).map(|round| json!({"round":round,"response":if round == 16 {response.clone()} else {Value::Null}})).collect::<Vec<_>>());
        }
        let mut digest = String::with_capacity(64);
        for byte in ring::digest::digest(
            &ring::digest::SHA256,
            &serde_json::to_vec(&snapshot).expect("snapshot"),
        )
        .as_ref()
        {
            write!(digest, "{byte:02x}").expect("digest");
        }
        let mut parameters =
            json!({"runId":"a".repeat(64),"accountingPage":{"revision":4,"offset":0}});
        let mut page = json!({
            "runId":"a".repeat(64),"sessionId":"owned-session","revision":4,"turn":0,"status":"outcome_unknown",
            "durable":true,"acknowledged":false,"automaticReplay":false,
            "accounting":{"available":true,"offset":0,"endOffset":1,"nextOffset":null,"totalRounds":1,"sha256":digest,"summary":snapshot["summary"],"rounds":snapshot["rounds"]},
        });
        if scenario == "missing" {
            page["accounting"] = json!({"available":false});
        } else if scenario == "continuation" {
            parameters["accountingPage"]["offset"] = json!(16);
            parameters["accountingPage"]["sha256"] = json!(digest);
            page["accounting"]["offset"] = json!(16);
            page["accounting"]["endOffset"] = json!(17);
            page["accounting"]["totalRounds"] = json!(17);
            page["accounting"]["rounds"] = json!([snapshot["rounds"][16]]);
        } else if scenario == "bad-digest" {
            page["accounting"]["sha256"] = json!("0".repeat(64));
        } else if scenario == "bad-count" {
            page["accounting"]["rounds"][0]["response"]["observedTokens"]["totalTokens"] = json!(8);
        } else if scenario == "extra-content" {
            page["accounting"]["rounds"][0]["response"]["prompt"] =
                json!("private-content-must-not-render");
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let captured = Arc::clone(&calls);
        let expected = parameters.clone();
        let returned = page.clone();
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let calls = Arc::clone(&captured);
            let expected = expected.clone();
            let page = page.clone();
            async move {
                send_challenge(&mut socket).await;
                let (connect, params) = receive_connect(&mut socket).await;
                support::verify_connect_proof(&params);
                assert_eq!(
                    params
                        .scopes
                        .as_ref()
                        .expect("requested scopes")
                        .iter()
                        .map(claw_protocol::gateway::Name::as_str)
                        .collect::<Vec<_>>(),
                    ["operator.read"]
                );
                send_hello(
                    &mut socket,
                    connect.id(),
                    "accounting-fixture",
                    4,
                    AUTHENTICATED_MAX_FRAME_BYTES,
                    "operator",
                    &["operator.read"],
                )
                .await;
                let request = receive_request(&mut socket).await;
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request.method().as_str(), "agent.wait");
                let actual: Value =
                    serde_json::from_str(request.params().value().expect("parameters").as_json())
                        .expect("request JSON");
                assert_eq!(actual, expected);
                send_json(
                    &mut socket,
                    json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":page}),
                )
                .await;
                loop {
                    match socket.read_frame().await {
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => {
                            calls.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        }))
        .await;
        let mut arguments: Vec<OsString> = ["gateway", "accounting-run", &"a".repeat(64), "4"]
            .into_iter()
            .map(OsString::from)
            .collect();
        if scenario == "continuation" {
            arguments.extend(
                ["--offset", "16", "--sha256", &digest]
                    .into_iter()
                    .map(OsString::from),
            );
        }
        arguments.extend(gateway_arguments(gateway.url.as_str()).into_iter().skip(2));
        let output = run_cli(arguments, Some(TOKEN)).await;
        assert_eq!(
            output.status.success(),
            expected_success,
            "{scenario}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let document: Value = serde_json::from_slice(&output.stdout).expect("pure JSON result");
        let stdout = String::from_utf8(output.stdout).expect("UTF8 JSON");
        if expected_success {
            assert_eq!(document["method"], "agent.wait");
            assert_eq!(document["result"], returned);
            assert_eq!(document["shutdown_clean"], true);
        } else {
            assert!(stdout.contains("invalid_accounting_page"));
            assert!(!stdout.contains("untrusted-model-fixture"));
            assert!(!stdout.contains("private-content-must-not-render"));
        }
        assert!(!stdout.contains(TOKEN));
        assert!(output.stderr.is_empty());
        gateway.shutdown().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{scenario}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_run_cli_rejects_corrupt_pages_without_rendering_their_text() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let gateway = TestGateway::spawn(handler(move |mut socket, _| {
        let observed = Arc::clone(&observed);
        async move {
            send_challenge(&mut socket).await;
            let (connect,params) = receive_connect(&mut socket).await;
            support::verify_connect_proof(&params);
            send_hello(&mut socket,connect.id(),"partial-fixture",4,AUTHENTICATED_MAX_FRAME_BYTES,"operator",&["operator.read"]).await;
            let request = receive_request(&mut socket).await;
            observed.fetch_add(1,Ordering::SeqCst);
            assert_eq!(request.method().as_str(),"agent.wait");
            let parameters: Value = serde_json::from_str(request.params().value().expect("page parameters").as_json()).expect("JSON request");
            assert_eq!(parameters,json!({"runId":"a".repeat(64),"partialPage":{"revision":4,"offset":0}}));
            send_json(&mut socket,json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":{
                "runId":"a".repeat(64),"sessionId":"owned-session","revision":4,"turn":0,"status":"outcome_unknown","durable":true,"acknowledged":false,"automaticReplay":false,
                "partial":{"available":true,"text":"private-page-must-not-render","offset":0,"nextOffset":null,"totalBytes":28,"sha256":"0".repeat(64),"messageComplete":false,"untrusted":true,"reasoningIncluded":false,"toolArgumentsIncluded":false}
            }})).await;
            wait_for_close(&mut socket).await;
        }
    })).await;
    let mut arguments = vec![
        "gateway".into(),
        "partial-run".into(),
        "a".repeat(64).into(),
        "4".into(),
    ];
    arguments.extend(gateway_arguments(gateway.url.as_str()).into_iter().skip(2));
    let output = run_cli(arguments, Some(TOKEN)).await;
    assert!(!output.status.success());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let document = String::from_utf8(output.stdout).expect("JSON output");
    assert!(document.contains("invalid_partial_page"));
    assert!(!document.contains("private-page-must-not-render"));
    assert!(!document.contains(TOKEN));
    assert!(output.stderr.is_empty());
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_commands_reject_overgrants_and_never_echo_remote_error_secrets() {
    for overgrant in [true, false] {
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&requests);
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let observed = Arc::clone(&observed);
            async move {
                send_challenge(&mut socket).await;
                let (connect, _) = receive_connect(&mut socket).await;
                send_hello(&mut socket, connect.id(), "native-fixture", 4, AUTHENTICATED_MAX_FRAME_BYTES, "operator", if overgrant { &["operator.admin"] } else { &["operator.approvals"] }).await;
                if overgrant {
                    count_requests_until_close(&mut socket, &observed).await;
                } else {
                    let request = receive_request(&mut socket).await;
                    observed.fetch_add(1, Ordering::SeqCst);
                    send_json(&mut socket, json!({"type": "res", "id": request.id().as_str(), "ok": false, "error": {"code": "UNAUTHORIZED", "message": TOKEN_WRAPPED}})).await;
                    wait_for_close(&mut socket).await;
                }
            }
        })).await;
        let mut arguments = vec!["gateway".into(), "approve".into(), "approval-1".into()];
        arguments.extend(["--preview-fingerprint".into(), "a".repeat(64).into()]);
        arguments.extend(gateway_arguments(gateway.url.as_str()).into_iter().skip(2));
        let output = run_cli(arguments, Some(TOKEN)).await;
        assert!(!output.status.success());
        let document: Value = serde_json::from_slice(&output.stdout).expect("failure JSON");
        assert_eq!(
            document["delivery"],
            if overgrant { "not_sent" } else { "rejected" }
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
        gateway.shutdown().await;
        assert_eq!(requests.load(Ordering::SeqCst), usize::from(!overgrant));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_cli_keeps_unconfirmed_server_outcomes_unknown_without_replay() {
    for code in ["OUTCOME_UNKNOWN", "UNAVAILABLE"] {
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&requests);
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let observed = Arc::clone(&observed);
            async move {
                send_challenge(&mut socket).await;
                let (connect, _) = receive_connect(&mut socket).await;
                send_hello(&mut socket, connect.id(), "uncertain-fixture", 4, AUTHENTICATED_MAX_FRAME_BYTES, "operator", &["operator.write"]).await;
                let request = receive_request(&mut socket).await;
                observed.fetch_add(1, Ordering::SeqCst);
                send_json(&mut socket, json!({"type": "res", "id": request.id().as_str(), "ok": false, "error": {"code": code, "message": TOKEN_WRAPPED, "retryable": false}})).await;
                count_requests_until_close(&mut socket, &observed).await;
            }
        })).await;
        let mut arguments = vec![
            "send".into(),
            "session-one".into(),
            "once".into(),
            "--idempotency-key".into(),
            "original-key".into(),
        ];
        arguments.extend(gateway_arguments(gateway.url.as_str()).into_iter().skip(2));
        let output = run_cli(arguments, Some(TOKEN)).await;
        assert!(!output.status.success());
        let result: Value = serde_json::from_slice(&output.stdout).expect("JSON failure");
        assert_eq!(result["delivery"], "unknown");
        assert_eq!(result["status"], "outcome_unknown");
        assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
        gateway.shutdown().await;
        assert_eq!(
            requests.load(Ordering::SeqCst),
            1,
            "writes must not be replayed"
        );
    }
}

#[derive(Clone, Debug)]
enum GatewayBehavior {
    Healthy {
        server_version: &'static str,
        expected_token: Option<&'static str>,
    },
    AuthenticationFailure,
    PairingRequired,
    HelloProtocol(u64),
    HealthNegative,
    HealthRpcFailure,
    HealthTimeout,
    HealthThenClose,
    MalformedResponse,
    OversizedResponse,
    ImmediateClose {
        close_flushed: watch::Sender<bool>,
    },
    HelloClaims {
        role: &'static str,
        scopes: &'static [&'static str],
    },
}

async fn spawn_gateway(behavior: GatewayBehavior, request_count: Arc<AtomicUsize>) -> TestGateway {
    TestGateway::spawn(handler(move |mut socket, _| {
        let behavior = behavior.clone();
        let request_count = Arc::clone(&request_count);
        async move {
            send_challenge(&mut socket).await;
            let (connect, params) = receive_connect(&mut socket).await;
            support::verify_connect_proof(&params);
            if matches!(
                behavior,
                GatewayBehavior::AuthenticationFailure | GatewayBehavior::PairingRequired
            ) {
                let code = if matches!(behavior, GatewayBehavior::PairingRequired) {
                    "PAIRING_REQUIRED"
                } else {
                    "AUTH_TOKEN_MISMATCH"
                };
                send_connect_error(&mut socket, connect.id(), code).await;
                return;
            }
            let expected_token = match behavior {
                GatewayBehavior::Healthy { expected_token, .. } => expected_token,
                _ => Some(TOKEN),
            };
            if !connect_matches(&params, expected_token) {
                send_connect_error(&mut socket, connect.id(), "AUTH_TOKEN_MISMATCH").await;
                return;
            }

            let (server_version, protocol, max_payload) = match behavior {
                GatewayBehavior::Healthy { server_version, .. } => {
                    (server_version, 4, AUTHENTICATED_MAX_FRAME_BYTES)
                }
                GatewayBehavior::HelloProtocol(protocol) => {
                    ("test-gateway", protocol, AUTHENTICATED_MAX_FRAME_BYTES)
                }
                GatewayBehavior::OversizedResponse => ("test-gateway", 4, 1_024),
                _ => ("test-gateway", 4, AUTHENTICATED_MAX_FRAME_BYTES),
            };
            let (hello_role, hello_scopes) = match behavior {
                GatewayBehavior::HelloClaims { role, scopes } => (role, scopes),
                _ => ("operator", &["operator.read"][..]),
            };
            send_hello(
                &mut socket,
                connect.id(),
                server_version,
                protocol,
                max_payload,
                hello_role,
                hello_scopes,
            )
            .await;
            if matches!(behavior, GatewayBehavior::HelloProtocol(_)) {
                return;
            }
            if let GatewayBehavior::ImmediateClose { close_flushed } = &behavior {
                socket
                    .write_frame(fastwebsockets::Frame::close(1000, b"diagnostic close"))
                    .await
                    .expect("send immediate close");
                socket.flush().await.expect("flush immediate close");
                close_flushed.send_replace(true);
                count_requests_until_close(&mut socket, &request_count).await;
                return;
            }
            if matches!(behavior, GatewayBehavior::HelloClaims { .. }) {
                count_requests_until_close(&mut socket, &request_count).await;
                return;
            }

            let request = receive_request(&mut socket).await;
            request_count.fetch_add(1, Ordering::SeqCst);
            let params_are_empty = request
                .params()
                .value()
                .and_then(|value| Codec::authenticated().decode_opaque::<Value>(value).ok())
                .is_some_and(|value| value == json!({}));
            if request.method().as_str() != "health" || !params_are_empty {
                send_json(
                    &mut socket,
                    json!({
                        "type": "res",
                        "id": request.id().as_str(),
                        "ok": false,
                        "error": {
                            "code": "INVALID_REQUEST",
                            "message": "unexpected diagnostic request"
                        }
                    }),
                )
                .await;
                wait_for_close(&mut socket).await;
                return;
            }
            match behavior {
                GatewayBehavior::Healthy { .. } => {
                    send_health(&mut socket, request.id().as_str(), true).await;
                    wait_for_close(&mut socket).await;
                }
                GatewayBehavior::HealthNegative => {
                    send_health(&mut socket, request.id().as_str(), false).await;
                    wait_for_close(&mut socket).await;
                }
                GatewayBehavior::HealthRpcFailure => {
                    send_json(
                        &mut socket,
                        json!({
                            "type": "res",
                            "id": request.id().as_str(),
                            "ok": false,
                            "error": {
                                "code": "UNAVAILABLE",
                                "message": format!("upstream exposed {TOKEN}")
                            }
                        }),
                    )
                    .await;
                    wait_for_close(&mut socket).await;
                }
                GatewayBehavior::HealthTimeout => wait_for_close(&mut socket).await,
                GatewayBehavior::HealthThenClose => {
                    send_health(&mut socket, request.id().as_str(), true).await;
                    socket
                        .write_frame(fastwebsockets::Frame::close(1000, b"response complete"))
                        .await
                        .expect("send close after health");
                    socket.flush().await.expect("flush response close");
                    count_requests_until_close(&mut socket, &request_count).await;
                }
                GatewayBehavior::MalformedResponse => {
                    send_raw_text(&mut socket, b"{not-json".to_vec()).await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                GatewayBehavior::OversizedResponse => {
                    send_raw_text(&mut socket, vec![b'x'; 1_025]).await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                GatewayBehavior::AuthenticationFailure
                | GatewayBehavior::PairingRequired
                | GatewayBehavior::HelloProtocol(_)
                | GatewayBehavior::ImmediateClose { .. }
                | GatewayBehavior::HelloClaims { .. } => unreachable!("handled before health"),
            }
        }
    }))
    .await
}

fn connect_matches(params: &ConnectParams, expected_token: Option<&str>) -> bool {
    let auth_matches = match (expected_token, params.auth.as_ref()) {
        (None, None) => true,
        (Some(expected), Some(auth)) => {
            auth.token.as_deref() == Some(expected)
                && auth.bootstrap_token.is_none()
                && auth.device_token.is_none()
                && auth.password.is_none()
                && auth.approval_runtime_token.is_none()
                && auth.agent_runtime_identity_token.is_none()
        }
        (None, Some(_)) | (Some(_), None) => false,
    };
    params.min_protocol.get() == 4
        && params.max_protocol.get() == 4
        && params.client.id == ClientId::Probe
        && params
            .client
            .display_name
            .as_ref()
            .map(claw_protocol::gateway::Name::as_str)
            == Some("GTA Claw Gateway diagnostic")
        && params.client.version.as_str() == env!("CARGO_PKG_VERSION")
        && params.client.platform.as_str() == std::env::consts::OS
        && params.client.device_family.is_none()
        && params.client.model_identifier.is_none()
        && params.client.mode == ClientMode::Probe
        && params.client.instance_id.is_none()
        && params.caps.as_ref().is_some_and(Vec::is_empty)
        && params.commands.is_none()
        && params.permissions.is_none()
        && params.path_env.is_none()
        && params
            .role
            .as_ref()
            .map(claw_protocol::gateway::Name::as_str)
            == Some("operator")
        && params
            .scopes
            .as_ref()
            .is_some_and(|scopes| scopes.len() == 1 && scopes[0].as_str() == "operator.read")
        && params
            .device
            .as_ref()
            .is_some_and(|device| device.nonce.as_str() == "test-nonce")
        && auth_matches
        && params.locale.is_none()
        && params.user_agent.is_none()
}

async fn send_hello(
    socket: &mut support::TestSocket,
    id: &RequestId,
    server_version: &str,
    protocol: u64,
    max_payload: usize,
    role: &str,
    scopes: &[&str],
) {
    send_json(
        socket,
        json!({
            "type": "res",
            "id": id.as_str(),
            "ok": true,
            "payload": {
                "type": "hello-ok",
                "protocol": protocol,
                "server": {"version": server_version, "connId": "test-connection"},
                "features": {
                    "methods": ["health"],
                    "events": ["connect.challenge", "tick"]
                },
                "snapshot": {
                    "presence": [],
                    "health": {},
                    "stateVersion": {"presence": 0, "health": 0},
                    "uptimeMs": 1,
                    "authMode": "token"
                },
                "auth": {"role": role, "scopes": scopes},
                "policy": {
                    "maxPayload": max_payload,
                    "maxBufferedBytes": max_payload,
                    "tickIntervalMs": 1000
                }
            }
        }),
    )
    .await;
}

async fn count_requests_until_close(socket: &mut support::TestSocket, request_count: &AtomicUsize) {
    loop {
        match socket.read_frame().await {
            Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => {
                request_count.fetch_add(1, Ordering::SeqCst);
            }
            Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => return,
            Ok(_) => {}
            Err(_) => return,
        }
    }
}

async fn send_health(socket: &mut support::TestSocket, id: &str, ok: bool) {
    send_json(
        socket,
        json!({
            "type": "res",
            "id": id,
            "ok": true,
            "payload": {
                "ok": ok,
                "ts": 1_700_000_000_123_u64,
                "durationMs": 17,
                "channels": {
                    "not-rendered": {
                        "secret": TOKEN,
                        "control": "line\nforgery"
                    }
                }
            }
        }),
    )
    .await;
}

async fn run_cli(arguments: Vec<OsString>, stdin: Option<&str>) -> Output {
    run_cli_in(arguments, stdin, None).await
}

async fn run_cli_in(
    arguments: Vec<OsString>,
    stdin: Option<&str>,
    profile_root: Option<&std::path::Path>,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
    if let Some(root) = profile_root {
        command.env("LOCALAPPDATA", root);
    }
    command
        .args(arguments)
        .env_remove("GTA_CLAW_LOG")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("CLI process starts");
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().expect("piped stdin");
        pipe.write_all(input.as_bytes())
            .await
            .expect("write token stdin");
        drop(pipe);
    }
    collect_child_output(child, Duration::from_secs(8), "CLI process").await
}

async fn run_cli_with_open_stdin(arguments: Vec<OsString>) -> (Output, Duration) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
    command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("CLI process starts");
    let open_stdin = child.stdin.take().expect("open stdin pipe");
    let started = Instant::now();
    let output =
        collect_child_output(child, Duration::from_secs(3), "invalid-input CLI process").await;
    let elapsed = started.elapsed();
    drop(open_stdin);
    (output, elapsed)
}

async fn collect_child_output(mut child: Child, limit: Duration, label: &str) -> Output {
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let stdout_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.expect("read stdout");
        bytes
    });
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.expect("read stderr");
        bytes
    });
    let Ok(status) = tokio::time::timeout(limit, child.wait()).await else {
        child.start_kill().expect("terminate timed-out CLI");
        let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .expect("reap timed-out CLI")
            .expect("timed-out CLI status");
        let stdout = stdout_task.await.expect("stdout task");
        let stderr = stderr_task.await.expect("stderr task");
        panic!(
            "{label} exceeded {limit:?}: status={status} stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
    };
    let status = status.expect("CLI process status");
    Output {
        status,
        stdout: stdout_task.await.expect("stdout task"),
        stderr: stderr_task.await.expect("stderr task"),
    }
}

fn gateway_arguments(url: &str) -> Vec<OsString> {
    let url = url.strip_suffix('/').unwrap_or(url);
    [
        "gateway",
        "health",
        "--endpoint",
        url,
        "--ephemeral-device",
        "--token-stdin",
        "--json",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn parse_json(output: &Output) -> Value {
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("one JSON summary")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn successful_hello_health_is_redacted_deterministic_and_closes_once() {
    let request_count = Arc::new(AtomicUsize::new(0));
    let gateway = spawn_gateway(
        GatewayBehavior::Healthy {
            server_version: "网关-v4",
            expected_token: Some(TOKEN),
        },
        Arc::clone(&request_count),
    )
    .await;
    let arguments = gateway_arguments(gateway.url.as_str());
    assert!(
        arguments
            .iter()
            .all(|argument| argument.to_string_lossy() != TOKEN),
        "token must not appear in argv"
    );
    let output = run_cli(arguments, Some(&format!("{TOKEN}\n"))).await;
    assert_eq!(output.status.code(), Some(0));
    let summary = parse_json(&output);
    let keys = summary
        .as_object()
        .expect("JSON object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    // Field order is now the declaration order of the summary struct rather
    // than an alphabetical accident, so the diagnostic reads top-down: what ran,
    // how it went, then the connection facts behind that verdict.
    assert_eq!(
        keys,
        [
            "schema_version",
            "command",
            "status",
            "category",
            "message",
            "endpoint",
            "protocol",
            "role",
            "scopes",
            "server",
            "health",
            "elapsed_ms",
            "identity",
            "pairing_entry_possible",
        ]
    );
    assert_eq!(summary["category"], "success");
    assert_eq!(summary["schema_version"], 2);
    assert_eq!(summary["status"], "healthy");
    assert_eq!(
        summary["endpoint"],
        gateway.url.origin().ascii_serialization()
    );
    assert_eq!(summary["protocol"], 4);
    assert_eq!(summary["role"], "operator");
    assert_eq!(summary["scopes"], json!(["operator.read"]));
    assert_eq!(summary["server"]["version"], Value::Null);
    assert_eq!(summary["server"]["version_status"], "redacted_peer_value");
    assert_eq!(summary["health"]["ok"], true);
    assert_eq!(summary["health"]["timestamp_ms"], 1_700_000_000_123_u64);
    assert_eq!(summary["health"]["duration_ms"], 17);
    assert_eq!(summary["identity"], "ephemeral");
    assert_eq!(summary["pairing_entry_possible"], true);
    let captured = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!captured.contains(TOKEN));
    assert!(!captured.contains("not-rendered"));
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_version_never_reflects_credentials_separators_or_bidi() {
    for peer_version in [
        TOKEN,
        TOKEN_WRAPPED,
        "gateway\u{2028}forged",
        "gateway\u{2029}forged",
        "gateway\u{202e}forged",
    ] {
        for json_output in [true, false] {
            let gateway = spawn_gateway(
                GatewayBehavior::Healthy {
                    server_version: peer_version,
                    expected_token: Some(TOKEN),
                },
                Arc::new(AtomicUsize::new(0)),
            )
            .await;
            let mut arguments = gateway_arguments(gateway.url.as_str());
            if !json_output {
                arguments.retain(|argument| argument != "--json");
            }
            let output = run_cli(arguments, Some(&format!("{TOKEN}\n"))).await;
            assert_eq!(output.status.code(), Some(0));
            let captured = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!captured.contains(TOKEN));
            assert!(!captured.contains(peer_version));
            assert!(!captured.contains('\u{2028}'));
            assert!(!captured.contains('\u{2029}'));
            assert!(!captured.contains('\u{202e}'));
            if json_output {
                let summary = parse_json(&output);
                assert_eq!(summary["server"]["version"], Value::Null);
                assert_eq!(summary["server"]["version_status"], "redacted_peer_value");
            } else {
                assert!(captured.contains("server_version: [redacted peer value]"));
            }
            gateway.shutdown().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authentication_and_pairing_failures_have_stable_category() {
    for (behavior, status) in [
        (
            GatewayBehavior::AuthenticationFailure,
            "authentication_failed",
        ),
        (GatewayBehavior::PairingRequired, "pairing_required"),
    ] {
        let gateway = spawn_gateway(behavior.clone(), Arc::new(AtomicUsize::new(0))).await;
        let output = run_cli(
            gateway_arguments(gateway.url.as_str()),
            Some(&format!("{TOKEN}\n")),
        )
        .await;
        assert_eq!(output.status.code(), Some(4));
        let summary = parse_json(&output);
        assert_eq!(summary["category"], "authentication_pairing");
        assert_eq!(summary["status"], status);
        gateway.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_token_is_explicit_and_wrong_token_is_rejected_by_the_server() {
    let gateway = spawn_gateway(
        GatewayBehavior::Healthy {
            server_version: "no-token-gateway",
            expected_token: None,
        },
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    let arguments = [
        "gateway",
        "health",
        "--endpoint",
        gateway
            .url
            .as_str()
            .strip_suffix('/')
            .expect("root endpoint"),
        "--ephemeral-device",
        "--json",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run_cli(arguments, None).await;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_json(&output)["status"], "healthy");
    gateway.shutdown().await;

    let gateway = spawn_gateway(
        GatewayBehavior::Healthy {
            server_version: "token-gateway",
            expected_token: Some(TOKEN),
        },
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    let wrong_token = "wrong-stdin-token";
    let output = run_cli(
        gateway_arguments(gateway.url.as_str()),
        Some(&format!("{wrong_token}\n")),
    )
    .await;
    assert_eq!(output.status.code(), Some(4));
    let captured = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!captured.contains(wrong_token));
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn immediate_post_hello_disconnect_is_stably_transport_failure() {
    for iteration in 0..100 {
        let (close_flushed, mut close_flushed_rx) = watch::channel(false);
        let request_count = Arc::new(AtomicUsize::new(0));
        let gateway = spawn_gateway(
            GatewayBehavior::ImmediateClose { close_flushed },
            Arc::clone(&request_count),
        )
        .await;
        let token_input = format!("{TOKEN}\n");
        let close_proof = async {
            tokio::time::timeout(
                Duration::from_secs(2),
                close_flushed_rx.wait_for(|flushed| *flushed),
            )
            .await
            .map(|result| result.map(|_| ()))
        };
        let (output, close_proof) = tokio::join!(
            run_cli(gateway_arguments(gateway.url.as_str()), Some(&token_input)),
            close_proof
        );
        gateway.shutdown().await;
        close_proof
            .unwrap_or_else(|_| panic!("iteration {iteration} timed out before close flush"))
            .unwrap_or_else(|_| panic!("iteration {iteration} lost close-flush publisher"));
        assert_eq!(output.status.code(), Some(3));
        let summary = parse_json(&output);
        assert_eq!(summary["category"], "transport_transient");
        assert_eq!(summary["status"], "transport_failure");
        assert!(
            request_count.load(Ordering::SeqCst) <= 1,
            "iteration {iteration} replayed health after close"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_response_wins_a_following_close_without_replay() {
    for _ in 0..25 {
        let request_count = Arc::new(AtomicUsize::new(0));
        let gateway =
            spawn_gateway(GatewayBehavior::HealthThenClose, Arc::clone(&request_count)).await;
        let output = run_cli(
            gateway_arguments(gateway.url.as_str()),
            Some(&format!("{TOKEN}\n")),
        )
        .await;
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(parse_json(&output)["status"], "healthy");
        gateway.shutdown().await;
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unexpected_hello_role_or_scopes_are_protocol_failures_without_health_rpc() {
    for (role, scopes) in [
        ("operator", &[][..]),
        ("operator", &["operator.admin"][..]),
        ("operator", &["operator.read", "operator.admin"][..]),
        ("node", &["operator.read"][..]),
    ] {
        let request_count = Arc::new(AtomicUsize::new(0));
        let gateway = spawn_gateway(
            GatewayBehavior::HelloClaims { role, scopes },
            Arc::clone(&request_count),
        )
        .await;
        let output = run_cli(
            gateway_arguments(gateway.url.as_str()),
            Some(&format!("{TOKEN}\n")),
        )
        .await;
        assert_eq!(output.status.code(), Some(5));
        assert_eq!(parse_json(&output)["category"], "protocol");
        gateway.shutdown().await;
        assert_eq!(request_count.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_version_control_text_malformed_and_oversized_are_rejected() {
    for behavior in [
        GatewayBehavior::HelloProtocol(3),
        GatewayBehavior::MalformedResponse,
        GatewayBehavior::OversizedResponse,
    ] {
        let gateway = spawn_gateway(behavior.clone(), Arc::new(AtomicUsize::new(0))).await;
        let output = run_cli(
            gateway_arguments(gateway.url.as_str()),
            Some(&format!("{TOKEN}\n")),
        )
        .await;
        assert_eq!(
            output.status.code(),
            Some(5),
            "behavior {behavior:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let summary = parse_json(&output);
        assert_eq!(summary["category"], "protocol");
        gateway.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_negative_and_rpc_failure_are_exit_six_without_server_text() {
    for behavior in [
        GatewayBehavior::HealthNegative,
        GatewayBehavior::HealthRpcFailure,
    ] {
        let gateway = spawn_gateway(behavior, Arc::new(AtomicUsize::new(0))).await;
        let output = run_cli(
            gateway_arguments(gateway.url.as_str()),
            Some(&format!("{TOKEN}\n")),
        )
        .await;
        assert_eq!(output.status.code(), Some(6));
        let summary = parse_json(&output);
        assert_eq!(summary["category"], "health_negative");
        assert_eq!(summary["status"], "unhealthy");
        assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
        gateway.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn command_timeout_cancels_health_and_closes_without_late_rpc() {
    let request_count = Arc::new(AtomicUsize::new(0));
    let gateway = spawn_gateway(GatewayBehavior::HealthTimeout, Arc::clone(&request_count)).await;
    let mut arguments = gateway_arguments(gateway.url.as_str());
    arguments.extend([OsString::from("--timeout-ms"), OsString::from("300")]);
    let output = run_cli(arguments, Some(&format!("{TOKEN}\n"))).await;
    assert_eq!(output.status.code(), Some(7));
    let summary = parse_json(&output);
    assert_eq!(summary["category"], "timeout_cancel");
    assert_eq!(summary["status"], "timeout");
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
    gateway.shutdown().await;
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_and_remote_plaintext_are_distinct_stable_failures() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let address = listener.local_addr().expect("local address");
    drop(listener);
    let unreachable = format!("ws://{address}");
    let output = run_cli(gateway_arguments(&unreachable), Some(&format!("{TOKEN}\n"))).await;
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(parse_json(&output)["category"], "transport_transient");

    let output = run_cli(
        gateway_arguments("ws://192.0.2.1:18789"),
        Some(&format!("{TOKEN}\n")),
    )
    .await;
    assert_eq!(output.status.code(), Some(2));
    let summary = parse_json(&output);
    assert_eq!(summary["category"], "usage_config");
    assert_eq!(summary["status"], "insecure_remote_ws");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_or_insecure_endpoints_exit_before_reading_stdin() {
    for endpoint in [
        "not-a-url",
        " ws://127.0.0.1:9",
        "ws://exa\u{200b}mple.com",
        "ws://exa\u{2060}mple.com",
        "ws://exa\u{feff}mple.com",
        "WS://127.0.0.1:9",
        "ws://LOCALHOST:9",
        "wss://例え.COM/socket",
        "wss://ｅxample.com",
        "wss://example。com",
        "ws://[0:0:0:0:0:0:0:1]:9",
        "wss://example.com:0443",
        "wss://example.com:0",
        "wss://example.com/a/../b",
        "wss://example.com/%62",
        "wss://example.com.",
        "wss://example..com",
        "wss://_foo.example",
        "ws://192.0.2.1:18789",
    ] {
        let (output, elapsed) = run_cli_with_open_stdin(gateway_arguments(endpoint)).await;
        assert_eq!(output.status.code(), Some(2), "endpoint {endpoint:?}");
        assert!(elapsed < Duration::from_secs(1), "endpoint {endpoint:?}");
        assert_eq!(parse_json(&output)["category"], "usage_config");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_resolving_dns_cannot_hold_the_process_past_its_bound() {
    let mut arguments = gateway_arguments("wss://never-resolves.invalid");
    arguments.extend([OsString::from("--timeout-ms"), OsString::from("300")]);
    let started = Instant::now();
    let output = run_cli(arguments, Some(&format!("{TOKEN}\n"))).await;
    assert!(
        matches!(output.status.code(), Some(3 | 7)),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoint_credentials_query_and_fragment_are_never_rendered() {
    let endpoint = "ws://operator:argv-secret@127.0.0.1:9/path?token=query-secret#fragment-secret";
    let (output, elapsed) = run_cli_with_open_stdin(gateway_arguments(endpoint)).await;
    assert_eq!(output.status.code(), Some(2));
    assert!(elapsed < Duration::from_secs(1));
    let summary = parse_json(&output);
    assert_eq!(summary["category"], "usage_config");
    assert_eq!(summary["status"], "credential_bearing_endpoint");
    assert_eq!(summary["endpoint"], "ws://127.0.0.1:9");
    let captured = String::from_utf8_lossy(&output.stdout);
    for secret in ["argv-secret", "query-secret", "fragment-secret"] {
        assert!(!captured.contains(secret));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdin_errors_and_token_file_fail_closed_before_network() {
    let output = run_cli(
        gateway_arguments("ws://127.0.0.1:9"),
        Some("two lines\nare rejected\n"),
    )
    .await;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(parse_json(&output)["status"], "secret_invalid");

    let arguments = [
        "gateway".into(),
        "health".into(),
        "--endpoint".into(),
        "ws://127.0.0.1:9".into(),
        "--ephemeral-device".into(),
        "--token-file".into(),
        "token.txt".into(),
        "--json".into(),
    ]
    .to_vec();
    let output = run_cli(arguments, None).await;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(parse_json(&output)["status"], "token_file_unsupported");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timeout_terminates_an_open_stdin_secret_source() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
    command
        .args([
            "gateway",
            "health",
            "--endpoint",
            "ws://127.0.0.1:9",
            "--ephemeral-device",
            "--token-stdin",
            "--timeout-ms",
            "300",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("CLI process starts");
    let open_stdin = child.stdin.take().expect("open stdin pipe");
    let output = tokio::time::timeout(Duration::from_secs(3), child.wait_with_output())
        .await
        .expect("CLI must not hang on open stdin")
        .expect("CLI output");
    drop(open_stdin);
    assert_eq!(output.status.code(), Some(7));
    let summary = parse_json(&output);
    assert_eq!(summary["category"], "timeout_cancel");
    assert_eq!(summary["status"], "timeout");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigint_cancels_and_joins_the_gateway_task() {
    let request_count = Arc::new(AtomicUsize::new(0));
    let gateway = spawn_gateway(GatewayBehavior::HealthTimeout, Arc::clone(&request_count)).await;
    let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
    command
        .args(gateway_arguments(gateway.url.as_str()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("CLI process starts");
    let mut stdin = child.stdin.take().expect("token stdin");
    stdin
        .write_all(format!("{TOKEN}\n").as_bytes())
        .await
        .expect("write token");
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(3), async {
        while request_count.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("health request observed");
    let pid = child.id().expect("child process id");
    let signal = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .await
        .expect("send SIGINT");
    assert!(signal.success());
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("cancelled CLI timeout")
        .expect("cancelled CLI output");
    assert_eq!(output.status.code(), Some(7));
    let summary = parse_json(&output);
    assert_eq!(summary["category"], "timeout_cancel");
    assert_eq!(summary["status"], "cancelled");
    gateway.shutdown().await;
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
}

/// Runs `gateway health` against one healthy Gateway once per argument set.
async fn run_healthy(runs: &[&[&str]]) -> Vec<Output> {
    let request_count = Arc::new(AtomicUsize::new(0));
    let gateway = spawn_gateway(
        GatewayBehavior::Healthy {
            server_version: "diag-v1",
            expected_token: Some(TOKEN),
        },
        Arc::clone(&request_count),
    )
    .await;
    let mut outputs = Vec::with_capacity(runs.len());
    for extra in runs {
        let mut arguments = gateway_arguments(gateway.url.as_str());
        arguments.extend(extra.iter().copied().map(OsString::from));
        let output = run_cli(arguments, Some(&format!("{TOKEN}\n"))).await;
        assert_eq!(
            output.status.code(),
            Some(0),
            "stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        outputs.push(output);
    }
    gateway.shutdown().await;
    outputs
}

/// Parses the summary without the "stderr is empty" precondition `parse_json` enforces.
fn summary_of(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("one JSON summary")
}

/// Replaces the one non-deterministic field so two runs can be compared byte for byte.
fn normalize(output: &Output) -> Value {
    let mut summary = summary_of(output);
    summary["elapsed_ms"] = json!(0);
    summary
}

/// Parses the `claw-observability` JSON records the subscriber writes.
///
/// The shape is the shared layer's, not this binary's: `level`, `target`, and a
/// redacted `fields` map. Asserting on it here proves the diagnostics really do
/// travel through the installed subscriber rather than a private writer.
fn diagnostic_lines(output: &Output) -> Vec<Value> {
    records(&String::from_utf8(output.stderr.clone()).expect("diagnostics are UTF-8"))
}

/// Parses the JSON records the installed subscriber wrote, from either sink.
fn records(text: &str) -> Vec<Value> {
    text.lines()
        .map(|line| {
            let record: Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("diagnostics are JSON lines: {error}: {line}"));
            assert!(
                record["fields"]["action"].is_string(),
                "every diagnostic line is one of this binary's events: {line}"
            );
            assert!(
                record["target"]
                    .as_str()
                    .expect("target")
                    .starts_with("gta_claw_cli"),
                "no dependency may share this stream: {line}"
            );
            record
        })
        .collect()
}

/// A path under Cargo's per-target temporary directory, cleared of any leftover.
///
/// The file is opened in append mode, so a stale run must not be able to add
/// records to the ones this test asserts on.
fn log_path(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_file(&path);
    path
}

fn fields(record: &Value) -> &Value {
    &record["fields"]
}

fn find<'a>(records: &'a [Value], action: &str) -> Option<&'a Value> {
    records
        .iter()
        .find(|record| record["fields"]["action"] == action)
}

fn actions(records: &[Value]) -> Vec<String> {
    records
        .iter()
        .map(|record| {
            record["fields"]["action"]
                .as_str()
                .expect("action")
                .to_owned()
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verbose_diagnostics_are_additive_and_leave_the_json_contract_untouched() {
    let outputs = run_healthy(&[&[], &["--verbose"]]).await;
    let (quiet, verbose) = (&outputs[0], &outputs[1]);
    assert!(
        quiet.stderr.is_empty(),
        "the default run must stay silent: {}",
        String::from_utf8_lossy(&quiet.stderr)
    );
    assert_eq!(
        normalize(quiet),
        normalize(verbose),
        "verbosity must not alter the schema-version-2 object"
    );
    assert_eq!(
        String::from_utf8_lossy(&quiet.stdout)
            .split("\"elapsed_ms\"")
            .next(),
        String::from_utf8_lossy(&verbose.stdout)
            .split("\"elapsed_ms\"")
            .next(),
        "key order must be byte-identical up to the elapsed measurement"
    );

    let records = diagnostic_lines(verbose);
    let observed = actions(&records);
    for expected in [
        "endpoint.resolve",
        "credential.read",
        "identity.generate",
        "client.start",
        "connection.ready",
        "authorization.grant",
        "rpc.response",
        "client.shutdown",
        "diagnostic.complete",
    ] {
        assert!(
            observed.iter().any(|action| action == expected),
            "missing {expected} in {observed:?}"
        );
    }
    assert!(
        !observed.iter().any(|action| action == "rpc.request"),
        "correlation detail belongs to -vv only: {observed:?}"
    );
    for record in &records {
        assert_eq!(record["level"], "DEBUG", "stage events are the -v level");
        if fields(record)["action"] != "telemetry.install" {
            assert_eq!(
                fields(record)["endpoint"],
                summary_of(verbose)["endpoint"],
                "every event after resolution names the endpoint the verdict names"
            );
        }
        for (key, value) in fields(record).as_object().expect("field map") {
            // Nothing here is a secret, so a redacted value means a field was
            // named badly and silently lost its content.
            assert_ne!(
                value, "[REDACTED]",
                "{key} is redacted by its own name; rename it"
            );
        }
    }
    let ready = find(&records, "connection.ready").expect("connection.ready");
    assert_eq!(fields(ready)["protocol.negotiated"], 4);
    let grant = find(&records, "authorization.grant").expect("authorization.grant");
    assert_eq!(fields(grant)["outcome"], "success");
    assert_eq!(fields(grant)["role.granted"], "operator");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn diagnostics_never_carry_the_token_and_detail_is_opt_in() {
    let outputs = run_healthy(&[&["-vv"]]).await;
    let verbose = &outputs[0];
    let stderr = String::from_utf8(verbose.stderr.clone()).expect("diagnostics are UTF-8");
    assert!(
        !stderr.contains(TOKEN),
        "the stdin token must never reach the diagnostic stream"
    );
    assert!(
        !stderr.contains(TOKEN_WRAPPED),
        "no substring form of the token may appear either"
    );
    let records = diagnostic_lines(verbose);
    let observed = actions(&records);
    for expected in ["rpc.request", "connection.epoch", "command.bounds"] {
        assert!(
            observed.iter().any(|action| action == expected),
            "missing {expected} in {observed:?}"
        );
    }
    let install = find(&records, "telemetry.install").expect("telemetry.install");
    assert_eq!(
        fields(install)["telemetry.default_filter"],
        "gta_claw_cli=trace",
        "a bare level would put bridged dependency `log` records on this stream"
    );
    assert!(
        records
            .iter()
            .any(|record| record["level"] == "TRACE" && record["level"] != "DEBUG"),
        "-vv opens the trace level: {observed:?}"
    );
    let credential = find(&records, "credential.read").expect("credential.read");
    assert_eq!(fields(credential)["auth.source"], "stdin");
    assert!(
        fields(credential)
            .as_object()
            .expect("field map")
            .values()
            .all(|value| value != TOKEN),
        "no field may carry the secret verbatim"
    );
    assert!(
        fields(credential)["message"].as_str().unwrap_or_default() != TOKEN,
        "message text bypasses redaction, so it must never carry the secret"
    );
    assert_eq!(
        String::from_utf8_lossy(&verbose.stdout)
            .matches('\n')
            .count(),
        1,
        "diagnostics must never be written to stdout"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rejected_hello_names_the_stage_that_failed() {
    let request_count = Arc::new(AtomicUsize::new(0));
    let gateway = spawn_gateway(
        GatewayBehavior::HelloClaims {
            role: "node",
            scopes: &["operator.read"],
        },
        Arc::clone(&request_count),
    )
    .await;
    let mut arguments = gateway_arguments(gateway.url.as_str());
    arguments.push(OsString::from("--verbose"));
    let output = run_cli(arguments, Some(&format!("{TOKEN}\n"))).await;
    gateway.shutdown().await;
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(request_count.load(Ordering::SeqCst), 0);

    let records = diagnostic_lines(&output);
    let observed = actions(&records);
    assert!(
        !observed.iter().any(|action| action == "rpc.response"),
        "the RPC never ran, so it must not be reported: {observed:?}"
    );
    let ready = find(&records, "connection.ready")
        .unwrap_or_else(|| panic!("connection.ready in {observed:?}"));
    assert_eq!(
        fields(ready)["outcome"],
        "failure",
        "the stage that failed must say so"
    );
    assert_eq!(fields(ready)["failure.category"], "protocol");
    assert_eq!(fields(ready)["failure.exit_code"], 5);
    let complete = find(&records, "diagnostic.complete").expect("diagnostic.complete");
    assert_eq!(fields(complete)["failure.category"], "protocol");
    assert_eq!(fields(complete)["failure.exit_code"], 5);
    assert_eq!(
        fields(complete)["failure.status"],
        summary_of(&output)["status"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_file_takes_every_record_and_leaves_standard_error_clean() {
    let path = log_path("cli-diagnostics.jsonl");
    let flag = path.to_str().expect("UTF-8 path").to_owned();
    let outputs = run_healthy(&[&[], &["--verbose"], &["--verbose", "--log-file", &flag]]).await;
    let (quiet, to_stderr, to_file) = (&outputs[0], &outputs[1], &outputs[2]);

    // The default is unchanged: without the flag the records are still on
    // standard error, and the flag is the only thing that moves them.
    let on_stderr = diagnostic_lines(to_stderr);
    assert!(
        !on_stderr.is_empty(),
        "-v alone still writes to standard error"
    );
    assert!(
        to_file.stderr.is_empty(),
        "the file is the destination, so standard error stays a clean stream: {}",
        String::from_utf8_lossy(&to_file.stderr)
    );
    assert_eq!(
        normalize(quiet),
        normalize(to_file),
        "a destination must not alter the schema-version-2 object"
    );

    let text = fs::read_to_string(&path).expect("the requested log file was written");
    let written = records(&text);
    assert_eq!(
        actions(&written),
        actions(&on_stderr),
        "the same records, only somewhere else"
    );
    let install = find(&written, "telemetry.install").expect("telemetry.install");
    assert_eq!(
        fields(install)["telemetry.output"],
        Value::from(path.display().to_string()),
        "the installed destination is reported as the file, not stderr"
    );
    assert!(
        !text.contains(TOKEN),
        "the stdin token must never reach the diagnostic file either"
    );
    fs::remove_file(&path).expect("remove the log file");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unopenable_log_file_fails_the_command_without_falling_back_to_stderr() {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("no-such-cli-directory");
    let path = directory.join("run.jsonl");
    let flag = path.to_str().expect("UTF-8 path");
    // Nothing is contacted and standard input is never read: the destination is
    // resolved before the Gateway path starts, so this endpoint never answers.
    let mut json_arguments = gateway_arguments("ws://127.0.0.1:1");
    json_arguments.extend(
        ["--verbose", "--log-file", flag]
            .into_iter()
            .map(OsString::from),
    );
    let json_run = run_cli(json_arguments, None).await;

    assert_eq!(
        json_run.status.code(),
        Some(2),
        "an unusable destination is a usage failure, not a silent redirect"
    );
    let summary = parse_json(&json_run);
    assert_eq!(summary["schema_version"], 2);
    assert_eq!(summary["status"], "log_file_unusable");
    assert_eq!(summary["category"], "usage_config");
    assert_eq!(
        summary["message"],
        "diagnostic log file directory does not exist"
    );
    assert_eq!(summary["endpoint"], "ws://127.0.0.1:1");

    let mut text_arguments: Vec<OsString> = [
        "gateway",
        "health",
        "--endpoint",
        "ws://127.0.0.1:1",
        "--ephemeral-device",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    text_arguments.extend(["-vv", "--log-file", flag].into_iter().map(OsString::from));
    let text_run = run_cli(text_arguments, None).await;

    assert_eq!(text_run.status.code(), Some(2));
    assert!(text_run.stdout.is_empty());
    let text = String::from_utf8(text_run.stderr).expect("UTF-8 failure text");
    assert!(
        text.starts_with(
            "Gateway health failed: diagnostic log file directory does not exist (usage_config)\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("\nnext: point --log-file at a writable path"),
        "{text}"
    );
    assert!(text.contains("\nexit code: 2 (usage_config)\n"), "{text}");
    assert!(
        !text.contains("gta_claw_cli"),
        "not one diagnostic record may fall back to standard error: {text}"
    );
    assert!(!path.exists(), "a failed open creates nothing");
    assert!(!directory.exists(), "and never creates the directory");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_file_without_verbosity_stays_silent_and_opens_nothing() {
    let path = log_path("cli-quiet.jsonl");
    let flag = path.to_str().expect("UTF-8 path").to_owned();
    let outputs = run_healthy(&[&[], &["--log-file", &flag]]).await;

    assert_eq!(
        normalize(&outputs[0]),
        normalize(&outputs[1]),
        "a destination without -v changes nothing"
    );
    assert!(outputs[1].stderr.is_empty());
    assert!(
        !path.exists(),
        "no verbosity means no destination, so the file is never opened"
    );
}

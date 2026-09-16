//! End-to-end TUI worker coverage over a real local WebSocket double.

#[expect(
    dead_code,
    reason = "the Gateway test double is shared with claw-gateway-client, which owns the file; \
              this binary exercises only the subset the TUI worker needs"
)]
#[path = "../../../crates/claw-gateway-client/tests/support/mod.rs"]
mod support;

use std::time::Duration;

use claw_conformance::ReleaseBaseline;
use claw_protocol::gateway::{AUTHENTICATED_MAX_FRAME_BYTES, Codec};
use gta_claw_tui::gateway::{
    GatewayOptions, MemoryCommand, UiCommand, WorkerEvent, spawn_gateway_worker,
};
use gta_claw_tui::model::{RunState, SessionSummary, TranscriptEntry};
use serde_json::json;
use support::{
    TestGateway, complete_handshake, handler, raw_stalled_server, receive_request, send_json,
    wait_for_close,
};

#[cfg(windows)]
struct ProfileCleanup(claw_platform::identity::DeviceProfile);

#[cfg(windows)]
impl Drop for ProfileCleanup {
    fn drop(&mut self) {
        if let Ok(store) = claw_platform::identity::native_store() {
            let _ = self.0.forget(store.as_ref());
        }
    }
}

#[tokio::test]
async fn approval_worker_fetches_complete_preview_and_never_resolves_a_changed_binding() {
    for changed in [false, true] {
        let resolutions = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let captured = std::sync::Arc::clone(&resolutions);
        let token = "e".repeat(64);
        let expected = claw_security::authorization::approval_preview_fingerprint(&token)
            .expect("fingerprint");
        let expected_fingerprint = expected.clone();
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let resolutions = std::sync::Arc::clone(&captured);
            let token = token.clone();
            let fingerprint = expected_fingerprint.clone();
            async move {
                complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
                let sessions = receive_request(&mut socket).await;
                send_json(&mut socket, json!({"type": "res", "id": sessions.id().as_str(), "ok": true, "payload": {"sessions": []}})).await;
                send_json(&mut socket, json!({"type": "event", "event": "exec.approval.requested", "seq": 1, "payload": {"id": "approval-1", "sessionId": "native-session"}})).await;
                for recheck in [false, true] {
                    let preview = receive_request(&mut socket).await;
                    assert_eq!(preview.method().as_str(), "exec.approval.get");
                    let token = if recheck && changed { "d".repeat(64) } else { token.clone() };
                    let fingerprint = if recheck && changed { claw_security::authorization::approval_preview_fingerprint(&token).expect("changed fingerprint") } else { fingerprint.clone() };
                    let mut payload = json!({"id": "approval-1", "sessionId": "native-session", "tool": "fs_write", "previewComplete": true, "bindingToken": token, "previewFingerprint": fingerprint, "toolRevision": 4,
                        "toolPublication": "workspace-fixture", "resourceScope": "workspace: reviewed.txt",
                        "caller": {"source": "Gateway", "subject": "verified-device", "account": null, "permissionGeneration": 0, "owner": false}});
                    payload["prompt"] = json!(format!("{}fs_write\n{{\"path\":\"reviewed.txt\"}}", claw_protocol::native_approval::bound_approval_context_header(&payload).expect("context")));
                    send_json(&mut socket, json!({"type": "res", "id": preview.id().as_str(), "ok": true, "payload": payload})).await;
                }
                if !changed {
                    let resolve = receive_request(&mut socket).await;
                    assert_eq!(resolve.method().as_str(), "approval.resolve");
                    let params: serde_json::Value = serde_json::from_str(resolve.params().value().expect("decision").as_json()).expect("decision JSON");
                    assert_eq!(params["bindingToken"], token);
                    resolutions.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    send_json(&mut socket, json!({"type": "res", "id": resolve.id().as_str(), "ok": true, "payload": {"ok": true}})).await;
                    let next = receive_request(&mut socket).await;
                    assert_eq!(next.method().as_str(), "exec.approval.list");
                    send_json(&mut socket, json!({"type": "res", "id": next.id().as_str(), "ok": true, "payload": {"requests": [], "nextCursor": null}})).await;
                }
                loop {
                    match socket.read_frame().await {
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => { resolutions.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        })).await;
        let mut worker = spawn_gateway_worker(GatewayOptions {
            url: gateway.url.clone(),
            token: None,
            device_profile: None,
        });
        let fingerprint = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let WorkerEvent::Prompt(gta_claw_tui::model::Prompt::Approval {
                    text,
                    preview_fingerprint: Some(fingerprint),
                    ..
                }) = worker.events.recv().await.expect("worker update")
                {
                    assert!(text.contains("reviewed.txt") && text.contains("verified-device"));
                    break fingerprint;
                }
            }
        })
        .await
        .expect("complete preview deadline");
        assert_eq!(fingerprint, expected);
        worker
            .commands
            .send(
                UiCommand::ResolveApproval {
                    id: "approval-1".to_owned(),
                    approved: true,
                    preview_fingerprint: fingerprint,
                }
                .for_connection(1),
            )
            .await
            .expect("queued decision");
        let notice = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let WorkerEvent::Notice(notice) =
                    worker.events.recv().await.expect("decision result")
                {
                    break notice;
                }
            }
        })
        .await
        .expect("decision deadline");
        assert!(
            notice.contains(if changed {
                "preview changed"
            } else {
                "Approval accepted"
            }),
            "{notice}"
        );
        worker.shutdown().await;
        gateway.shutdown().await;
        assert_eq!(
            resolutions.load(std::sync::atomic::Ordering::SeqCst),
            usize::from(!changed)
        );
    }
}

#[tokio::test]
#[cfg(windows)]
async fn native_tui_profile_preserves_handshake_identity_across_worker_restarts() {
    let identities = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = std::sync::Arc::clone(&identities);
    let gateway = TestGateway::spawn(handler(move |mut socket, _| {
        let observed = std::sync::Arc::clone(&observed);
        async move {
            let (_, params) = complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
            support::verify_connect_proof(&params);
            let device = serde_json::to_value(params).expect("handshake JSON")["device"]["id"].as_str().expect("device ID").to_owned();
            observed.lock().expect("captured identity").push(device);
            let request = receive_request(&mut socket).await;
            assert_eq!(request.method().as_str(), "sessions.list");
            send_json(&mut socket, json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":{"sessions":[]}})).await;
            wait_for_close(&mut socket).await;
        }
    })).await;
    let alias = format!(
        "tui-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let cleanup = ProfileCleanup(
        claw_platform::identity::DeviceProfile::new(
            gateway.url.as_str(),
            &alias,
            claw_platform::identity::native_lock_directory().expect("native coordination root"),
        )
        .expect("owned test profile"),
    );
    for _ in 0..2 {
        let mut worker = spawn_gateway_worker(GatewayOptions {
            url: gateway.url.clone(),
            token: None,
            device_profile: Some(alias.clone()),
        });
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                if matches!(worker.events.recv().await, Some(WorkerEvent::Sessions(_))) {
                    break;
                }
            }
        })
        .await
        .expect("native profile handshake completes");
        worker.shutdown().await;
    }
    let observed = identities.lock().expect("captured handshakes").clone();
    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0], observed[1]);
    let store = claw_platform::identity::native_store().expect("native credential store");
    assert!(
        cleanup
            .0
            .forget(store.as_ref())
            .expect("remove exactly the test profile")
    );
    drop(cleanup);
    gateway.shutdown().await;
}

#[tokio::test]
#[cfg(windows)]
async fn native_tui_memory_preflights_capabilities_and_preserves_exact_submission() {
    for scenario in [
        "list",
        "get",
        "search",
        "save",
        "delete",
        "export",
        "import",
        "unsupported",
        "disabled",
        "model",
        "archive-missing",
        "bad-receipt",
        "ephemeral",
        "stale",
        "raw",
    ] {
        let preflight = !matches!(scenario, "ephemeral" | "stale" | "raw");
        let sent = matches!(
            scenario,
            "list" | "get" | "search" | "save" | "delete" | "export" | "import" | "bad-receipt"
        );
        let arguments = match scenario {
            "get" => json!({"action":"get","id":"Mixed.Case","revision":2,"offset":0}),
            "search" => json!({"action":"search","query":"private search","limit":2}),
            "save" => {
                json!({"action":"save","id":"Mixed.Case","kind":"preference","content":"private note\n!goal {}","expectedRevision":2})
            }
            "delete" => json!({"action":"delete","id":"Mixed.Case","expectedRevision":2}),
            "export" | "archive-missing" => json!({"action":"export","revision":2,"offset":0}),
            "import" => {
                json!({"action":"import","expectedRevision":0,"overwrite":false,"archive":{"schemaVersion":1,"notebook":{"revision":0,"entries":[]}}})
            }
            _ => json!({"action":"list"}),
        };
        let expected_arguments = arguments.clone();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_calls = std::sync::Arc::clone(&calls);
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let expected_arguments = expected_arguments.clone();
            let calls = std::sync::Arc::clone(&observed_calls);
            async move {
                let (_, params) = complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
                support::verify_connect_proof(&params);
                let sessions = receive_request(&mut socket).await;
                assert_eq!(sessions.method().as_str(), "sessions.list");
                send_json(&mut socket, json!({"type":"res","id":sessions.id().as_str(),"ok":true,"payload":{"sessions":[]}})).await;
                if preflight {
                    let health = receive_request(&mut socket).await;
                    assert_eq!(health.method().as_str(), "health");
                    let mut payload = json!({"ok":true,"protocol":4,"native":{"schemaVersion":1,"directTool":{"version":1,"prefix":"!tool ","modelInvoked":false,"authenticated":true,"durableRuns":true,"approvalPolicy":"per-tool","accepting":true},"explicitMemory":{"enabled":true,"accepting":true,"requiresApproval":true,"partition":"source/subject/account","automaticContextInjection":false,"archiveSchemaVersion":1}}});
                    match scenario {
                        "unsupported" => payload = json!({"ok":true,"protocol":4}),
                        "disabled" => payload["native"]["explicitMemory"]["enabled"] = json!(false),
                        "model" => payload["native"]["directTool"]["modelInvoked"] = json!(true),
                        "archive-missing" => { let _ = payload["native"]["explicitMemory"].as_object_mut().expect("memory object").remove("archiveSchemaVersion"); }
                        _ => {}
                    }
                    send_json(&mut socket, json!({"type":"res","id":health.id().as_str(),"ok":true,"payload":payload})).await;
                }
                if sent {
                    let submission = receive_request(&mut socket).await;
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    assert_eq!(submission.method().as_str(), "chat.send");
                    let params: serde_json::Value = serde_json::from_str(submission.params().value().expect("submission").as_json()).expect("JSON");
                    assert_eq!(params["sessionKey"], "memory-session");
                    assert_eq!(params["idempotencyKey"], "original-memory-key");
                    let message = params["message"].as_str().expect("single command");
                    assert_eq!(message.lines().count(), 1);
                    let envelope: serde_json::Value = serde_json::from_str(message.strip_prefix("!tool ").expect("typed direct tool")).expect("envelope");
                    assert_eq!(envelope, json!({"name":"memory_notes","arguments":expected_arguments}));
                    let revision = u64::from(scenario != "bad-receipt");
                    send_json(&mut socket, json!({"type":"res","id":submission.id().as_str(),"ok":true,"payload":{"status":"accepted","durable":true,"sessionId":"memory-session","runId":"a".repeat(64),"revision":revision,"phase":"queued"}})).await;
                    if scenario != "bad-receipt" {
                        let result = receive_request(&mut socket).await;
                        assert_eq!(result.method().as_str(), "agent.wait");
                        send_json(&mut socket, json!({"type":"res","id":result.id().as_str(),"ok":true,"payload":{"durable":true,"sessionId":"memory-session","runId":"a".repeat(64),"phase":"finished","revision":3,"result":{"status":"completed","text":"untrusted memory result"}}})).await;
                    }
                }
                loop {
                    match socket.read_frame().await {
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => { calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        })).await;
        let alias = format!(
            "tui-memory-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let cleanup = ProfileCleanup(
            claw_platform::identity::DeviceProfile::new(
                gateway.url.as_str(),
                &alias,
                claw_platform::identity::native_lock_directory().expect("coordination root"),
            )
            .expect("owned profile"),
        );
        let mut worker = spawn_gateway_worker(GatewayOptions {
            url: gateway.url.clone(),
            token: None,
            device_profile: (scenario != "ephemeral").then_some(alias),
        });
        tokio::time::timeout(Duration::from_secs(4), async {
            while !matches!(
                worker.events.recv().await.expect("worker update"),
                WorkerEvent::Sessions(_)
            ) {}
        })
        .await
        .expect("ready profile");
        let command = if scenario == "raw" {
            UiCommand::SendMessage {
                session_id: "memory-session".to_owned(),
                text: " !TOOL= {\"name\":\"memory_notes\",\"arguments\":{\"action\":\"list\"}}"
                    .to_owned(),
                idempotency_key: "original-memory-key".to_owned(),
            }
        } else {
            UiCommand::InvokeMemory {
                session_id: "memory-session".to_owned(),
                command: MemoryCommand::new(arguments).expect("typed command"),
                idempotency_key: "original-memory-key".to_owned(),
            }
        };
        worker
            .commands
            .send(command.for_connection(if scenario == "stale" { 9 } else { 1 }))
            .await
            .expect("command queue");
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                match worker.events.recv().await.expect("memory result") {
                    WorkerEvent::SendNotSent {
                        idempotency_key, ..
                    } => {
                        assert!(!sent, "{scenario}");
                        assert_eq!(idempotency_key, "original-memory-key");
                        break;
                    }
                    WorkerEvent::SendUnconfirmed { idempotency_key } => {
                        assert_eq!(scenario, "bad-receipt");
                        assert_eq!(idempotency_key, "original-memory-key");
                        break;
                    }
                    WorkerEvent::NativeRun {
                        text: Some(text),
                        revision,
                        ..
                    } => {
                        assert!(sent && scenario != "bad-receipt");
                        assert_eq!(text, "untrusted memory result");
                        assert_eq!(revision, 3);
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("bounded memory outcome");
        worker.shutdown().await;
        gateway.shutdown().await;
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            usize::from(sent),
            "{scenario}"
        );
        drop(cleanup);
    }
}

#[tokio::test]
async fn native_tui_accounting_crosses_real_worker_without_granting_ack_or_replay() {
    use claw_protocol::native_accounting::{AccountingSource, CounterCoverage};
    for scenario in [
        "missing",
        "unreported",
        "partial",
        "zero",
        "journal",
        "overflow",
        "bad-total",
        "nonterminal",
        "missing-turn",
    ] {
        let valid = !matches!(scenario, "bad-total" | "nonterminal" | "missing-turn");
        let rounds = if matches!(scenario, "journal" | "overflow") {
            2
        } else {
            1
        };
        let mut accounting = json!({
            "available":true,"recordedRounds":rounds,
            "completeCounterRounds":if scenario == "overflow" {2} else {u16::from(matches!(scenario, "zero" | "journal" | "bad-total" | "nonterminal" | "missing-turn"))},
            "partialCounterRounds":u16::from(scenario == "partial"),
            "unreportedRounds":u16::from(matches!(scenario, "unreported" | "journal" | "missing")),
            "allPrimaryCountersReported":matches!(scenario, "zero" | "bad-total" | "nonterminal" | "missing-turn"),
            "observedTokens":{"inputTokens":0,"outputTokens":0,"totalTokens":u16::from(scenario == "bad-total"),"cachedInputTokens":0,"reasoningTokens":0},
            "aggregationOverflow":scenario == "overflow","costCalculated":false,"billingReconciled":false,
            "recordSource":"terminal_turn","attemptsMayBeUnsent":true,
        });
        if scenario == "missing" {
            accounting = serde_json::Value::Null;
        } else if scenario == "journal" {
            accounting["recordSource"] = json!("provider_journal");
            accounting["journalRevision"] = json!(2);
            accounting["journalClosed"] = json!(false);
            accounting["observedTokens"] = json!({"inputTokens":5,"outputTokens":2,"totalTokens":7,"cachedInputTokens":1,"reasoningTokens":1});
        } else if scenario == "overflow" {
            accounting["observedTokens"] = serde_json::Value::Null;
        }
        let unexpected = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = std::sync::Arc::clone(&unexpected);
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let accounting = accounting.clone();
            let observed = std::sync::Arc::clone(&observed);
            async move {
                complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
                let sessions = receive_request(&mut socket).await;
                send_json(&mut socket, json!({"type":"res","id":sessions.id().as_str(),"ok":true,"payload":{"sessions":[]}})).await;
                let submission = receive_request(&mut socket).await;
                assert_eq!(submission.method().as_str(), "chat.send");
                send_json(&mut socket, json!({"type":"res","id":submission.id().as_str(),"ok":true,"payload":{"durable":true,"sessionId":"accounting-session","runId":"a".repeat(64)}})).await;
                let query = receive_request(&mut socket).await;
                assert_eq!(query.method().as_str(), "agent.wait");
                let parameters: serde_json::Value = serde_json::from_str(query.params().value().expect("read params").as_json()).expect("read JSON");
                assert_eq!(parameters, json!({"runId":"a".repeat(64),"timeoutMs":0}));
                let mut payload = json!({
                    "durable":true,"sessionId":"accounting-session","runId":"a".repeat(64),
                    "revision":4,"turn":2,"phase":"outcome_unknown","status":"outcome_unknown",
                    "result":null,"providerAccounting":accounting,
                });
                if scenario == "bad-total" {
                    payload["result"] = json!({"status":"completed","text":"not eligible for ACK"});
                } else if scenario == "nonterminal" {
                    payload["phase"] = json!("executing");
                } else if scenario == "missing-turn" {
                    payload.as_object_mut().expect("object").remove("turn");
                }
                send_json(&mut socket, json!({"type":"res","id":query.id().as_str(),"ok":true,"payload":payload})).await;
                loop {
                    match socket.read_frame().await {
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => { observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        })).await;
        let mut worker = spawn_gateway_worker(GatewayOptions {
            url: gateway.url.clone(),
            token: None,
            device_profile: None,
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            while !matches!(
                worker.events.recv().await.expect("startup"),
                WorkerEvent::Sessions(_)
            ) {}
        })
        .await
        .expect("ready worker");
        worker
            .commands
            .send(
                UiCommand::SendMessage {
                    session_id: "accounting-session".to_owned(),
                    text: "fixture".to_owned(),
                    idempotency_key: "accounting-fixture-key".to_owned(),
                }
                .for_connection(1),
            )
            .await
            .expect("explicit submission");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match worker.events.recv().await.expect("accounting update") {
                    WorkerEvent::NativeRun {
                        session_id,
                        run_id,
                        state,
                        text,
                        revision,
                        provider_accounting,
                        ..
                    } => {
                        assert!(valid, "{scenario}");
                        assert_eq!(session_id, "accounting-session");
                        assert_eq!(run_id, "a".repeat(64));
                        assert_eq!(state, RunState::OutcomeUnknown);
                        assert_eq!(revision, 4);
                        assert!(text.is_none());
                        if scenario == "missing" {
                            assert!(provider_accounting.is_none());
                        } else {
                            let report = provider_accounting.expect("validated accounting");
                            let coverage = match scenario {
                                "zero" => CounterCoverage::Complete,
                                "partial" | "journal" => CounterCoverage::Partial,
                                "overflow" => CounterCoverage::Overflow,
                                _ => CounterCoverage::Unreported,
                            };
                            assert_eq!(report.coverage, coverage);
                            if scenario == "journal" {
                                assert_eq!(
                                    report.source,
                                    AccountingSource::ProviderJournal {
                                        revision: 2,
                                        closed: false
                                    }
                                );
                                assert_eq!(
                                    report
                                        .observed_tokens
                                        .expect("observed subset")
                                        .total_tokens,
                                    7
                                );
                            }
                        }
                        break;
                    }
                    WorkerEvent::Notice(notice) => {
                        assert!(!valid, "{scenario}: {notice}");
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("bounded accounting result");
        worker
            .commands
            .send(
                UiCommand::AcknowledgeRun {
                    run_id: "a".repeat(64),
                    revision: 4,
                }
                .for_connection(1),
            )
            .await
            .expect("attempted ACK");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let WorkerEvent::Notice(notice) =
                    worker.events.recv().await.expect("local ACK rejection")
                {
                    assert!(
                        notice.contains("not delivered completely"),
                        "{scenario}: {notice}"
                    );
                    break;
                }
            }
        })
        .await
        .expect("ACK refused locally");
        worker.shutdown().await;
        gateway.shutdown().await;
        assert_eq!(
            unexpected.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "{scenario}"
        );
    }
}

#[tokio::test]
async fn native_tui_model_catalogue_reads_and_refreshes_without_chat_ack_or_selection() {
    use gta_claw_tui::gateway::{ModelCatalogueAction, ModelCatalogueRequest};
    use serde_json::Value;
    use std::fmt::Write as _;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    for scenario in [
        "pages",
        "refresh",
        "refresh-refused",
        "bad-page",
        "unavailable",
        "stale",
        "availability-disabled",
        "availability-authentication_pending",
        "availability-not_initialized",
        "availability-retired",
        "availability-private-remote-secret",
        "availability-refused",
    ] {
        let availability = scenario.strip_prefix("availability-");
        let snapshot = json!({"provider":"fixture","providerGeneration":1,"selectedModel":"fixture-model-0","selectionPinned":true,
            "observedAtMs":123,"source":"provider_sdk_catalogue","liveCapabilitiesVerified":false,
            "models":(0..9).map(|ordinal|json!({"id":format!("fixture-model-{ordinal}"),"displayName":null,
                "contextWindow":null,"maxOutputTokens":null,"advertisedCapabilities":["completion"]})).collect::<Vec<_>>()});
        let mut digest = String::with_capacity(64);
        for byte in ring::digest::digest(
            &ring::digest::SHA256,
            &serde_json::to_vec(&snapshot).expect("snapshot"),
        )
        .as_ref()
        {
            write!(digest, "{byte:02x}").expect("snapshot digest");
        }
        let mut first = json!({"schemaVersion":1,"available":true,"offset":0,"endOffset":8,"nextOffset":8,"totalModels":9,"sha256":digest,
            "provider":"fixture","providerGeneration":1,"selectedModel":"fixture-model-0","selectionPinned":true,"observedAtMs":123,
            "source":"provider_sdk_catalogue","liveCapabilitiesVerified":false,"selectionChanged":false,"networkContacted":false,
            "models":&snapshot["models"].as_array().expect("models")[..8]});
        if scenario == "bad-page" {
            first["models"][0]["displayName"] = json!("private-remote\nlabel");
        }
        if scenario == "unavailable" {
            first = json!({"schemaVersion":1,"available":false,"selectionChanged":false,"networkContacted":false});
        }
        if let Some(reason) = availability {
            first = json!({"schemaVersion":1,"available":false,"unavailableReason":reason,"selectionChanged":false,"networkContacted":false});
        }
        let mut actions = if availability.is_some() {
            vec![ModelCatalogueAction::Availability]
        } else {
            vec![ModelCatalogueAction::Read {
                offset: 0,
                sha256: None,
            }]
        };
        let mut replies = vec![first.clone()];
        if scenario == "pages" {
            actions.push(ModelCatalogueAction::Read {
                offset: 8,
                sha256: Some(digest.clone()),
            });
            first["offset"] = json!(8);
            first["endOffset"] = json!(9);
            first["nextOffset"] = Value::Null;
            first["models"] = json!([snapshot["models"][8]]);
            replies.push(first);
        } else if matches!(scenario, "refresh" | "refresh-refused") {
            actions.push(ModelCatalogueAction::Refresh {
                sha256: digest.clone(),
            });
            replies.push(json!({"schemaVersion":1,"refreshed":true,"provider":"fixture","providerGeneration":1,"requestedSha256":digest,
                "selectedModel":"fixture-model-0","totalModels":9,"selectionChanged":false,"networkContacted":true,"inferenceInvoked":false}));
        }
        let expected_calls = if scenario == "stale" {
            0
        } else {
            actions.len()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let expected_actions = actions.clone();
        let gateway = TestGateway::spawn(handler(move |mut socket,_| {
            let replies = replies.clone();
            let actions = expected_actions.clone();
            let calls = Arc::clone(&observed);
            async move {
                complete_handshake(&mut socket,AUTHENTICATED_MAX_FRAME_BYTES).await;
                let sessions = receive_request(&mut socket).await;
                send_json(&mut socket,json!({"type":"res","id":sessions.id().as_str(),"ok":true,"payload":{"sessions":[]}})).await;
                if scenario != "stale" {
                    for (ordinal,(action,reply)) in actions.into_iter().zip(replies).enumerate() {
                        let request = receive_request(&mut socket).await;
                        calls.fetch_add(1,Ordering::SeqCst);
                        assert_eq!(request.method().as_str(),"models.list");
                        let actual:Value = serde_json::from_str(request.params().value().expect("params").as_json()).expect("JSON");
                        let expected = match action {
                            ModelCatalogueAction::Availability => json!({"nativeCatalogPage":{"offset":0,"includeAvailability":true}}),
                            ModelCatalogueAction::Read {offset,sha256} => {
                                let mut params = json!({"nativeCatalogPage":{"offset":offset}});
                                if let Some(digest) = sha256 {params["nativeCatalogPage"]["sha256"] = json!(digest);}
                                params
                            }
                            ModelCatalogueAction::Refresh {sha256} => json!({"nativeCatalogRefresh":{"sha256":sha256}}),
                        };
                        assert_eq!(actual,expected);
                        if scenario == "refresh-refused" && ordinal == 1 || scenario == "availability-refused" {
                            send_json(&mut socket,json!({"type":"res","id":request.id().as_str(),"ok":false,"error":{"code":"INVALID_REQUEST","message":"private-remote-secret"}})).await;
                        } else {send_json(&mut socket,json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":reply})).await;}
                    }
                }
                loop {match socket.read_frame().await {
                    Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => {calls.fetch_add(1,Ordering::SeqCst);}
                    Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => break,
                    Ok(_)=>{},Err(_)=>break,
                }}
            }
        })).await;
        let mut worker = spawn_gateway_worker(GatewayOptions {
            url: gateway.url.clone(),
            token: None,
            device_profile: None,
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if matches!(worker.events.recv().await, Some(WorkerEvent::Sessions(_))) {
                    break;
                }
            }
        })
        .await
        .expect("ready worker");
        for (ordinal, action) in actions.into_iter().enumerate() {
            let request = ModelCatalogueRequest {
                connection_id: 1,
                sequence: u64::try_from(ordinal + 1).expect("sequence"),
                action,
            };
            worker
                .commands
                .send(
                    UiCommand::ModelCatalogue(request.clone())
                        .for_connection(if scenario == "stale" { 2 } else { 1 }),
                )
                .await
                .expect("queued catalogue");
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    match worker.events.recv().await.expect("catalogue outcome") {
                        WorkerEvent::ModelCatalogue {
                            request: returned,
                            result,
                        } => {
                            assert_eq!(returned, request);
                            assert_eq!(
                                result.is_ok(),
                                !(scenario == "bad-page"
                                    || scenario == "refresh-refused" && ordinal == 1
                                    || matches!(
                                        scenario,
                                        "availability-private-remote-secret"
                                            | "availability-refused"
                                    )),
                                "{scenario}: {result:?}"
                            );
                            match result {
                                Ok(page) => {
                                    if let Some(reason) = availability {
                                        assert_eq!(page["unavailableReason"], reason);
                                    }
                                }
                                Err(error) => assert!(!error.contains("private-remote")),
                            }
                            break;
                        }
                        WorkerEvent::Notice(notice) if scenario == "stale" => {
                            assert!(notice.contains("previous connection"));
                            break;
                        }
                        WorkerEvent::NativeRun { .. } | WorkerEvent::ResultAcknowledged { .. } => {
                            panic!("catalogue cannot deliver or acknowledge chat")
                        }
                        _ => {}
                    }
                }
            })
            .await
            .expect("bounded catalogue result");
        }
        worker
            .commands
            .send(
                UiCommand::AcknowledgeRun {
                    run_id: "a".repeat(64),
                    revision: 4,
                }
                .for_connection(1),
            )
            .await
            .expect("attempt ACK");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let WorkerEvent::Notice(notice) =
                    worker.events.recv().await.expect("ACK refusal")
                {
                    assert!(notice.contains("not delivered completely"));
                    break;
                }
            }
        })
        .await
        .expect("local ACK refusal");
        worker.shutdown().await;
        gateway.shutdown().await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            expected_calls,
            "{scenario}: no extra RPC"
        );
    }
}

#[tokio::test]
async fn native_tui_accounting_pages_are_bound_read_only_and_never_acknowledge_results() {
    use gta_claw_tui::gateway::AccountingPageRequest;
    use serde_json::Value;
    use std::fmt::Write as _;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    for scenario in [
        "valid",
        "zero",
        "missing",
        "bad-digest",
        "identity",
        "provenance",
        "extra",
        "stale",
    ] {
        let total = if matches!(scenario, "valid" | "provenance") {
            17
        } else {
            1
        };
        let tokens = json!({"inputTokens":0,"outputTokens":0,"totalTokens":0,"cachedInputTokens":0,"reasoningTokens":0});
        let snapshot = json!({"summary":{"available":true,"recordedRounds":total,"completeCounterRounds":1,"partialCounterRounds":0,"unreportedRounds":total-1,
            "allPrimaryCountersReported":total==1,"observedTokens":tokens,"aggregationOverflow":false,"costCalculated":false,"billingReconciled":false,
            "recordSource":"provider_journal","journalRevision":7,"journalClosed":false,"attemptsMayBeUnsent":true},
            "rounds":(0..total).map(|round| json!({"round":round,"response":if round == 0 { json!({"provider":"fixture","model":"private-model",
                "responseId":"response-123","usageReporting":"complete","finishReason":"stop","observedTokens":tokens}) } else {Value::Null}})).collect::<Vec<_>>()});
        let mut digest = String::with_capacity(64);
        for byte in ring::digest::digest(
            &ring::digest::SHA256,
            &serde_json::to_vec(&snapshot).expect("snapshot"),
        )
        .as_ref()
        {
            write!(digest, "{byte:02x}").expect("digest");
        }
        let first_end = total.min(16);
        let mut page = json!({"runId":"a".repeat(64),"sessionId":"owned","revision":4,"turn":0,"status":"outcome_unknown",
            "durable":true,"acknowledged":false,"automaticReplay":false,"accounting":{"available":true,"offset":0,"endOffset":first_end,
                "nextOffset":(total > 16).then_some(16),"totalRounds":total,"sha256":digest,"summary":snapshot["summary"],
                "rounds":&snapshot["rounds"].as_array().expect("rounds")[..first_end]}});
        if scenario == "missing" {
            page["accounting"] = json!({"available":false});
        }
        if scenario == "bad-digest" {
            page["accounting"]["sha256"] = json!("0".repeat(64));
        }
        if scenario == "identity" {
            page["sessionId"] = json!("other");
        }
        if scenario == "extra" {
            page["accounting"]["rounds"][0]["response"]["prompt"] = json!("private-prompt");
        }
        let mut pages = vec![page.clone()];
        if total > 16 {
            page["accounting"]["offset"] = json!(16);
            page["accounting"]["endOffset"] = json!(17);
            page["accounting"]["nextOffset"] = Value::Null;
            page["accounting"]["rounds"] = json!([snapshot["rounds"][16]]);
            if scenario == "provenance" {
                page["accounting"]["summary"]["journalRevision"] = json!(8);
            }
            pages.push(page);
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let captured = Arc::clone(&calls);
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let pages = pages.clone();
            let calls = Arc::clone(&captured);
            let digest = digest.clone();
            async move {
                complete_handshake(&mut socket,AUTHENTICATED_MAX_FRAME_BYTES).await;
                let sessions = receive_request(&mut socket).await;
                send_json(&mut socket,json!({"type":"res","id":sessions.id().as_str(),"ok":true,"payload":{"sessions":[]}})).await;
                if scenario != "stale" {
                    for (index,page) in pages.into_iter().enumerate() {
                        let request = receive_request(&mut socket).await;
                        calls.fetch_add(1,Ordering::SeqCst);
                        assert_eq!(request.method().as_str(),"agent.wait");
                        let actual:Value = serde_json::from_str(request.params().value().expect("params").as_json()).expect("JSON");
                        let mut expected = json!({"runId":"a".repeat(64),"accountingPage":{"revision":4,"offset":index*16}});
                        if index > 0 {expected["accountingPage"]["sha256"] = json!(digest);}
                        assert_eq!(actual,expected,"no ACK, wait, inference or replay");
                        send_json(&mut socket,json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":page})).await;
                    }
                }
                loop {
                    match socket.read_frame().await {
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => {calls.fetch_add(1,Ordering::SeqCst);}
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => break,
                        Ok(_) => {}, Err(_) => break,
                    }
                }
            }
        })).await;
        let mut worker = spawn_gateway_worker(GatewayOptions {
            url: gateway.url.clone(),
            token: None,
            device_profile: None,
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if matches!(worker.events.recv().await, Some(WorkerEvent::Sessions(_))) {
                    break;
                }
            }
        })
        .await
        .expect("ready");
        let request = AccountingPageRequest {
            connection_id: 1,
            session_id: "owned".to_owned(),
            run_id: "a".repeat(64),
            revision: 4,
            turn: 0,
            state: RunState::OutcomeUnknown,
            offset: 0,
            total_rounds: None,
            sha256: None,
            summary: None,
        };
        worker
            .commands
            .send(
                UiCommand::ReadAccounting(request).for_connection(if scenario == "stale" {
                    9
                } else {
                    1
                }),
            )
            .await
            .expect("page command");
        let pages_received = tokio::time::timeout(Duration::from_secs(3), async {
            let mut received = 0;
            loop {
                match worker.events.recv().await.expect("event") {
                    WorkerEvent::AccountingPage(page) => {
                        received += 1;
                        if let Some(offset) = page.next_offset {
                            let next = AccountingPageRequest {
                                offset,
                                total_rounds: Some(page.total_rounds),
                                sha256: Some(page.sha256),
                                summary: Some(page.summary),
                                ..page.request
                            };
                            worker
                                .commands
                                .send(UiCommand::ReadAccounting(next).for_connection(1))
                                .await
                                .expect("next page");
                        } else {
                            break received;
                        }
                    }
                    WorkerEvent::Notice(notice) => {
                        assert!(
                            !matches!(scenario, "valid" | "zero"),
                            "{scenario}: {notice}"
                        );
                        assert!(
                            !notice.contains("private-model") && !notice.contains("private-prompt")
                        );
                        break received;
                    }
                    WorkerEvent::NativeRun { .. } => {
                        panic!("accounting cannot become a complete result")
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("bounded page response");
        assert_eq!(
            pages_received,
            match scenario {
                "valid" => 2,
                "zero" | "provenance" => 1,
                _ => 0,
            },
            "{scenario}"
        );
        worker
            .commands
            .send(
                UiCommand::AcknowledgeRun {
                    run_id: "a".repeat(64),
                    revision: 4,
                }
                .for_connection(1),
            )
            .await
            .expect("attempt ACK");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let WorkerEvent::Notice(notice) =
                    worker.events.recv().await.expect("refused ACK")
                {
                    assert!(notice.contains("not delivered completely"), "{notice}");
                    break;
                }
            }
        })
        .await
        .expect("ACK refused locally");
        worker.shutdown().await;
        gateway.shutdown().await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if scenario == "stale" {
                0
            } else {
                total.div_ceil(16)
            },
            "{scenario}"
        );
    }
}

#[tokio::test]
async fn native_tui_send_cancel_and_result_ack_keep_exact_run_and_revision() {
    let baseline = ReleaseBaseline::load(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/releases/v2026.9.4"),
    )
    .expect("reviewed upstream request schemas");
    let run_id = "a".repeat(64);
    let expected = run_id.clone();
    let acknowledged = std::sync::Arc::new(tokio::sync::Notify::new());
    let received_ack = std::sync::Arc::clone(&acknowledged);
    let gateway = TestGateway::spawn(handler(move |mut socket, _| {
        let baseline = baseline.clone();
        let run_id = run_id.clone();
        let received_ack = std::sync::Arc::clone(&received_ack);
        async move {
            complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
            let sessions = receive_request(&mut socket).await;
            send_json(&mut socket, json!({"type":"res","id":sessions.id().as_str(),"ok":true,"payload":{"sessions":[]}})).await;
            let send = receive_request(&mut socket).await;
            assert_eq!(send.method().as_str(), "chat.send");
            let params: serde_json::Value = serde_json::from_str(send.params().value().expect("submission").as_json()).expect("submission JSON");
            assert_eq!(params, json!({"sessionKey":"native-session","message":"hello native TUI","idempotencyKey":"retained-key"}));
            baseline.validate_gateway_request("chat.send", &params).expect("upstream-compatible send parameters");
            send_json(&mut socket, json!({"type":"res","id":send.id().as_str(),"ok":true,"payload":{"durable":true,"sessionId":"native-session","runId":run_id}})).await;
            let running = receive_request(&mut socket).await;
            assert_eq!(running.method().as_str(), "agent.wait");
            let params = serde_json::from_str(running.params().value().expect("wait").as_json()).expect("wait JSON");
            baseline.validate_gateway_request("agent.wait", &params).expect("upstream-compatible wait parameters");
            send_json(&mut socket, json!({"type":"res","id":running.id().as_str(),"ok":true,"payload":{"durable":true,"sessionId":"native-session","runId":run_id,"phase":"executing","status":"executing","revision":2,"result":null}})).await;
            let abort = receive_request(&mut socket).await;
            assert_eq!(abort.method().as_str(), "chat.abort");
            let params: serde_json::Value = serde_json::from_str(abort.params().value().expect("cancellation").as_json()).expect("cancellation JSON");
            assert_eq!(params, json!({"sessionKey":"native-session","runId":run_id}));
            baseline.validate_gateway_request("chat.abort", &params).expect("upstream-compatible cancellation parameters");
            send_json(&mut socket, json!({"type":"res","id":abort.id().as_str(),"ok":true,"payload":{"aborted":true}})).await;
            let terminal = receive_request(&mut socket).await;
            assert_eq!(terminal.method().as_str(), "agent.wait");
            send_json(&mut socket, json!({"type":"res","id":terminal.id().as_str(),"ok":true,"payload":{"durable":true,"sessionId":"native-session","runId":run_id,"phase":"finished","revision":3,"result":{"status":"cancelled","text":"cancelled result"}}})).await;
            let ack = receive_request(&mut socket).await;
            assert_eq!(ack.method().as_str(), "agent.wait");
            let params: serde_json::Value = serde_json::from_str(ack.params().value().expect("result acknowledgement").as_json()).expect("ACK JSON");
            assert_eq!(params, json!({"runId":run_id,"acknowledgeRevision":3}));
            assert!(baseline.validate_gateway_request("agent.wait", &params).is_err(), "native durable ACK must remain distinguished from the upstream request contract");
            send_json(&mut socket, json!({"type":"res","id":ack.id().as_str(),"ok":true,"payload":{"runId":run_id,"revision":3,"acknowledged":true,"durable":true}})).await;
            received_ack.notify_one();
            wait_for_close(&mut socket).await;
        }
    })).await;
    let mut worker = spawn_gateway_worker(GatewayOptions {
        url: gateway.url.clone(),
        token: None,
        device_profile: None,
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if matches!(worker.events.recv().await, Some(WorkerEvent::Sessions(_))) {
                break;
            }
        }
    })
    .await
    .expect("initial ready state");
    worker
        .commands
        .send(
            UiCommand::SendMessage {
                session_id: "native-session".to_owned(),
                text: "hello native TUI".to_owned(),
                idempotency_key: "retained-key".to_owned(),
            }
            .for_connection(1),
        )
        .await
        .expect("message queue");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(WorkerEvent::NativeRun {
                run_id,
                state,
                text,
                ..
            }) = worker.events.recv().await
            {
                assert_eq!(run_id, expected);
                assert_eq!(state, RunState::Running);
                assert!(text.is_none());
                break;
            }
        }
    })
    .await
    .expect("run accepted and active");
    worker
        .commands
        .send(
            UiCommand::AcknowledgeRun {
                run_id: expected.clone(),
                revision: 2,
            }
            .for_connection(1),
        )
        .await
        .expect("invalid early ACK");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(WorkerEvent::Notice(notice)) = worker.events.recv().await
                && notice.contains("not delivered completely")
            {
                break;
            }
        }
    })
    .await
    .expect("early ACK rejected locally");
    worker
        .commands
        .send(
            UiCommand::AbortRun {
                session_id: "native-session".to_owned(),
                run_id: expected.clone(),
            }
            .for_connection(1),
        )
        .await
        .expect("exact cancellation");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(WorkerEvent::NativeRun {
                run_id,
                state,
                text,
                revision,
                ..
            }) = worker.events.recv().await
            {
                assert_eq!(run_id, expected);
                assert_eq!(state, RunState::Cancelled);
                assert_eq!(text.as_deref(), Some("cancelled result"));
                assert_eq!(revision, 3);
                break;
            }
        }
    })
    .await
    .expect("complete cancelled result");
    worker
        .commands
        .send(
            UiCommand::AcknowledgeRun {
                run_id: expected,
                revision: 3,
            }
            .for_connection(1),
        )
        .await
        .expect("complete exact ACK");
    tokio::time::timeout(Duration::from_secs(3), acknowledged.notified())
        .await
        .expect("server actually receives the exact ACK");
    worker.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn native_tui_partial_pages_are_bound_read_only_and_never_acknowledge_results() {
    use gta_claw_tui::gateway::PartialPageRequest;
    use std::fmt::Write as _;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    for mode in [
        "valid",
        "empty",
        "corrupt",
        "identity-changed",
        "complete",
        "unknown-field",
        "stale",
    ] {
        let text = if mode == "valid" {
            format!("{}\u{754c}tail", "x".repeat(2047))
        } else if mode == "empty" {
            String::new()
        } else {
            "untrusted-must-not-be-displayed".to_owned()
        };
        let mut digest = String::new();
        for byte in ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref() {
            write!(digest, "{byte:02x}").expect("digest");
        }
        let first_end = text.len().min(2047);
        let mut pages = vec![
            json!({"runId":"a".repeat(64),"sessionId":"owned","revision":3,"turn":0,"status":"outcome_unknown","durable":true,"acknowledged":false,"automaticReplay":false,
            "partial":{"available":true,"text":&text[..first_end],"offset":0,"nextOffset":(first_end < text.len()).then_some(first_end),"totalBytes":text.len(),"sha256":digest,"messageComplete":false,"untrusted":true,"reasoningIncluded":false,"toolArgumentsIncluded":false}}),
        ];
        if mode == "valid" {
            let mut last = pages[0].clone();
            last["partial"]["text"] = json!(&text[first_end..]);
            last["partial"]["offset"] = json!(first_end);
            last["partial"]["nextOffset"] = serde_json::Value::Null;
            pages.push(last);
        }
        match mode {
            "corrupt" => pages[0]["partial"]["sha256"] = json!("0".repeat(64)),
            "identity-changed" => pages[0]["sessionId"] = json!("other"),
            "complete" => pages[0]["partial"]["messageComplete"] = json!(true),
            "unknown-field" => pages[0]["partial"]["extra"] = json!("must not pass"),
            _ => {}
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let expected_digest = digest.clone();
        let gateway = TestGateway::spawn(handler(move |mut socket, connection| {
            let calls = Arc::clone(&observed);
            let pages = pages.clone();
            let digest = expected_digest.clone();
            async move {
                assert_eq!(connection, 0);
                complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
                let sessions = receive_request(&mut socket).await;
                assert_eq!(sessions.method().as_str(), "sessions.list");
                send_json(&mut socket, json!({"type":"res","id":sessions.id().as_str(),"ok":true,"payload":{"sessions":[]}})).await;
                if mode != "stale" {
                    for (index, page) in pages.into_iter().enumerate() {
                        let request = receive_request(&mut socket).await;
                        assert_eq!(request.method().as_str(), "agent.wait");
                        let actual: serde_json::Value = serde_json::from_str(request.params().value().expect("params").as_json()).expect("request");
                        let mut expected = json!({"runId":"a".repeat(64),"partialPage":{"revision":3,"offset":if index == 0 { 0 } else { first_end }}});
                        if index > 0 { expected["partialPage"]["sha256"] = json!(digest); }
                        assert_eq!(actual, expected, "page reads contain no ACK or mutation");
                        calls.fetch_add(1, Ordering::SeqCst);
                        send_json(&mut socket, json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":page})).await;
                    }
                }
                loop {
                    match socket.read_frame().await {
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => panic!("partial viewing issued an unexpected extra request"),
                        Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => break,
                        Ok(_) => {},
                        Err(_) => break,
                    }
                }
            }
        })).await;
        let mut worker = spawn_gateway_worker(GatewayOptions {
            url: gateway.url.clone(),
            token: None,
            device_profile: None,
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if matches!(worker.events.recv().await, Some(WorkerEvent::Sessions(_))) {
                    break;
                }
            }
        })
        .await
        .expect("worker ready");
        let request = PartialPageRequest {
            session_id: "owned".to_owned(),
            run_id: "a".repeat(64),
            revision: 3,
            turn: 0,
            state: RunState::OutcomeUnknown,
            offset: 0,
            total_bytes: None,
            sha256: None,
        };
        worker
            .commands
            .send(
                UiCommand::ReadPartial(request).for_connection(if mode == "stale" { 9 } else { 1 }),
            )
            .await
            .expect("explicit first page");
        let page = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match worker.events.recv().await.expect("worker event") {
                    WorkerEvent::PartialPage(page) => break Ok(page),
                    WorkerEvent::Notice(notice) => break Err(notice),
                    _ => {}
                }
            }
        })
        .await
        .expect("bounded first page");
        if matches!(mode, "valid" | "empty") {
            let first = page.expect("validated partial event");
            assert_eq!(first.text, text[..first_end]);
            assert_eq!(first.sha256, digest);
            worker
                .commands
                .send(
                    UiCommand::AcknowledgeRun {
                        run_id: "a".repeat(64),
                        revision: 3,
                    }
                    .for_connection(1),
                )
                .await
                .expect("refused partial ACK probe");
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let Some(WorkerEvent::Notice(notice)) = worker.events.recv().await {
                        assert!(notice.contains("not delivered completely"));
                        break;
                    }
                }
            })
            .await
            .expect("partial cannot become ACK eligible");
            if let Some(offset) = first.next_offset {
                let next = PartialPageRequest {
                    offset,
                    total_bytes: Some(first.total_bytes),
                    sha256: Some(first.sha256),
                    ..first.request
                };
                worker
                    .commands
                    .send(UiCommand::ReadPartial(next).for_connection(1))
                    .await
                    .expect("next explicit page");
                let last = tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        if let Some(WorkerEvent::PartialPage(page)) = worker.events.recv().await {
                            break page;
                        }
                    }
                })
                .await
                .expect("bounded continuation");
                assert_eq!(last.text, text[first_end..]);
                assert!(last.next_offset.is_none());
            }
        } else {
            let notice = page.expect_err("bad or stale page refused");
            assert!(!notice.contains("untrusted-must-not-be-displayed"));
        }
        worker.shutdown().await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if mode == "valid" {
                2
            } else {
                usize::from(mode != "stale")
            }
        );
        gateway.shutdown().await;
    }
}

#[tokio::test]
async fn native_tui_selected_history_is_complete_and_session_bound() {
    for oversized in [false, true] {
        let gateway = TestGateway::spawn(handler(move |mut socket, _| async move {
            let baseline = ReleaseBaseline::load(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/releases/v2026.9.4"),
            ).expect("reviewed upstream request schemas");
            complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
            let sessions = receive_request(&mut socket).await;
            send_json(&mut socket, json!({"type":"res","id":sessions.id().as_str(),"ok":true,"payload":{"sessions":[]}})).await;
            let history = receive_request(&mut socket).await;
            assert_eq!(history.method().as_str(), "chat.history");
            let params = serde_json::from_str(history.params().value().expect("history parameters").as_json()).expect("history JSON");
            baseline.validate_gateway_request("chat.history", &params).expect("upstream-compatible history parameters");
            let text = if oversized { "x".repeat(16 * 1024 + 1) } else { "retained complete answer".to_owned() };
            send_json(&mut socket, json!({"type":"res","id":history.id().as_str(),"ok":true,"payload":{"sessionKey":"selected-session","messages":[{"role":"assistant","text":text}]}})).await;
            if !oversized {
                let approvals = receive_request(&mut socket).await;
                assert_eq!(approvals.method().as_str(), "exec.approval.list");
                send_json(&mut socket, json!({"type":"res","id":approvals.id().as_str(),"ok":true,"payload":{"requests":[]}})).await;
                let recovery = receive_request(&mut socket).await;
                assert_eq!(recovery.method().as_str(), "sessions.get");
                send_json(&mut socket, json!({"type":"res","id":recovery.id().as_str(),"ok":true,"payload":{"sessionKey":"selected-session","pendingRuns":[],"activeRuns":[]}})).await;
            }
            wait_for_close(&mut socket).await;
        })).await;
        let mut worker = spawn_gateway_worker(GatewayOptions {
            url: gateway.url.clone(),
            token: None,
            device_profile: None,
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if matches!(worker.events.recv().await, Some(WorkerEvent::Sessions(_))) {
                    break;
                }
            }
        })
        .await
        .expect("initial state");
        worker
            .commands
            .send(UiCommand::SelectSession("selected-session".to_owned()))
            .await
            .expect("select session");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match worker.events.recv().await.expect("history update") {
                    WorkerEvent::History {
                        session_id,
                        messages,
                    } => {
                        assert!(!oversized);
                        assert_eq!(session_id, "selected-session");
                        assert_eq!(
                            messages,
                            vec![TranscriptEntry {
                                role: "assistant".to_owned(),
                                text: "retained complete answer".to_owned()
                            }]
                        );
                        break;
                    }
                    WorkerEvent::Notice(notice) => {
                        assert!(
                            oversized && notice.contains("too large to display completely"),
                            "{notice}"
                        );
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("history deadline");
        worker.shutdown().await;
        gateway.shutdown().await;
    }
}

#[tokio::test]
async fn native_tui_recovery_advances_independent_cursors_after_complete_result_ack() {
    use std::sync::Arc;

    let finished = Arc::new(tokio::sync::Notify::new());
    let complete = Arc::clone(&finished);
    let gateway = TestGateway::spawn(handler(move |mut socket, _| {
        let complete = Arc::clone(&complete);
        async move {
            complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
            let sessions = receive_request(&mut socket).await;
            send_json(&mut socket, json!({"type":"res","id":sessions.id().as_str(),"ok":true,"payload":{"sessions":[]}})).await;
            let history = receive_request(&mut socket).await;
            assert_eq!(history.method().as_str(), "chat.history");
            send_json(&mut socket, json!({"type":"res","id":history.id().as_str(),"ok":true,"payload":{"sessionKey":"recovery-session","messages":[]}})).await;
            let approvals = receive_request(&mut socket).await;
            send_json(&mut socket, json!({"type":"res","id":approvals.id().as_str(),"ok":true,"payload":{"requests":[]}})).await;
            for page in 0_u64..3 {
                let request = receive_request(&mut socket).await;
                assert_eq!(request.method().as_str(), "sessions.get");
                let parameters: serde_json::Value = Codec::authenticated().decode_opaque(request.params().value().expect("recovery params")).expect("recovery JSON");
                assert_eq!(parameters["sessionKey"], "recovery-session");
                if page == 0 { assert!(parameters.get("after").is_none() && parameters.get("activeAfter").is_none()); }
                else { assert_eq!(parameters["after"], format!("{:064x}", 1)); assert_eq!(parameters["activeAfter"], format!("{:064x}", 9 + page)); }
                let pending = format!("{:064x}", if page == 0 { 1 } else { 2 });
                let active = format!("{:064x}", 10 + page);
                send_json(&mut socket, json!({"type":"res","id":request.id().as_str(),"ok":true,"payload":{
                    "sessionKey":"recovery-session", "pendingRuns":[{"runId":pending,"sessionId":"recovery-session"}],
                    "activeRuns":[{"runId":active,"sessionId":"recovery-session"}],
                    "nextCursor":if page == 0 { Some(pending.clone()) } else { None },
                    "nextActiveCursor":if page < 2 { Some(active.clone()) } else { None }
                }})).await;
                let ids = if page < 2 { vec![pending.clone(), active.clone()] } else { vec![active.clone()] };
                for run_id in ids {
                    let query = receive_request(&mut socket).await;
                    assert_eq!(query.method().as_str(), "agent.wait");
                    let parameters: serde_json::Value = Codec::authenticated().decode_opaque(query.params().value().expect("run params")).expect("run JSON");
                    assert_eq!(parameters, json!({"runId":run_id,"timeoutMs":0}));
                    let terminal = run_id == pending;
                    send_json(&mut socket, json!({"type":"res","id":query.id().as_str(),"ok":true,"payload":{
                        "runId":run_id,"sessionId":"recovery-session","durable":true,"revision":if terminal {4} else {2},"turn":if terminal {page+1} else {10+page},
                        "phase":if terminal {"finished"} else {"executing"},"status":if terminal {"completed"} else {"executing"},
                        "result":if terminal {json!({"status":"completed","text":"retained complete result"})} else {serde_json::Value::Null}
                    }})).await;
                }
                if page < 2 {
                    let ack = receive_request(&mut socket).await;
                    let parameters: serde_json::Value = Codec::authenticated().decode_opaque(ack.params().value().expect("ACK params")).expect("ACK JSON");
                    assert_eq!(parameters, json!({"runId":pending,"acknowledgeRevision":4}));
                    send_json(&mut socket, json!({"type":"res","id":ack.id().as_str(),"ok":true,"payload":{"runId":pending,"revision":4,"acknowledged":true,"durable":true}})).await;
                }
            }
            complete.notify_one();
            wait_for_close(&mut socket).await;
        }
    })).await;
    let mut worker = spawn_gateway_worker(GatewayOptions {
        url: gateway.url.clone(),
        token: None,
        device_profile: None,
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if matches!(worker.events.recv().await, Some(WorkerEvent::Sessions(_))) {
                break;
            }
        }
    })
    .await
    .expect("ready session snapshot");
    worker
        .commands
        .send(UiCommand::SelectSession("recovery-session".to_owned()))
        .await
        .expect("selected recovery");
    let mut recovered = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while recovered.len() < 5 {
            match worker.events.recv().await.expect("recovery update") {
                WorkerEvent::NativeRun {
                    run_id,
                    text,
                    revision,
                    ..
                } => {
                    recovered.push(run_id.clone());
                    if text.is_some() {
                        worker
                            .commands
                            .send(UiCommand::AcknowledgeRun { run_id, revision }.for_connection(1))
                            .await
                            .expect("complete result ACK");
                    }
                }
                WorkerEvent::RecoveryAvailable(session) => {
                    worker
                        .commands
                        .send(UiCommand::RecoverRuns(session))
                        .await
                        .expect("next bounded page");
                }
                WorkerEvent::Notice(notice) => panic!("unexpected recovery error: {notice}"),
                _ => {}
            }
        }
        finished.notified().await;
    })
    .await
    .expect("all independent recovery pages complete");
    assert_eq!(
        recovered,
        [1, 10, 2, 11, 12].map(|ordinal| format!("{ordinal:064x}"))
    );
    worker.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn native_tui_acknowledgement_requires_complete_matching_durable_receipt() {
    for valid in [false, true] {
        let run_id = "c".repeat(64);
        let expected = run_id.clone();
        let gateway = TestGateway::spawn(handler(move |mut socket, _| {
            let run_id = run_id.clone();
            async move {
                complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
                let sessions = receive_request(&mut socket).await;
                send_json(&mut socket, json!({"type":"res","id":sessions.id().as_str(),"ok":true,"payload":{"sessions":[]}})).await;
                let query = receive_request(&mut socket).await;
                assert_eq!(query.method().as_str(), "agent.wait");
                send_json(&mut socket, json!({"type":"res","id":query.id().as_str(),"ok":true,"payload":{"runId":run_id,"sessionId":"ack-session","revision":4,"durable":true,"phase":"finished","status":"completed","turn":1,"result":{"status":"completed","text":"complete result"}}})).await;
                let ack = receive_request(&mut socket).await;
                let parameters: serde_json::Value = Codec::authenticated().decode_opaque(ack.params().value().expect("ACK arguments")).expect("ACK JSON");
                assert_eq!(parameters, json!({"runId":run_id,"acknowledgeRevision":4}));
                let payload = if valid { json!({"runId":run_id,"revision":4,"durable":true,"acknowledged":true}) } else { json!({"runId":"d".repeat(64),"revision":3,"acknowledged":true}) };
                send_json(&mut socket, json!({"type":"res","id":ack.id().as_str(),"ok":true,"payload":payload})).await;
                wait_for_close(&mut socket).await;
            }
        })).await;
        let mut worker = spawn_gateway_worker(GatewayOptions {
            url: gateway.url.clone(),
            token: None,
            device_profile: None,
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if matches!(worker.events.recv().await, Some(WorkerEvent::Sessions(_))) {
                    break;
                }
            }
        })
        .await
        .expect("ready state");
        worker
            .commands
            .send(UiCommand::QueryRun {
                session_id: "ack-session".to_owned(),
                run_id: expected.clone(),
            })
            .await
            .expect("complete result query");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if matches!(
                    worker.events.recv().await,
                    Some(WorkerEvent::NativeRun { text: Some(_), .. })
                ) {
                    break;
                }
            }
        })
        .await
        .expect("complete result received");
        worker
            .commands
            .send(
                UiCommand::AcknowledgeRun {
                    run_id: expected.clone(),
                    revision: 4,
                }
                .for_connection(1),
            )
            .await
            .expect("exact ACK");
        let result = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
            .await
            .expect("ACK result wakes render loop")
            .expect("worker update");
        if valid {
            assert_eq!(
                result,
                WorkerEvent::ResultAcknowledged {
                    run_id: expected,
                    revision: 4
                }
            );
        } else {
            assert!(
                matches!(result, WorkerEvent::Notice(notice) if notice.contains("acknowledgement is unconfirmed"))
            );
        }
        worker.shutdown().await;
        gateway.shutdown().await;
    }
}

#[tokio::test]
async fn old_approval_commands_cannot_cross_a_tui_connection_restart() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let connections = Arc::new(AtomicUsize::new(0));
    let unexpected = Arc::new(AtomicUsize::new(0));
    let close_first = Arc::new(tokio::sync::Notify::new());
    let stop_first = Arc::clone(&close_first);
    let unexpected_calls = Arc::clone(&unexpected);
    let connected = Arc::clone(&connections);
    let token = "e".repeat(64);
    let fingerprint =
        claw_security::authorization::approval_preview_fingerprint(&token).expect("fingerprint");
    let expected = fingerprint.clone();
    let gateway = TestGateway::spawn(handler(move |mut socket, _| {
        let first = connected.fetch_add(1, Ordering::SeqCst) == 0;
        let stop_first = Arc::clone(&stop_first);
        let unexpected_calls = Arc::clone(&unexpected_calls);
        let token = token.clone();
        let fingerprint = fingerprint.clone();
        async move {
            complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
            let sessions = receive_request(&mut socket).await;
            assert_eq!(sessions.method().as_str(), "sessions.list");
            send_json(&mut socket, json!({"type":"res","id":sessions.id().as_str(),"ok":true,"payload":{"sessions":[]}})).await;
            if first {
                send_json(&mut socket, json!({"type":"event","event":"exec.approval.requested","seq":1,"payload":{"id":"approval-1","sessionId":"session-1"}})).await;
                let preview = receive_request(&mut socket).await;
                assert_eq!(preview.method().as_str(), "exec.approval.get");
                let mut payload = json!({"id":"approval-1","sessionId":"session-1","tool":"fs_write","previewComplete":true,"bindingToken":token,"previewFingerprint":fingerprint,
                    "toolPublication":"workspace-fixture","toolRevision":1,"resourceScope":"workspace: target.txt",
                    "caller":{"source":"Http","subject":"owner","account":null,"permissionGeneration":0,"owner":true}});
                payload["prompt"] = json!(format!("{}fs_write\n{{}}", claw_protocol::native_approval::bound_approval_context_header(&payload).expect("preview header")));
                send_json(&mut socket, json!({"type":"res","id":preview.id().as_str(),"ok":true,"payload":payload})).await;
                stop_first.notified().await;
                return;
            }
            loop {
                match socket.read_frame().await {
                    Ok(frame) if frame.opcode == fastwebsockets::OpCode::Text => { unexpected_calls.fetch_add(1, Ordering::SeqCst); }
                    Ok(frame) if frame.opcode == fastwebsockets::OpCode::Close => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    })).await;
    let mut worker = spawn_gateway_worker(GatewayOptions {
        url: gateway.url.clone(),
        token: None,
        device_profile: None,
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if matches!(worker.events.recv().await, Some(WorkerEvent::Prompt(_))) {
                break;
            }
        }
    })
    .await
    .expect("original approval displayed");
    close_first.notify_one();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(WorkerEvent::Connection(state)) = worker.events.recv().await
                && state.contains("unavailable")
            {
                break;
            }
        }
    })
    .await
    .expect("connection loss observed");
    worker
        .commands
        .send(UiCommand::Refresh)
        .await
        .expect("explicit reconnect");
    let stale = [
        UiCommand::ResolveApproval {
            id: "approval-1".to_owned(),
            approved: true,
            preview_fingerprint: expected,
        },
        UiCommand::SendMessage {
            session_id: "previous-session".to_owned(),
            text: "never automatically resend".to_owned(),
            idempotency_key: "original-key".to_owned(),
        },
        UiCommand::AbortRun {
            session_id: "previous-session".to_owned(),
            run_id: "a".repeat(64),
        },
        UiCommand::AcknowledgeRun {
            run_id: "a".repeat(64),
            revision: 4,
        },
        UiCommand::Answer {
            session_id: "previous-session".to_owned(),
            question_id: "previous-question".to_owned(),
            text: "old answer".to_owned(),
        },
    ];
    for command in stale {
        worker
            .commands
            .send(command.for_connection(1))
            .await
            .expect("queued command from the old observed connection");
    }
    let mut unconfirmed = false;
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut rejected = 0;
        while rejected < 5 {
            match worker
                .events
                .recv()
                .await
                .expect("connection-bound refusal")
            {
                WorkerEvent::Notice(notice) if notice.contains("previous connection") => {
                    rejected += 1;
                }
                WorkerEvent::SendNotSent {
                    idempotency_key, ..
                } => {
                    assert_eq!(idempotency_key, "original-key");
                    unconfirmed = true;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("stale decision rejected locally");
    assert!(unconfirmed);
    worker.shutdown().await;
    gateway.shutdown().await;
    assert_eq!(connections.load(Ordering::SeqCst), 2);
    assert_eq!(unexpected.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn gateway_worker_loads_sessions_and_streams_transcript() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        let (_, params) = complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        assert_eq!(
            params
                .scopes
                .expect("TUI requests scopes")
                .iter()
                .map(claw_protocol::gateway::Name::as_str)
                .collect::<Vec<_>>(),
            vec!["operator.read", "operator.write", "operator.approvals"]
        );
        let request = receive_request(&mut socket).await;
        assert_eq!(request.method().as_str(), "sessions.list");
        send_json(
            &mut socket,
            json!({
                "type": "res",
                "id": request.id().as_str(),
                "ok": true,
                "payload": {
                    "sessions": [{
                        "id": "session-42",
                        "title": "Repair updater",
                        "workspace": "D:\\work\\gta-claw",
                        "state": "running",
                        "progress": 37
                    }]
                }
            }),
        )
        .await;
        send_json(
            &mut socket,
            json!({
                "type": "event",
                "event": "session.message",
                "payload": {
                    "sessionId": "session-42",
                    "role": "assistant",
                    "text": "Downloaded manifest"
                },
                "seq": 1
            }),
        )
        .await;
        send_json(
            &mut socket,
            json!({
                "type": "event",
                "event": "sessions.changed",
                "seq": 2
            }),
        )
        .await;
        let list = receive_request(&mut socket).await;
        assert_eq!(list.method().as_str(), "artifacts.list");
        let list_params = Codec::authenticated()
            .decode_opaque::<serde_json::Value>(
                list.params().value().expect("artifact list params"),
            )
            .expect("decode artifact list params");
        assert_eq!(list_params, json!({"sessionId": "session-42"}));
        send_json(
            &mut socket,
            json!({
                "type": "res",
                "id": list.id().as_str(),
                "ok": true,
                "payload": {
                    "artifacts": [{
                        "id": "artifact-7",
                        "name": "report.json"
                    }]
                }
            }),
        )
        .await;
        let get = receive_request(&mut socket).await;
        assert_eq!(get.method().as_str(), "artifacts.get");
        let get_params = Codec::authenticated()
            .decode_opaque::<serde_json::Value>(get.params().value().expect("artifact get params"))
            .expect("decode artifact get params");
        assert_eq!(
            get_params,
            json!({"sessionId": "session-42", "artifactId": "artifact-7"})
        );
        send_json(
            &mut socket,
            json!({
                "type": "res",
                "id": get.id().as_str(),
                "ok": true,
                "payload": {"content": "{\n  \"status\": \"ok\"\n}"}
            }),
        )
        .await;
        wait_for_close(&mut socket).await;
    }))
    .await;

    let mut worker = spawn_gateway_worker(GatewayOptions {
        url: gateway.url.clone(),
        token: None,
        device_profile: None,
    });
    let connecting = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("connecting event timeout")
        .expect("connecting event");
    assert_eq!(
        connecting,
        WorkerEvent::Connection("Gateway: connecting (bounded retries)".to_owned())
    );
    let connection = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("connection event timeout")
        .expect("connection event");
    assert_eq!(
        connection,
        WorkerEvent::Ready {
            connection_id: 1,
            description: "Gateway: ready (protocol 4, epoch 1)".to_owned()
        }
    );
    let sessions = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("sessions event timeout")
        .expect("sessions event");
    assert_eq!(
        sessions,
        WorkerEvent::Sessions(vec![SessionSummary {
            id: "session-42".to_owned(),
            title: "Repair updater".to_owned(),
            workspace: "D:\\work\\gta-claw".to_owned(),
            state: RunState::Running,
            progress: Some(37),
        }])
    );
    let message = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("message event timeout")
        .expect("message event");
    assert_eq!(
        message,
        WorkerEvent::Message {
            session_id: "session-42".to_owned(),
            message: TranscriptEntry {
                role: "assistant".to_owned(),
                text: "Downloaded manifest".to_owned(),
            }
        }
    );
    let changed = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("changed event timeout")
        .expect("changed event");
    assert_eq!(
        changed,
        WorkerEvent::Notice("Sessions changed; press r to refresh".to_owned())
    );
    worker
        .commands
        .send(UiCommand::LoadArtifacts("session-42".to_owned()))
        .await
        .expect("request artifacts");
    let artifacts = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("artifacts event timeout")
        .expect("artifacts event");
    assert_eq!(
        artifacts,
        WorkerEvent::Artifacts {
            session_id: "session-42".to_owned(),
            artifacts: vec!["report.json".to_owned()]
        }
    );
    let preview = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("artifact preview timeout")
        .expect("artifact preview");
    assert_eq!(
        preview,
        WorkerEvent::ArtifactContent {
            session_id: "session-42".to_owned(),
            lines: vec![
                "{".to_owned(),
                "  \"status\": \"ok\"".to_owned(),
                "}".to_owned(),
            ]
        }
    );

    worker.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn failed_connections_can_be_retried_without_restarting_the_tui() {
    let gateway = TestGateway::spawn(handler(|mut socket, index| async move {
        if index < 3 {
            return;
        }
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        let request = receive_request(&mut socket).await;
        assert_eq!(request.method().as_str(), "sessions.list");
        send_json(
            &mut socket,
            json!({
                "type": "res",
                "id": request.id().as_str(),
                "ok": true,
                "payload": {"sessions": []}
            }),
        )
        .await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let mut worker = spawn_gateway_worker(GatewayOptions {
        url: gateway.url.clone(),
        token: None,
        device_profile: None,
    });

    assert_eq!(
        worker.events.recv().await,
        Some(WorkerEvent::Connection(
            "Gateway: connecting (bounded retries)".to_owned()
        ))
    );
    let unavailable = tokio::time::timeout(Duration::from_secs(5), worker.events.recv())
        .await
        .expect("bounded connection attempts")
        .expect("unavailable event");
    assert_eq!(
        unavailable,
        WorkerEvent::Connection("Gateway: unavailable (press r to retry)".to_owned())
    );
    let _notice = worker.events.recv().await.expect("actionable error notice");
    worker
        .commands
        .send(UiCommand::Refresh)
        .await
        .expect("retry command");
    assert_eq!(
        worker.events.recv().await,
        Some(WorkerEvent::Connection(
            "Gateway: connecting (bounded retries)".to_owned()
        ))
    );
    assert!(matches!(
        worker.events.recv().await,
        Some(WorkerEvent::Ready { connection_id: 2, description }) if description.starts_with("Gateway: ready")
    ));
    assert_eq!(
        worker.events.recv().await,
        Some(WorkerEvent::Sessions(Vec::new()))
    );

    worker.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn shutdown_cancels_a_stalled_connection_attempt() {
    let (url, cancellation, tasks) = raw_stalled_server().await;
    let mut worker = spawn_gateway_worker(GatewayOptions {
        url,
        token: None,
        device_profile: None,
    });
    assert!(matches!(
        worker.events.recv().await,
        Some(WorkerEvent::Connection(_))
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::time::timeout(Duration::from_secs(2), worker.shutdown())
        .await
        .expect("worker shutdown is bounded");

    cancellation.cancel();
    tasks.close();
    tokio::time::timeout(Duration::from_secs(2), tasks.wait())
        .await
        .expect("stalled test server shuts down");
}

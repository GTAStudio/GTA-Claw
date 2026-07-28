//! ACP subprocess interoperability tests.

use std::{path::PathBuf, process::Stdio, sync::Arc, time::Duration};

use claw_acp::debug_client::{DebugClient, DebugClientConfig, DebugRunRequest, DenyPermissions};
use claw_acp::error::AcpInteropError;
use claw_acp::schema::ProtocolVersion;
use claw_acp::schema_v1::{
    ClientCapabilities, ContentBlock, ContentChunk, InitializeRequest, NewSessionRequest,
    PromptRequest, SessionConfigId, SessionConfigValueId, SessionId, SessionModeId, SessionUpdate,
    StopReason, TextContent,
};
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};

async fn raw_fixture_exchange(
    request: &[u8],
) -> (Vec<serde_json::Value>, std::process::ExitStatus) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_claw-acp-fixture"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ACP fixture");
    let mut stdin = child.stdin.take().expect("fixture stdin");
    stdin.write_all(request).await.expect("write raw request");
    stdin.shutdown().await.expect("close fixture stdin");
    drop(stdin);
    let mut lines = BufReader::new(child.stdout.take().expect("fixture stdout")).lines();
    let mut responses = Vec::new();
    while let Some(line) = lines.next_line().await.expect("read fixture response") {
        responses.push(serde_json::from_str(&line).expect("fixture response JSON"));
    }
    let status = child.wait().await.expect("wait for fixture");
    (responses, status)
}

#[tokio::test]
async fn bridge_flushes_an_accepted_request_after_input_eof() {
    let params =
        InitializeRequest::new(ProtocolVersion::V1).client_capabilities(ClientCapabilities::new());
    let request = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "initialize",
        "params": params,
    }))
    .expect("serialize initialize");
    let mut framed = request;
    framed.push(b'\n');

    let (responses, status) = raw_fixture_exchange(&framed).await;

    assert!(status.success());
    assert_eq!(responses.len(), 1);
    let response = &responses[0];
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 7);
    assert_eq!(response["result"]["protocolVersion"], 1);
    assert_eq!(response["result"]["agentInfo"]["name"], "gta-claw");
}

#[tokio::test]
async fn bridge_rejects_invalid_request_ids_with_a_null_id() {
    let (responses, status) = raw_fixture_exchange(
        b"{\"jsonrpc\":\"2.0\",\"id\":false,\"method\":\"initialize\",\"params\":{}}\n",
    )
    .await;

    assert!(status.success());
    assert_eq!(responses.len(), 1);
    assert_eq!(
        responses[0],
        json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {
                "code": -32600,
                "message": "Invalid Request"
            }
        })
    );
}

#[tokio::test]
async fn bridge_drains_notifications_and_responses_after_input_eof() {
    let cwd = std::env::current_dir().expect("fixture cwd");
    let frames = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": InitializeRequest::new(ProtocolVersion::V1),
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "session/new",
            "params": NewSessionRequest::new(cwd),
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "session/prompt",
            "params": PromptRequest::new(
                SessionId::new("fixture-session"),
                vec![ContentBlock::Text(TextContent::new("drain fixture"))],
            ),
        }),
    ];
    let mut wire = Vec::new();
    for frame in frames {
        serde_json::to_writer(&mut wire, &frame).expect("serialize ACP frame");
        wire.push(b'\n');
    }

    let (messages, status) = raw_fixture_exchange(&wire).await;

    assert!(status.success());
    assert_eq!(messages.len(), 4);
    assert!(messages.iter().any(|message| {
        message["method"] == "session/update" && message["params"]["sessionId"] == "fixture-session"
    }));
    assert!(
        messages
            .iter()
            .any(|message| { message["id"] == 3 && message["result"]["stopReason"] == "end_turn" })
    );
}

#[tokio::test]
async fn bridge_answers_methodless_invalid_envelopes() {
    let (responses, status) = raw_fixture_exchange(b"{}\n").await;

    assert!(status.success());
    assert_eq!(
        responses,
        vec![json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {
                "code": -32600,
                "message": "Invalid Request"
            }
        })]
    );
}

#[tokio::test]
async fn bridge_does_not_answer_unmatched_error_responses() {
    let (responses, status) = raw_fixture_exchange(
        b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"}}\n",
    )
    .await;

    assert!(status.success());
    assert_eq!(responses, Vec::<serde_json::Value>::new());
}

#[tokio::test]
async fn bridge_preserves_partial_frames_while_dispatch_tasks_complete() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_claw-acp-fixture"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ACP fixture");
    let mut stdin = child.stdin.take().expect("fixture stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("fixture stdout")).lines();
    let initialize = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": InitializeRequest::new(ProtocolVersion::V1),
    }))
    .expect("serialize initialize");
    let session = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "session/new",
        "params": NewSessionRequest::new(std::env::current_dir().expect("fixture cwd")),
    }))
    .expect("serialize new session");
    let split = session.len() / 2;
    stdin
        .write_all(&initialize)
        .await
        .expect("write initialize");
    stdin.write_all(b"\n").await.expect("frame initialize");
    stdin
        .write_all(&session[..split])
        .await
        .expect("write partial session request");
    stdin.flush().await.expect("flush partial frame");
    let initialize_response: serde_json::Value = serde_json::from_str(
        &stdout
            .next_line()
            .await
            .expect("read initialize response")
            .expect("initialize response line"),
    )
    .expect("initialize response JSON");
    stdin
        .write_all(&session[split..])
        .await
        .expect("write session suffix");
    stdin.write_all(b"\n").await.expect("frame session request");
    stdin.shutdown().await.expect("close fixture stdin");
    drop(stdin);
    let session_response: serde_json::Value = serde_json::from_str(
        &stdout
            .next_line()
            .await
            .expect("read session response")
            .expect("session response line"),
    )
    .expect("session response JSON");
    let status = child.wait().await.expect("wait for fixture");

    assert!(status.success());
    assert_eq!(initialize_response["id"], 1);
    assert_eq!(session_response["id"], 2);
    assert_eq!(session_response["result"]["sessionId"], "fixture-session");
}

#[tokio::test]
async fn debug_client_exercises_bridge_lifecycle_and_streaming() {
    let mut config = DebugClientConfig::new(PathBuf::from(env!("CARGO_BIN_EXE_claw-acp-fixture")));
    config.timeout = Duration::from_secs(5);
    config
        .environment
        .insert("REQUEST_PERMISSION".into(), "1".into());
    config
        .environment
        .insert("WAIT_FOR_CANCEL".into(), "1".into());
    let client = DebugClient::new(config, Arc::new(DenyPermissions));
    let mut request = DebugRunRequest::new(
        std::env::current_dir().expect("test cwd must resolve"),
        vec![ContentBlock::Text(TextContent::new("hello fixture"))],
    );
    request.cancel_after = Some(Duration::from_millis(50));

    let result = client.run(request).await.expect("ACP script must succeed");

    assert_eq!(result.initialize.protocol_version, ProtocolVersion::V1);
    assert_eq!(result.session_id.to_string(), "fixture-session");
    let sessions = result
        .sessions
        .expect("fixture advertises session listing capability");
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(
        sessions.sessions[0].session_id.to_string(),
        "fixture-session"
    );
    assert_eq!(result.prompt.stop_reason, StopReason::Cancelled);
    assert!(result.close.is_some());
    assert_eq!(result.notifications.len(), 1);
    match &result.notifications[0].update {
        SessionUpdate::AgentMessageChunk(chunk) => {
            assert_eq!(
                chunk.clone(),
                ContentChunk::new(ContentBlock::Text(TextContent::new("fixture response")))
            );
        }

        update => panic!("unexpected session update: {update:?}"),
    }
}

#[tokio::test]
async fn debug_client_resumes_and_configures_a_session() {
    let mut config = DebugClientConfig::new(PathBuf::from(env!("CARGO_BIN_EXE_claw-acp-fixture")));
    config.timeout = Duration::from_secs(5);
    let client = DebugClient::new(config, Arc::new(DenyPermissions));
    let mut request = DebugRunRequest::new(
        std::env::current_dir().expect("test cwd must resolve"),
        vec![ContentBlock::Text(TextContent::new("configure fixture"))],
    );
    request.resume_session = Some(SessionId::new("fixture-session"));
    request.mode = Some(SessionModeId::new("plan"));
    request.config_options = vec![(
        SessionConfigId::new("model"),
        SessionConfigValueId::new("fixture-model"),
    )];

    let result = client
        .run(request)
        .await
        .expect("resumed ACP script must succeed");

    assert_eq!(result.initialize.protocol_version, ProtocolVersion::V1);
    let capabilities = result.initialize.agent_capabilities.session_capabilities;
    assert!(capabilities.list.is_some());
    assert!(capabilities.resume.is_some());
    assert!(capabilities.close.is_some());
    assert_eq!(result.session_id, SessionId::new("fixture-session"));
    assert_eq!(
        serde_json::to_value(&result.mode).expect("mode response must serialize"),
        json!({})
    );
    assert_eq!(result.config_options.len(), 1);
    assert_eq!(
        serde_json::to_value(&result.config_options[0])
            .expect("configuration response must serialize"),
        json!({
            "configOptions": [{
                "id": "model",
                "name": "Model",
                "category": "model",
                "type": "select",
                "currentValue": "fixture-model",
                "options": [{
                    "value": "fixture-model",
                    "name": "Fixture Model"
                }]
            }]
        })
    );
    assert_eq!(result.prompt.stop_reason, StopReason::EndTurn);
    assert_eq!(
        serde_json::to_value(&result.close).expect("close response must serialize"),
        json!({})
    );
}

#[tokio::test]
async fn debug_client_rejects_unsupported_protocol_version() {
    let mut config = DebugClientConfig::new(PathBuf::from(env!("CARGO_BIN_EXE_claw-acp-fixture")));
    config.arguments = vec!["--protocol-mismatch".into()];
    config.timeout = Duration::from_secs(5);
    let client = DebugClient::new(config, Arc::new(DenyPermissions));
    let request = DebugRunRequest::new(
        std::env::current_dir().expect("test cwd must resolve"),
        vec![ContentBlock::Text(TextContent::new("must not run"))],
    );

    let error = client
        .run(request)
        .await
        .expect_err("protocol version zero must be rejected");

    assert!(matches!(error, AcpInteropError::Protocol(_)));
}

#[tokio::test]
async fn debug_client_skips_unadvertised_optional_session_methods() {
    let mut config = DebugClientConfig::new(PathBuf::from(env!("CARGO_BIN_EXE_claw-acp-fixture")));
    config.timeout = Duration::from_secs(5);
    config
        .environment
        .insert("OMIT_OPTIONAL_SESSION_CAPABILITIES".into(), "1".into());
    let client = DebugClient::new(config, Arc::new(DenyPermissions));
    let request = DebugRunRequest::new(
        std::env::current_dir().expect("test cwd must resolve"),
        vec![ContentBlock::Text(TextContent::new(
            "optional capability fixture",
        ))],
    );

    let result = client
        .run(request)
        .await
        .expect("agent without optional session methods must run");

    assert_eq!(result.sessions, None);
    assert_eq!(result.close, None);
    assert_eq!(result.prompt.stop_reason, StopReason::EndTurn);
}

#[cfg(windows)]
#[tokio::test]
async fn debug_client_terminates_the_agent_descendant_process_tree() {
    let lock_path = std::env::temp_dir().join(format!(
        "gta-claw-acp-tree-lock-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must follow epoch")
            .as_nanos()
    ));
    let mut config = DebugClientConfig::new(PathBuf::from(env!("CARGO_BIN_EXE_claw-acp-fixture")));
    config.arguments = vec![
        "--spawn-grandchild".into(),
        lock_path.to_string_lossy().into_owned(),
    ];
    config.timeout = Duration::from_secs(5);
    let client = DebugClient::new(config, Arc::new(DenyPermissions));
    let request = DebugRunRequest::new(
        std::env::current_dir().expect("test cwd must resolve"),
        vec![ContentBlock::Text(TextContent::new("process tree fixture"))],
    );

    client
        .run(request)
        .await
        .expect("ACP script with grandchild must succeed");
    assert_eq!(
        std::fs::read(&lock_path).expect("grandchild marker must exist"),
        b"ready"
    );

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match std::fs::remove_file(&lock_path) {
                Ok(()) => break,
                Err(error) if error.raw_os_error() == Some(32) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("unexpected lock cleanup error: {error}"),
            }
        }
    })
    .await
    .expect("ACP descendant file lock must be released promptly");
}

#[cfg(unix)]
use std::{future::Future, pin::Pin};

#[cfg(unix)]
fn recorded_grandchild(lock_path: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(format!("{}.pid", lock_path.display()))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .expect("ps must run")
        .status
        .success()
}

/// Drives `run` until the fixture has recorded the grandchild it spawned.
///
/// The fixture never answers `initialize`, so the run future is polled purely
/// to let the spawn happen; observing the descendant before the run ends is
/// what keeps the kill assertions free of a spawn-versus-deadline race.
#[cfg(unix)]
async fn wait_for_grandchild<F>(run: &mut Pin<Box<F>>, lock_path: &std::path::Path) -> u32
where
    F: Future,
    F::Output: std::fmt::Debug,
{
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if let Some(grandchild) = recorded_grandchild(lock_path) {
                return grandchild;
            }
            tokio::select! {
                result = &mut *run => {
                    panic!("an unresponsive agent must not finish its run: {result:?}")
                }
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    })
    .await
    .expect("fixture must record its grandchild process identifier")
}

#[cfg(unix)]
async fn expect_descendant_exit(grandchild: u32, lock_path: &std::path::Path) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while process_exists(grandchild) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("ACP agent descendant must not survive its parent");
    let _ = std::fs::remove_file(lock_path);
    let _ = std::fs::remove_file(format!("{}.pid", lock_path.display()));
}

#[cfg(unix)]
fn process_tree_lock_path(label: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "gta-claw-acp-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must follow epoch")
            .as_nanos()
    ))
}

#[cfg(unix)]
fn unresponsive_tree_client(lock_path: &std::path::Path, timeout: Duration) -> DebugClient {
    let mut config = DebugClientConfig::new(PathBuf::from(env!("CARGO_BIN_EXE_claw-acp-fixture")));
    config.arguments = vec![
        "--spawn-grandchild".into(),
        lock_path.to_string_lossy().into_owned(),
    ];
    config
        .environment
        .insert("NEVER_RESPOND".into(), "1".into());
    config.timeout = timeout;
    DebugClient::new(config, Arc::new(DenyPermissions))
}

#[cfg(unix)]
fn process_tree_request() -> DebugRunRequest {
    DebugRunRequest::new(
        std::env::current_dir().expect("test cwd must resolve"),
        vec![ContentBlock::Text(TextContent::new("process tree fixture"))],
    )
}

#[cfg(unix)]
#[tokio::test]
async fn debug_client_times_out_an_agent_that_never_answers_initialize() {
    let lock_path = process_tree_lock_path("timeout-tree");
    let client = unresponsive_tree_client(&lock_path, Duration::from_secs(5));
    let mut run = Box::pin(client.run(process_tree_request()));
    let grandchild = wait_for_grandchild(&mut run, &lock_path).await;

    let error = run
        .await
        .expect_err("an agent that never answers initialize must not hang the client");

    assert!(
        matches!(error, AcpInteropError::Timeout(deadline) if deadline == Duration::from_secs(5)),
        "unexpected error: {error:?}"
    );
    expect_descendant_exit(grandchild, &lock_path).await;
}

#[cfg(unix)]
#[tokio::test]
async fn dropping_a_debug_run_kills_the_whole_agent_process_group() {
    let lock_path = process_tree_lock_path("dropped-tree");
    let client = unresponsive_tree_client(&lock_path, Duration::from_secs(30));
    let mut run = Box::pin(client.run(process_tree_request()));
    let grandchild = wait_for_grandchild(&mut run, &lock_path).await;

    drop(run);

    expect_descendant_exit(grandchild, &lock_path).await;
}

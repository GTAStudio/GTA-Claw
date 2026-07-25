//! ACP subprocess interoperability tests.

use std::{path::PathBuf, sync::Arc, time::Duration};

use agent_client_protocol::schema::{
    ContentBlock, ContentChunk, ProtocolVersion, SessionConfigId, SessionConfigValueId, SessionId,
    SessionModeId, SessionUpdate, StopReason, TextContent,
};
use claw_acp::debug_client::{DebugClient, DebugClientConfig, DebugRunRequest, DenyPermissions};
use claw_acp::error::AcpInteropError;
use serde_json::json;

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

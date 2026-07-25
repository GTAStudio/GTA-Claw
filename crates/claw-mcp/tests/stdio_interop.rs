//! MCP process transport interoperability tests.
#![allow(deprecated)]

use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use claw_mcp::{
    client::{
        ClientEventSink, DiscardEvents, McpClient, McpClientEvent, RejectSampling, SamplingFuture,
        SamplingPort, StdioClientConfig,
    },
    error::McpError,
};
use rmcp::model::{
    CallToolRequestParams, CreateMessageRequestParams, CreateMessageResult, GetPromptRequestParams,
    LoggingLevel, LoggingMessageNotificationParam, ReadResourceRequestParams,
    ResourceUpdatedNotificationParam, SamplingMessage, SubscribeRequestParams,
    UnsubscribeRequestParams,
};
use serde_json::{Map, Value, json};

#[derive(Debug, Default)]
struct RecordingSampling {
    requests: Mutex<Vec<Value>>,
}

impl SamplingPort for RecordingSampling {
    fn create_message<'a>(&'a self, request: CreateMessageRequestParams) -> SamplingFuture<'a> {
        let request = serde_json::to_value(request).expect("sampling request must serialize");
        self.requests
            .lock()
            .expect("sampling request lock must be healthy")
            .push(request);
        Box::pin(async {
            Ok(CreateMessageResult::new(
                SamplingMessage::assistant_text("fixture sampled response"),
                "fixture-model".into(),
            )
            .with_stop_reason(CreateMessageResult::STOP_REASON_END_TURN))
        })
    }
}

#[derive(Debug, Default)]
struct RecordingEvents {
    events: Mutex<Vec<McpClientEvent>>,
}

impl ClientEventSink for RecordingEvents {
    fn emit(&self, event: McpClientEvent) {
        self.events
            .lock()
            .expect("event lock must be healthy")
            .push(event);
    }
}

fn fixture(arguments: Vec<String>) -> StdioClientConfig {
    StdioClientConfig {
        program: PathBuf::from(env!("CARGO_BIN_EXE_claw-mcp-fixture")),
        arguments: arguments.into_iter().map(OsString::from).collect(),
        environment: std::collections::HashMap::new(),
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_millis(150),
    }
}

#[tokio::test]
async fn stalled_child_stdin_cannot_block_request_timeout_or_shutdown() {
    let client = McpClient::connect_stdio(
        fixture(vec!["--stall-stdin".into()]),
        Arc::new(RejectSampling),
        Arc::new(DiscardEvents),
    )
    .await
    .expect("stall fixture must initialize");
    let oversized_uri = format!("gta://fixture/{}", "x".repeat(2 * 1024 * 1024));

    let request_error = tokio::time::timeout(
        Duration::from_secs(2),
        client.read_resource(ReadResourceRequestParams::new(oversized_uri)),
    )
    .await
    .expect("write-side request timeout must be bounded")
    .expect_err("stalled child must time out");
    assert_eq!(
        request_error.to_string(),
        "MCP operation timed out after 150ms"
    );

    tokio::time::timeout(Duration::from_secs(2), client.close())
        .await
        .expect("stalled child shutdown must be bounded")
        .expect("stalled child process tree must terminate");
}

#[tokio::test]
async fn stdio_subprocess_negotiates_lists_calls_times_out_and_shuts_down() {
    let sampling = Arc::new(RecordingSampling::default());
    let events = Arc::new(RecordingEvents::default());
    let client = McpClient::connect_stdio(fixture(Vec::new()), sampling.clone(), events.clone())
        .await
        .expect("fixture must initialize");

    let discovery = client
        .server_info()
        .expect("initialized client must retain server info");
    assert_eq!(discovery.server_info.name, "gta-claw-mcp-fixture");
    assert_eq!(discovery.server_info.version, "1.0.0");
    assert!(discovery.capabilities.tools.is_some());
    assert!(discovery.capabilities.resources.is_some());
    assert!(discovery.capabilities.prompts.is_some());

    let tools = client.list_tools().await.expect("tools/list must succeed");
    let names: Vec<&str> = tools.tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(names, vec!["echo", "hang", "sample", "notify", "cancel"]);

    let mut arguments = Map::new();
    arguments.insert("text".into(), Value::String("byte-exact echo".into()));
    let result = client
        .call_tool(CallToolRequestParams::new("echo").with_arguments(arguments))
        .await
        .expect("tools/call must succeed");
    assert_eq!(
        serde_json::to_value(result).expect("tool result must serialize"),
        json!({
            "content": [{"type": "text", "text": "byte-exact echo"}],
            "isError": false
        })
    );

    let resources = client
        .list_resources()
        .await
        .expect("resources/list must succeed");
    assert_eq!(
        serde_json::to_value(resources).expect("resources must serialize"),
        json!({
            "resources": [{
                "uri": "gta://fixture/session",
                "name": "fixture-session",
                "description": "A deterministic fixture session",
                "mimeType": "text/markdown",
                "size": 21
            }]
        })
    );
    let templates = client
        .list_resource_templates()
        .await
        .expect("resources/templates/list must succeed");
    assert_eq!(
        serde_json::to_value(templates).expect("templates must serialize"),
        json!({
            "resourceTemplates": [{
                "uriTemplate": "gta://fixture/{name}",
                "name": "fixture-by-name",
                "description": "Fixture resources by name",
                "mimeType": "text/plain"
            }]
        })
    );
    let resource = client
        .read_resource(ReadResourceRequestParams::new("gta://fixture/session"))
        .await
        .expect("resources/read must succeed");
    assert_eq!(
        serde_json::to_value(resource).expect("resource result must serialize"),
        json!({
            "contents": [{
                "uri": "gta://fixture/session",
                "mimeType": "text/markdown",
                "text": "fixture resource body"
            }]
        })
    );
    client
        .subscribe(SubscribeRequestParams::new("gta://fixture/session"))
        .await
        .expect("resources/subscribe must succeed");
    client
        .unsubscribe(UnsubscribeRequestParams::new("gta://fixture/session"))
        .await
        .expect("resources/unsubscribe must succeed");

    let prompts = client
        .list_prompts()
        .await
        .expect("prompts/list must succeed");
    assert_eq!(
        serde_json::to_value(prompts).expect("prompts must serialize"),
        json!({
            "prompts": [{
                "name": "summarize",
                "description": "Summarizes deterministic fixture text",
                "arguments": [{
                    "name": "text",
                    "description": "Text to summarize",
                    "required": true
                }]
            }]
        })
    );
    let mut prompt_arguments = Map::new();
    prompt_arguments.insert("text".into(), Value::String("the fixture".into()));
    let prompt = client
        .get_prompt(GetPromptRequestParams::new("summarize").with_arguments(prompt_arguments))
        .await
        .expect("prompts/get must succeed");
    assert_eq!(
        serde_json::to_value(prompt).expect("prompt result must serialize"),
        json!({
            "description": "Resolved deterministic fixture prompt",
            "messages": [{
                "role": "user",
                "content": {"type": "text", "text": "Summarize exactly: the fixture"}
            }]
        })
    );

    let sampled = client
        .call_tool(CallToolRequestParams::new("sample"))
        .await
        .expect("sampling tool must succeed");
    let sampled = serde_json::to_value(sampled).expect("sample tool result must serialize");
    let sampled_text = sampled
        .pointer("/content/0/text")
        .and_then(Value::as_str)
        .expect("sample tool must return text");
    assert_eq!(
        serde_json::from_str::<Value>(sampled_text).expect("sample response must be JSON"),
        json!({
            "model": "fixture-model",
            "stopReason": "endTurn",
            "role": "assistant",
            "content": {"type": "text", "text": "fixture sampled response"}
        })
    );
    assert_eq!(
        *sampling
            .requests
            .lock()
            .expect("sampling request lock must be healthy"),
        vec![json!({
            "messages": [{
                "role": "user",
                "content": {"type": "text", "text": "fixture sampling request"}
            }],
            "maxTokens": 32
        })]
    );

    client
        .call_tool(CallToolRequestParams::new("notify"))
        .await
        .expect("notification tool must succeed");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if events
                .events
                .lock()
                .expect("event lock must be healthy")
                .len()
                == 5
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server notifications must arrive");
    assert_eq!(
        *events.events.lock().expect("event lock must be healthy"),
        vec![
            McpClientEvent::ToolsChanged,
            McpClientEvent::ResourcesChanged,
            McpClientEvent::PromptsChanged,
            McpClientEvent::ResourceUpdated(ResourceUpdatedNotificationParam::new(
                "gta://fixture/session"
            )),
            McpClientEvent::Logging(
                LoggingMessageNotificationParam::new(
                    LoggingLevel::Info,
                    json!({"event": "fixture-notification"})
                )
                .with_logger("gta-claw-mcp-fixture")
            )
        ]
    );

    let error = client
        .call_tool(CallToolRequestParams::new("hang"))
        .await
        .expect_err("a hung tool must hit the request deadline");
    assert_eq!(
        error.to_string(),
        McpError::Timeout(Duration::from_millis(150)).to_string()
    );

    let cancellation_marker = std::env::temp_dir().join(format!(
        "gta-claw-mcp-cancel-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow epoch")
            .as_nanos()
    ));
    let mut cancellation_arguments = Map::new();
    cancellation_arguments.insert(
        "marker".into(),
        Value::String(cancellation_marker.to_string_lossy().into_owned()),
    );
    let error = client
        .call_tool(CallToolRequestParams::new("cancel").with_arguments(cancellation_arguments))
        .await
        .expect_err("cancellable tool must hit the request deadline");
    assert_eq!(
        error.to_string(),
        McpError::Timeout(Duration::from_millis(150)).to_string()
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match std::fs::read_to_string(&cancellation_marker) {
                Ok(contents) => {
                    assert_eq!(contents, "request timeout");
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("unexpected cancellation marker error: {error}"),
            }
        }
    })
    .await
    .expect("request cancellation must reach the server backend");
    std::fs::remove_file(&cancellation_marker).expect("cancellation marker must be removable");

    client.close().await.expect("shutdown must terminate child");
}

#[tokio::test]
async fn list_timeout_cancels_the_server_request() {
    let cancellation_marker = std::env::temp_dir().join(format!(
        "gta-claw-mcp-list-cancel-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow epoch")
            .as_nanos()
    ));
    let mut config = fixture(Vec::new());
    config.environment.insert(
        OsString::from("CANCELLED_LIST_MARKER"),
        cancellation_marker.as_os_str().to_owned(),
    );
    let client =
        McpClient::connect_stdio(config, Arc::new(RejectSampling), Arc::new(DiscardEvents))
            .await
            .expect("fixture must initialize");

    let error = client
        .list_tools()
        .await
        .expect_err("a hung list request must hit the deadline");
    assert_eq!(
        error.to_string(),
        McpError::Timeout(Duration::from_millis(150)).to_string()
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match std::fs::read_to_string(&cancellation_marker) {
                Ok(contents) => {
                    assert_eq!(contents, "list request timeout");
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("unexpected cancellation marker error: {error}"),
            }
        }
    })
    .await
    .expect("list cancellation must reach the server backend");

    std::fs::remove_file(&cancellation_marker).expect("cancellation marker must be removable");
    client.close().await.expect("shutdown must terminate child");
}

#[tokio::test]
async fn malformed_stdio_frame_fails_initialization() {
    let error = McpClient::connect_stdio(
        fixture(vec!["--malformed".into()]),
        Arc::new(RejectSampling),
        Arc::new(DiscardEvents),
    )
    .await
    .expect_err("malformed JSON-RPC must fail closed");

    assert!(matches!(error, McpError::ClientInitialize(_)));
}

#[tokio::test]
async fn oversized_unterminated_stdio_frame_fails_initialization() {
    let error = McpClient::connect_stdio(
        fixture(vec!["--oversized".into()]),
        Arc::new(RejectSampling),
        Arc::new(DiscardEvents),
    )
    .await
    .expect_err("oversized JSON-RPC must fail closed");

    assert!(matches!(error, McpError::ClientInitialize(_)));
}

#[tokio::test]
async fn unsupported_protocol_version_fails_initialization() {
    let error = McpClient::connect_stdio(
        fixture(vec!["--protocol-mismatch".into()]),
        Arc::new(RejectSampling),
        Arc::new(DiscardEvents),
    )
    .await
    .expect_err("unsupported versions must be rejected");

    assert_eq!(
        error.to_string(),
        "MCP protocol violation: server selected unsupported version 1900-01-01"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn closing_stdio_transport_terminates_the_descendant_process_tree() {
    let lock_path = std::env::temp_dir().join(format!(
        "gta-claw-mcp-tree-lock-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must follow epoch")
            .as_nanos()
    ));
    let client = McpClient::connect_stdio(
        fixture(vec![
            "--spawn-grandchild".into(),
            lock_path.to_string_lossy().into_owned(),
        ]),
        Arc::new(RejectSampling),
        Arc::new(DiscardEvents),
    )
    .await
    .expect("fixture with grandchild must initialize");

    let error = std::fs::remove_file(&lock_path)
        .expect_err("grandchild must hold a delete-denying file handle");
    assert_eq!(error.raw_os_error(), Some(32));
    client
        .close()
        .await
        .expect("closing transport must terminate process tree");

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match std::fs::remove_file(&lock_path) {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) if error.raw_os_error() == Some(32) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("unexpected lock cleanup error: {error}"),
            }
        }
    })
    .await
    .expect("descendant file lock must be released promptly");
}

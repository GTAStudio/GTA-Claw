//! Rust-only MCP subprocess fixture.
#![allow(deprecated)]

use std::{
    fs::OpenOptions,
    io::{self, BufRead, Write},
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::Duration,
};

use claw_mcp::{
    framing::DEFAULT_MAX_FRAME_BYTES,
    server::{GtaMcpServer, McpBackend, OperationContext, serve_stdio},
};
use rmcp::{
    ErrorData,
    model::{
        CallToolRequestParams, CallToolResult, ContentBlock, CreateMessageRequestParams,
        GetPromptRequestParams, GetPromptResult, JsonObject, ListPromptsResult,
        ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, LoggingLevel,
        LoggingMessageNotificationParam, PaginatedRequestParams, Prompt, PromptArgument,
        PromptMessage, ReadResourceRequestParams, ReadResourceResult, Resource, ResourceContents,
        ResourceTemplate, ResourceUpdatedNotificationParam, Role, SamplingMessage,
        ServerCapabilities, ServerInfo, SubscribeRequestParams, Tool, UnsubscribeRequestParams,
    },
};
use serde_json::{Value, json};

#[derive(Debug)]
struct FixtureBackend;

impl McpBackend for FixtureBackend {
    fn server_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.server_info.name = "gta-claw-mcp-fixture".into();
        info.server_info.version = "1.0.0".into();
        info.capabilities = ServerCapabilities::builder()
            .enable_logging()
            .enable_prompts()
            .enable_prompts_list_changed()
            .enable_resources()
            .enable_resources_list_changed()
            .enable_resources_subscribe()
            .enable_tools()
            .enable_tool_list_changed()
            .build();
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: OperationContext,
    ) -> Result<ListToolsResult, ErrorData> {
        if let Some(marker) = std::env::var_os("CANCELLED_LIST_MARKER") {
            context.cancellation.cancelled().await;
            std::fs::write(marker, b"list request timeout").map_err(|error| {
                ErrorData::internal_error(format!("failed to record cancellation: {error}"), None)
            })?;
        }
        Ok(ListToolsResult {
            tools: vec![
                Tool::new("echo", "Returns the supplied text", JsonObject::new()),
                Tool::new("hang", "Never completes normally", JsonObject::new()),
                Tool::new("sample", "Requests client sampling", JsonObject::new()),
                Tool::new("notify", "Emits server notifications", JsonObject::new()),
                Tool::new(
                    "cancel",
                    "Waits for cancellation and records it",
                    JsonObject::new(),
                ),
            ],
            ..ListToolsResult::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: OperationContext,
    ) -> Result<CallToolResult, ErrorData> {
        match request.name.as_ref() {
            "hang" => {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Err(ErrorData::internal_error(
                    "hung fixture unexpectedly completed",
                    None,
                ))
            }
            "echo" => {
                let text = required_string_argument(request.arguments, "text")?;
                Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
            }
            "sample" => {
                let response = GtaMcpServer::<Self>::sample(
                    &context,
                    CreateMessageRequestParams::new(
                        vec![SamplingMessage::user_text("fixture sampling request")],
                        32,
                    ),
                )
                .await
                .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
                let response = serde_json::to_string(&response)
                    .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
                Ok(CallToolResult::success(vec![ContentBlock::text(response)]))
            }
            "client-capabilities" => {
                let capabilities = context
                    .peer
                    .peer_info()
                    .ok_or_else(|| {
                        ErrorData::internal_error("client handshake info is unavailable", None)
                    })?
                    .capabilities
                    .clone();
                let capabilities = serde_json::to_string(&capabilities)
                    .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    capabilities,
                )]))
            }
            "notify" => {
                GtaMcpServer::<Self>::notify_tools_changed(&context)
                    .await
                    .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
                GtaMcpServer::<Self>::notify_resources_changed(&context)
                    .await
                    .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
                GtaMcpServer::<Self>::notify_prompts_changed(&context)
                    .await
                    .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
                context
                    .peer
                    .notify_resource_updated(ResourceUpdatedNotificationParam::new(
                        "gta://fixture/session",
                    ))
                    .await
                    .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
                context
                    .peer
                    .notify_logging_message(
                        LoggingMessageNotificationParam::new(
                            LoggingLevel::Info,
                            json!({"event": "fixture-notification"}),
                        )
                        .with_logger("gta-claw-mcp-fixture"),
                    )
                    .await
                    .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    "notifications emitted",
                )]))
            }
            "cancel" => {
                let marker = required_string_argument(request.arguments, "marker")?;
                context.cancellation.cancelled().await;
                std::fs::write(marker, b"request timeout")
                    .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    "cancelled",
                )]))
            }
            _ => Err(ErrorData::invalid_params("unknown fixture tool", None)),
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: OperationContext,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new("gta://fixture/session", "fixture-session")
                .with_description("A deterministic fixture session")
                .with_mime_type("text/markdown")
                .with_size(21),
        ]))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: OperationContext,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult::with_all_items(vec![
            ResourceTemplate::new("gta://fixture/{name}", "fixture-by-name")
                .with_description("Fixture resources by name")
                .with_mime_type("text/plain"),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: OperationContext,
    ) -> Result<ReadResourceResult, ErrorData> {
        if request.uri != "gta://fixture/session" {
            return Err(ErrorData::invalid_params("unknown fixture resource", None));
        }
        Ok(ReadResourceResult::new(vec![
            ResourceContents::text("fixture resource body", request.uri)
                .with_mime_type("text/markdown"),
        ]))
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        _context: OperationContext,
    ) -> Result<(), ErrorData> {
        validate_resource_uri(&request.uri)
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        _context: OperationContext,
    ) -> Result<(), ErrorData> {
        validate_resource_uri(&request.uri)
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: OperationContext,
    ) -> Result<ListPromptsResult, ErrorData> {
        Ok(ListPromptsResult::with_all_items(vec![Prompt::new(
            "summarize",
            Some("Summarizes deterministic fixture text"),
            Some(vec![
                PromptArgument::new("text")
                    .with_description("Text to summarize")
                    .with_required(true),
            ]),
        )]))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: OperationContext,
    ) -> Result<GetPromptResult, ErrorData> {
        if request.name != "summarize" {
            return Err(ErrorData::invalid_params("unknown fixture prompt", None));
        }
        let text = required_string_argument(request.arguments, "text")?;
        Ok(GetPromptResult::new(vec![PromptMessage::new_text(
            Role::User,
            format!("Summarize exactly: {text}"),
        )])
        .with_description("Resolved deterministic fixture prompt"))
    }
}

fn required_string_argument(
    arguments: Option<JsonObject>,
    name: &str,
) -> Result<String, ErrorData> {
    arguments
        .and_then(|mut arguments| arguments.remove(name))
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| ErrorData::invalid_params(format!("{name} must be a string"), None))
}

fn validate_resource_uri(uri: &str) -> Result<(), ErrorData> {
    if uri == "gta://fixture/session" {
        Ok(())
    } else {
        Err(ErrorData::invalid_params("unknown fixture resource", None))
    }
}

fn send_invalid_protocol_version() -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let request: Value = serde_json::from_str(&line).map_err(io::Error::other)?;
    let response = json!({
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": {
            "protocolVersion": "1900-01-01",
            "capabilities": {},
            "serverInfo": {"name": "bad-version", "version": "1.0.0"}
        }
    });
    writeln!(io::stdout(), "{response}")?;
    io::stdout().flush()
}

fn stall_stdin_after_initialize() -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let request: Value = serde_json::from_str(&line).map_err(io::Error::other)?;
    let response = json!({
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"resources": {}},
            "serverInfo": {"name": "stalled-stdin", "version": "1.0.0"}
        }
    });
    writeln!(io::stdout(), "{response}")?;
    io::stdout().flush()?;
    thread::sleep(Duration::from_secs(30));
    Ok(())
}

#[cfg(windows)]
fn hold_windows_delete_lock(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .share_mode(0x1 | 0x2)
        .open(path)?;
    file.write_all(b"ready")?;
    file.flush()?;
    thread::sleep(Duration::from_secs(10));
    Ok(())
}

#[cfg(not(windows))]
fn hold_windows_delete_lock(path: &Path) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(b"ready")?;
    file.flush()?;
    thread::sleep(Duration::from_secs(10));
    Ok(())
}

fn spawn_locking_grandchild(path: &Path) -> io::Result<()> {
    Command::new(std::env::current_exe()?)
        .arg("--grandchild")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    for _ in 0..100 {
        if std::fs::metadata(path).is_ok_and(|metadata| metadata.len() == 5) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "grandchild did not acquire file lock",
    ))
}

#[tokio::main]
async fn main() {
    let arguments = std::env::args().collect::<Vec<_>>();
    match arguments.get(1).map(String::as_str) {
        Some("--malformed") => {
            println!("{{not-json");
        }
        Some("--oversized") => {
            let frame = vec![b'x'; DEFAULT_MAX_FRAME_BYTES + 1];
            if let Err(error) = io::stdout()
                .write_all(&frame)
                .and_then(|()| io::stdout().flush())
            {
                eprintln!("fixture failed: {error}");
            }
        }
        Some("--protocol-mismatch") => {
            if let Err(error) = send_invalid_protocol_version() {
                eprintln!("fixture failed: {error}");
            }
        }
        Some("--stall-stdin") => {
            if let Err(error) = stall_stdin_after_initialize() {
                eprintln!("fixture failed: {error}");
            }
        }
        Some("--grandchild") => {
            if let Some(path) = arguments.get(2)
                && let Err(error) = hold_windows_delete_lock(Path::new(path))
            {
                eprintln!("fixture failed: {error}");
            }
        }
        Some("--spawn-grandchild") => {
            let Some(path) = arguments.get(2) else {
                eprintln!("fixture failed: missing lock path");
                return;
            };
            if let Err(error) = spawn_locking_grandchild(Path::new(path)) {
                eprintln!("fixture failed: {error}");
                return;
            }
            if let Err(error) = serve_stdio(Arc::new(FixtureBackend)).await {
                eprintln!("fixture failed: {error}");
            }
        }
        _ => {
            if let Err(error) = serve_stdio(Arc::new(FixtureBackend)).await {
                eprintln!("fixture failed: {error}");
            }
        }
    }
}

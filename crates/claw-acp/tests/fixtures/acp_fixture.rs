//! Rust-only ACP subprocess fixture.

use std::{
    fs::OpenOptions,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use agent_client_protocol::{
    Error,
    schema::{
        AgentCapabilities, CancelNotification, CloseSessionRequest, CloseSessionResponse,
        ContentBlock, ContentChunk, ListSessionsRequest, ListSessionsResponse, LoadSessionRequest,
        LoadSessionResponse, McpServer, NewSessionRequest, NewSessionResponse, PermissionOption,
        PermissionOptionId, PermissionOptionKind, PromptRequest, PromptResponse,
        RequestPermissionOutcome, RequestPermissionRequest, ResumeSessionRequest,
        ResumeSessionResponse, SessionCapabilities, SessionCloseCapabilities, SessionConfigOption,
        SessionConfigOptionCategory, SessionConfigSelectOption, SessionInfo,
        SessionListCapabilities, SessionResumeCapabilities, SessionUpdate,
        SetSessionConfigOptionRequest, SetSessionConfigOptionResponse, SetSessionModeRequest,
        SetSessionModeResponse, StopReason, TextContent, ToolCall, ToolCallId,
    },
};
use claw_acp::bridge::{AcpBackend, AcpBridge, AcpFuture, AcpSessionContext};
use serde_json::{Value, json};

#[derive(Debug, Default)]
struct FixtureBackend {
    cancelled: AtomicBool,
}

fn validate_mcp_servers(servers: &[McpServer]) -> Result<(), Error> {
    let actual = serde_json::to_value(servers)
        .map_err(|error| Error::internal_error().data(error.to_string()))?;
    let expected = if servers.is_empty() {
        json!([])
    } else {
        json!([{
            "name": "fixture-mcp",
            "command": "fixture-mcp",
            "args": ["--readonly"],
            "env": [{"name": "FIXTURE_MODE", "value": "readonly"}]
        }])
    };
    if actual != expected {
        return Err(Error::invalid_params().data("unexpected MCP server configuration"));
    }
    Ok(())
}

fn send_unsupported_protocol_version() -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let request: Value = serde_json::from_str(&line).map_err(io::Error::other)?;
    let response = json!({
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": {
            "protocolVersion": 0,
            "agentCapabilities": {}
        }
    });
    writeln!(io::stdout(), "{response}")?;
    io::stdout().flush()
}

impl AcpBackend for FixtureBackend {
    fn new_session<'a>(
        &'a self,
        request: NewSessionRequest,
        _context: AcpSessionContext,
    ) -> AcpFuture<'a, NewSessionResponse> {
        Box::pin(async move {
            validate_mcp_servers(&request.mcp_servers)?;
            Ok(NewSessionResponse::new("fixture-session"))
        })
    }

    fn load_session<'a>(
        &'a self,
        request: LoadSessionRequest,
        _context: AcpSessionContext,
    ) -> AcpFuture<'a, LoadSessionResponse> {
        Box::pin(async move {
            validate_mcp_servers(&request.mcp_servers)?;
            Ok(LoadSessionResponse::new())
        })
    }

    fn resume_session<'a>(
        &'a self,
        request: ResumeSessionRequest,
        _context: AcpSessionContext,
    ) -> AcpFuture<'a, ResumeSessionResponse> {
        Box::pin(async move {
            if request.session_id.to_string() != "fixture-session" {
                return Err(Error::invalid_params().data("unexpected session to resume"));
            }
            validate_mcp_servers(&request.mcp_servers)?;
            Ok(ResumeSessionResponse::new())
        })
    }

    fn list_sessions<'a>(
        &'a self,
        _request: ListSessionsRequest,
    ) -> AcpFuture<'a, ListSessionsResponse> {
        Box::pin(async {
            Ok(ListSessionsResponse::new(vec![SessionInfo::new(
                "fixture-session",
                PathBuf::from("C:\\fixture"),
            )]))
        })
    }

    fn close_session<'a>(
        &'a self,
        _request: CloseSessionRequest,
    ) -> AcpFuture<'a, CloseSessionResponse> {
        Box::pin(async { Ok(CloseSessionResponse::new()) })
    }

    fn prompt<'a>(
        &'a self,
        request: PromptRequest,
        context: AcpSessionContext,
    ) -> AcpFuture<'a, PromptResponse> {
        Box::pin(async move {
            if std::env::var_os("REQUEST_PERMISSION").is_some() {
                let permission = context
                    .request_permission(RequestPermissionRequest::new(
                        request.session_id.clone(),
                        ToolCall::new(ToolCallId::new("fixture-call"), "fixture permission").into(),
                        vec![PermissionOption::new(
                            PermissionOptionId::new("allow"),
                            "Allow",
                            PermissionOptionKind::AllowOnce,
                        )],
                    ))
                    .await?;
                if permission.outcome != RequestPermissionOutcome::Cancelled {
                    return Err(Error::internal_error()
                        .data("fixture expected the client to deny permission"));
                }
            }
            context.notify(
                request.session_id.clone(),
                SessionUpdate::AgentMessageChunk(ContentChunk::new(ContentBlock::Text(
                    TextContent::new("fixture response"),
                ))),
            )?;
            if std::env::var_os("WAIT_FOR_CANCEL").is_some() {
                while !self.cancelled.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                return Ok(PromptResponse::new(StopReason::Cancelled));
            }
            Ok(PromptResponse::new(StopReason::EndTurn))
        })
    }

    fn set_mode<'a>(
        &'a self,
        request: SetSessionModeRequest,
    ) -> AcpFuture<'a, SetSessionModeResponse> {
        Box::pin(async move {
            if request.session_id.to_string() != "fixture-session"
                || request.mode_id.to_string() != "plan"
            {
                return Err(Error::invalid_params().data("unexpected mode request"));
            }
            Ok(SetSessionModeResponse::new())
        })
    }

    fn set_config_option<'a>(
        &'a self,
        request: SetSessionConfigOptionRequest,
    ) -> AcpFuture<'a, SetSessionConfigOptionResponse> {
        Box::pin(async move {
            if request.session_id.to_string() != "fixture-session"
                || request.config_id.to_string() != "model"
                || request.value.to_string() != "fixture-model"
            {
                return Err(Error::invalid_params().data("unexpected configuration request"));
            }
            Ok(SetSessionConfigOptionResponse::new(vec![
                SessionConfigOption::select(
                    "model",
                    "Model",
                    "fixture-model",
                    vec![SessionConfigSelectOption::new(
                        "fixture-model",
                        "Fixture Model",
                    )],
                )
                .category(SessionConfigOptionCategory::Model),
            ]))
        })
    }

    fn cancel<'a>(&'a self, _notification: CancelNotification) -> AcpFuture<'a, ()> {
        Box::pin(async {
            self.cancelled.store(true, Ordering::SeqCst);
            Ok(())
        })
    }
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
        Some("--protocol-mismatch") => {
            if let Err(error) = send_unsupported_protocol_version() {
                eprintln!("fixture failed: {error}");
            }
            return;
        }
        Some("--grandchild") => {
            if let Some(path) = arguments.get(2)
                && let Err(error) = hold_windows_delete_lock(Path::new(path))
            {
                eprintln!("fixture failed: {error}");
            }
            return;
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
        }
        _ => {}
    }
    let mut session_capabilities =
        SessionCapabilities::new().resume(SessionResumeCapabilities::new());
    if std::env::var_os("OMIT_OPTIONAL_SESSION_CAPABILITIES").is_none() {
        session_capabilities = session_capabilities
            .list(SessionListCapabilities::new())
            .close(SessionCloseCapabilities::new());
    }
    let bridge = AcpBridge::new(
        Arc::new(FixtureBackend::default()),
        AgentCapabilities::new()
            .load_session(true)
            .session_capabilities(session_capabilities),
    );
    if let Err(error) = bridge.serve_stdio().await {
        eprintln!("fixture failed: {error}");
    }
}

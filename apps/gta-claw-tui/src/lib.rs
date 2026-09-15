//! Headless-first terminal application for GTA Claw.

use std::ffi::OsString;
use std::fmt::{self, Formatter};
use std::io::{self, IsTerminal as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal as crossterm_terminal;
use tokio::sync::mpsc;
use url::Url;

// This module carries its own `//!` documentation. An outer `///` here would
// make rustdoc resolve the links inside that `//!` block against this scope
// instead of the module's own, which silently breaks every one of them.
pub mod diagnostics;
/// Asynchronous Gateway adapter and bounded UI channels.
pub mod gateway;
/// TUI state and the complete run-state vocabulary.
pub mod model;
/// Deterministic cell-buffer renderer and Crossterm flusher.
pub mod render;
/// Panic-safe terminal lifecycle and background input pump.
pub mod terminal;

use diagnostics::Verbosity;
use gateway::{GatewayOptions, UiCommand, WorkerEvent, endpoint_label, spawn_gateway_worker};
use model::{AppModel, Prompt, Screen};
use terminal::{CrosstermControl, InputThread, TerminalSession};

/// Endpoint used when `--gateway` and `GTA_CLAW_GATEWAY_URL` are both absent.
const DEFAULT_GATEWAY_URL: &str = "ws://127.0.0.1:18789";
const MAX_PALETTE_BYTES: usize = 128;
const MAX_ANSWER_BYTES: usize = 4_096;
const MAX_NOTICE_BYTES: usize = 4_096;
const MAX_EVENT_TEXT_BYTES: usize = 16 * 1024;
const MAX_SESSIONS: usize = 1_000;
const MAX_TRANSCRIPT: usize = 2_000;
const MAX_TOOLS: usize = 500;
const MAX_DIFF_LINES: usize = 10_000;
const MAX_ARTIFACTS: usize = 1_000;
const MAX_ARTIFACT_LINES: usize = 2_000;

/// Process options accepted by the TUI executable.
#[derive(Clone)]
pub struct Options {
    /// Gateway WebSocket endpoint.
    pub gateway_url: Url,
    /// Optional shared token.
    pub token: Option<String>,
    /// Explicit Windows/macOS native device profile, never a plaintext credential file.
    pub device_profile: Option<String>,
    /// Force monochrome rendering.
    pub no_color: bool,
    /// Force a single non-interactive snapshot.
    pub plain: bool,
    /// How much of the Gateway path to report.
    pub verbosity: Verbosity,
    /// Append diagnostics to this file instead of standard error.
    pub log_file: Option<PathBuf>,
}

/// Formats without the token. A derived `Debug` would put the shared secret into
/// any log line, panic message, or bug report that formats the options.
impl fmt::Debug for Options {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Options")
            .field("gateway_url", &endpoint_label(&self.gateway_url))
            .field(
                "token",
                &if self.token.is_some() {
                    "<redacted>"
                } else {
                    "<none>"
                },
            )
            .field("no_color", &self.no_color)
            .field("plain", &self.plain)
            .field("verbosity", &self.verbosity)
            .field("log_file", &self.log_file)
            .finish_non_exhaustive()
    }
}

impl Options {
    /// Parses OS-native arguments without assuming they contain UTF-8.
    ///
    /// # Errors
    ///
    /// Returns the text to show the user when an argument is unknown, a value is
    /// missing, or the Gateway URL is not a usable `ws://` or `wss://` endpoint.
    /// `--help` and `-h` also return here, carrying the help text. The message
    /// never contains the token, and never contains the raw URL, which can carry
    /// credentials in its userinfo or query.
    pub fn parse<I>(arguments: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut gateway = std::env::var_os("GTA_CLAW_GATEWAY_URL").map_or_else(
            || DEFAULT_GATEWAY_URL.to_owned(),
            |value| value.to_string_lossy().into_owned(),
        );
        let token = std::env::var_os("GTA_CLAW_GATEWAY_TOKEN")
            .map(|value| value.to_string_lossy().into_owned());
        let mut no_color = std::env::var_os("NO_COLOR").is_some();
        let mut plain = false;
        let mut device_profile = None;
        let mut verbosity = Verbosity::Off;
        let mut log_file = None;
        let mut values = arguments.into_iter();
        let _program = values.next();
        while let Some(argument) = values.next() {
            match argument.to_string_lossy().as_ref() {
                "--gateway" => {
                    gateway = values
                        .next()
                        .ok_or_else(|| "--gateway requires a URL".to_owned())?
                        .to_string_lossy()
                        .into_owned();
                }
                "--no-color" => no_color = true,
                "--device-profile" => {
                    if device_profile.is_some() {
                        return Err("--device-profile may be specified only once".to_owned());
                    }
                    let profile = values
                        .next()
                        .and_then(|value| value.into_string().ok())
                        .ok_or_else(|| "--device-profile requires an ASCII alias".to_owned())?;
                    if profile.is_empty()
                        || profile.len() > 64
                        || !profile
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                    {
                        return Err("--device-profile must contain 1..64 ASCII letters, digits, hyphens or underscores".to_owned());
                    }
                    device_profile = Some(profile);
                }
                "--plain" => plain = true,
                "-v" | "--verbose" => verbosity = verbosity.max(Verbosity::Basic),
                "-vv" => verbosity = Verbosity::Detailed,
                "--log-file" => {
                    log_file = Some(PathBuf::from(
                        values
                            .next()
                            .ok_or_else(|| "--log-file requires a path".to_owned())?,
                    ));
                }
                "--help" | "-h" => return Err(help_text().to_owned()),
                unknown => return Err(format!("unknown argument: {unknown}\n{}", help_text())),
            }
        }
        let gateway_url =
            Url::parse(&gateway).map_err(|error| format!("invalid Gateway URL: {error}"))?;
        if !matches!(gateway_url.scheme(), "ws" | "wss") {
            return Err(format!(
                "invalid Gateway URL: expected a ws:// or wss:// endpoint, got {}://",
                gateway_url.scheme()
            ));
        }
        Ok(Self {
            gateway_url,
            token,
            device_profile,
            no_color,
            plain,
            verbosity,
            log_file,
        })
    }
}

/// Runs the TUI or its non-TTY snapshot fallback.
///
/// # Errors
///
/// Returns the message to show the user when a requested `--log-file` cannot be
/// opened, or when the terminal cannot be entered, restored, or written to.
/// Gateway failures are not errors here: they are surfaced in the interface as a
/// notice so the session stays usable.
pub async fn run(options: Options) -> Result<(), String> {
    let full_screen = !options.plain && terminal::is_interactive();
    // Resolved and installed here, before any alternate screen exists, so the
    // subscriber can never be pointed at the terminal being drawn and the notice
    // can never land inside the interface or survive into the restored shell.
    // An unusable `--log-file` also stops the run before the terminal is touched.
    let choice = diagnostics::choose_sink(
        options.verbosity,
        options.log_file.as_deref(),
        full_screen,
        io::stderr().is_terminal(),
    );
    let endpoint = endpoint_label(&options.gateway_url);
    if let Some(notice) = diagnostics::install(options.verbosity, &choice, &endpoint)? {
        eprintln!("gta-claw-tui: {notice}");
    }
    let worker_options = GatewayOptions {
        url: options.gateway_url,
        token: options.token,
        device_profile: options.device_profile,
    };
    if full_screen {
        return run_interactive(worker_options, options.no_color)
            .await
            .map_err(|error| error.to_string());
    }
    run_plain(worker_options).await
}

async fn run_plain(options: GatewayOptions) -> Result<(), String> {
    let endpoint = endpoint_label(&options.url);
    let mut worker = spawn_gateway_worker(options);
    let mut model = AppModel::default();
    let deadline = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            event = worker.events.recv() => {
                let Some(event) = event else {
                    break;
                };
                let complete = matches!(event, WorkerEvent::Sessions(_));
                apply_worker_event(&mut model, event);
                if complete {
                    break;
                }
            }
            () = &mut deadline => {
                model.notice = Some(format!(
                    "Gateway snapshot timed out after 5s (tried {endpoint}; \
                     check the gateway is running and reachable)"
                ));
                break;
            }
        }
    }
    println!("{}", render_plain(&model));
    worker.shutdown().await;
    Ok(())
}

async fn run_interactive(options: GatewayOptions, no_color: bool) -> io::Result<()> {
    terminal::install_panic_hook();
    let control = Arc::new(CrosstermControl::default());
    let terminal = TerminalSession::enter(control)?;
    let (input_thread, mut inputs) = InputThread::spawn(64)?;
    let mut worker = spawn_gateway_worker(options);
    let mut model = AppModel::default();
    let mut stdout = io::stdout();
    let mut redraw = true;
    let mut painted: Option<render::Grid> = None;
    let mut signal = Box::pin(shutdown_signal());
    let mut worker_events_open = true;

    let loop_result = async {
        loop {
            if redraw {
                let (width, height) = crossterm_terminal::size().unwrap_or((100, 30));
                model.viewport = (width, height);
                let grid = render::render(&model, width, height, no_color);
                render::flush_changes(&mut stdout, painted.as_ref(), &grid, no_color)?;
                painted = Some(grid);
                acknowledge_rendered_results(&mut model, &worker.commands);
                redraw = false;
            }
            tokio::select! {
                input = inputs.recv() => {
                    let Some(input) = input else {
                        break;
                    };
                    if matches!(input, Event::Resize(_, _)) {
                        painted = None;
                    }
                    if handle_input(&mut model, &input, &worker.commands) {
                        break;
                    }
                    redraw = true;
                }
                event = worker.events.recv(), if worker_events_open => {
                    let Some(event) = event else {
                        "Gateway: worker stopped".clone_into(&mut model.connection);
                        model.notice = Some("Gateway worker stopped unexpectedly".to_owned());
                        worker_events_open = false;
                        redraw = true;
                        continue;
                    };
                    apply_worker_event(&mut model, event);
                    redraw = true;
                }
                result = &mut signal => {
                    result?;
                    break;
                }
            }
        }
        Ok(())
    }
    .await;

    drop(input_thread);
    let restore_result = terminal.restore();
    worker.shutdown().await;
    loop_result.and(restore_result)
}

fn handle_input(model: &mut AppModel, event: &Event, commands: &mpsc::Sender<UiCommand>) -> bool {
    if let Event::Paste(text) = event {
        if model.composer_open && model.prompt.is_none() && !model.palette_open {
            let limit = model
                .memory_draft
                .as_ref()
                .map_or(16 * 1024, |(_, draft)| draft.input_limit());
            if model.composer.len().saturating_add(text.len()) <= limit
                && !text.chars().any(|character| {
                    character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                })
            {
                model.composer.push_str(text);
            } else {
                model.notice =
                    Some("Paste rejected: input limit or unsupported control character".to_owned());
            }
        }
        return false;
    }
    let Event::Key(key) = event else {
        return false;
    };
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return true;
    }
    if model.palette_open {
        return handle_palette(model, key, commands);
    }
    if model.composer_open && model.prompt.is_none() {
        let input_limit = model
            .memory_draft
            .as_ref()
            .map_or(16 * 1024, |(_, draft)| draft.input_limit());
        match key.code {
            KeyCode::Esc => model.composer_open = false,
            KeyCode::Backspace => {
                model.composer.pop();
            }
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::SHIFT) => {
                let _ = push_bounded(&mut model.composer, '\n', input_limit);
            }
            KeyCode::Enter => submit_message(model, commands),
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                    && !push_bounded(&mut model.composer, character, input_limit) =>
            {
                model.notice = Some("Message limit reached".to_owned());
            }
            _ => {}
        }
        return false;
    }
    if matches!(
        model.prompt,
        Some(Prompt::Approval {
            preview_fingerprint: Some(_),
            ..
        })
    ) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                model.approval_scroll = model.approval_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                model.approval_scroll = model.approval_scroll.saturating_add(1).min(32 * 1024);
            }
            KeyCode::PageDown => {
                model.approval_scroll = model
                    .approval_scroll
                    .saturating_add(usize::from(model.viewport.1.saturating_sub(9)))
                    .min(32 * 1024);
            }
            KeyCode::PageUp => {
                model.approval_scroll = model
                    .approval_scroll
                    .saturating_sub(usize::from(model.viewport.1.saturating_sub(9)));
            }
            KeyCode::Char('y') => resolve_prompt(model, commands, true),
            KeyCode::Char('n') => resolve_prompt(model, commands, false),
            KeyCode::Char('q') => return true,
            _ => {}
        }
        return false;
    }
    if matches!(model.prompt, Some(Prompt::Question { .. })) {
        match key.code {
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                if !push_bounded(&mut model.answer, character, MAX_ANSWER_BYTES) {
                    model.notice = Some(format!("Answer limit reached ({MAX_ANSWER_BYTES} bytes)"));
                }
                return false;
            }
            KeyCode::Backspace => {
                model.answer.pop();
                return false;
            }
            KeyCode::Enter => {
                if let (Some(Prompt::Question { id, .. }), Some(session)) =
                    (model.prompt.as_ref(), model.selected_session())
                {
                    let command = UiCommand::Answer {
                        session_id: session.id.clone(),
                        question_id: id.clone(),
                        text: model.answer.clone(),
                    };
                    if queue_command(model, commands, command) {
                        model.prompt = None;
                        model.answer.clear();
                        model.notice = Some("Answer submitted".to_owned());
                    }
                }
                return false;
            }
            _ => {}
        }
    }
    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('c') => begin_message(model, true),
        KeyCode::Char('i') => begin_message(model, false),
        KeyCode::Char('x') => native_run_command(model, commands, true),
        KeyCode::Tab => {
            model.next_screen();
            load_screen(model, commands);
        }
        KeyCode::BackTab => {
            previous_screen(model);
            load_screen(model, commands);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if model.screen == Screen::Sessions {
                model.select_previous();
            } else {
                model.scroll_back();
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if model.screen == Screen::Sessions {
                model.select_next();
            } else {
                model.scroll_forward();
            }
        }
        KeyCode::Enter if model.screen == Screen::Sessions => {
            if let Some(session) = model.selected_session().cloned() {
                model.screen = Screen::Workspace;
                let _ = queue_command(model, commands, UiCommand::SelectSession(session.id));
            }
        }
        KeyCode::Char('y') => resolve_prompt(model, commands, true),
        KeyCode::Char('n') => resolve_prompt(model, commands, false),
        KeyCode::Char('r') => {
            if queue_command(model, commands, UiCommand::Refresh) {
                model.notice = Some("Refreshing sessions...".to_owned());
            }
        }
        KeyCode::Char(':') => model.palette_open = true,
        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            model.palette_open = true;
        }
        KeyCode::Char('?') => model.screen = Screen::Help,
        KeyCode::Char(character @ '1'..='6') => {
            let index = usize::from(character as u8 - b'1');
            model.screen = Screen::ALL[index];
            model.scroll = 0;
            load_screen(model, commands);
        }
        _ => {}
    }
    false
}

fn handle_palette(
    model: &mut AppModel,
    key: &KeyEvent,
    commands: &mpsc::Sender<UiCommand>,
) -> bool {
    match key.code {
        KeyCode::Esc => {
            model.palette_open = false;
            model.palette.clear();
        }
        KeyCode::Backspace => {
            model.palette.pop();
        }
        KeyCode::Char(character)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            if !push_bounded(&mut model.palette, character, MAX_PALETTE_BYTES) {
                model.notice = Some(format!("Command limit reached ({MAX_PALETTE_BYTES} bytes)"));
            }
        }
        KeyCode::Enter => {
            let command = std::mem::take(&mut model.palette);
            model.palette_open = false;
            if command
                .split_whitespace()
                .next()
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("memory"))
            {
                begin_memory(model, commands, &command);
                return false;
            }
            match command.trim().to_ascii_lowercase().as_str() {
                "new" => begin_message(model, true),
                "message" | "send" => begin_message(model, false),
                "cancel" => native_run_command(model, commands, true),
                "run" => native_run_command(model, commands, false),
                "partial" => partial_page_command(model, commands, false),
                "partial-next" => partial_page_command(model, commands, true),
                "retry-send" => {
                    if let Some(pending) = model
                        .pending_message
                        .clone()
                        .filter(|pending| pending.unconfirmed)
                    {
                        if queue_command(model, commands, pending.command()) {
                            if let Some(pending) = model.pending_message.as_mut() {
                                pending.unconfirmed = false;
                            }
                            model.notice = Some("Checking the original submission key".to_owned());
                        }
                    } else {
                        model.notice = Some("No unconfirmed message is retained".to_owned());
                    }
                }
                "discard-send" => {
                    if model
                        .pending_message
                        .as_ref()
                        .is_some_and(|pending| pending.unconfirmed && !pending.may_have_been_sent)
                    {
                        model.pending_message = None;
                        model.notice = Some("Unsent input discarded".to_owned());
                    } else {
                        model.notice =
                            Some("Queued or unknown input must retain its original key".to_owned());
                    }
                }
                "discard-draft" => {
                    model.composer.clear();
                    model.memory_draft = None;
                    model.composer_open = false;
                    model.notice = Some("Unsubmitted draft discarded".to_owned());
                }
                "sessions" => model.screen = Screen::Sessions,
                "workspace" => model.screen = Screen::Workspace,
                "runs" => model.screen = Screen::Runs,
                "diff" => model.screen = Screen::Diff,
                "artifacts" => model.screen = Screen::Artifacts,
                "help" => model.screen = Screen::Help,
                "refresh" => {
                    if queue_command(model, commands, UiCommand::Refresh) {
                        model.notice = Some("Refreshing sessions...".to_owned());
                    }
                }
                "quit" | "q" => return true,
                "" => {}
                unknown => model.notice = Some(format!("Unknown command: {unknown}")),
            }
            model.scroll = 0;
            if !model.composer_open
                && !matches!(
                    command.trim().to_ascii_lowercase().as_str(),
                    "cancel"
                        | "run"
                        | "partial"
                        | "partial-next"
                        | "retry-send"
                        | "discard-send"
                        | "discard-draft"
                )
            {
                load_screen(model, commands);
            }
        }
        _ => {}
    }
    false
}

fn resolve_prompt(model: &mut AppModel, commands: &mpsc::Sender<UiCommand>, approved: bool) {
    if let Some(Prompt::Approval {
        id,
        preview_fingerprint: Some(fingerprint),
        ..
    }) = model.prompt.as_ref()
    {
        if approved && !render::approval_fully_visible(model, model.viewport.0, model.viewport.1) {
            model.notice = Some("Review the remaining approval text before approving".to_owned());
            return;
        }
        let command = UiCommand::ResolveApproval {
            id: id.clone(),
            approved,
            preview_fingerprint: fingerprint.clone(),
        };
        if queue_command(model, commands, command) {
            model.prompt = None;
            model.notice = Some(if approved {
                "Approval submitted".to_owned()
            } else {
                "Denial submitted".to_owned()
            });
        }
    }
}

fn random_message_identity() -> Result<String, String> {
    use ring::rand::SecureRandom;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0_u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "System entropy is unavailable".to_owned())?;
    let mut identity = String::from("tui-");
    for byte in bytes {
        identity.push(char::from(HEX[usize::from(byte >> 4)]));
        identity.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok(identity)
}

fn begin_message(model: &mut AppModel, new_session: bool) {
    if model.pending_message.is_some() {
        model.notice = Some("A queued or unknown message must be reconciled first".to_owned());
        return;
    }
    if let Some((session_id, _)) = &model.memory_draft {
        if !new_session
            && model
                .selected_session()
                .is_some_and(|session| &session.id == session_id)
        {
            model.screen = Screen::Workspace;
            model.composer_open = true;
        } else {
            model.notice = Some("A memory draft remains bound to its original session".to_owned());
        }
        return;
    }
    if new_session || model.selected_session().is_none() {
        if model.sessions.len() >= MAX_SESSIONS {
            model.notice = Some("Session display capacity reached".to_owned());
            return;
        }
        let id = match random_message_identity() {
            Ok(id) => id,
            Err(error) => {
                model.notice = Some(error);
                return;
            }
        };
        model.sessions.push(model::SessionSummary {
            id: id.clone(),
            title: id,
            state: model::RunState::Draft,
            ..model::SessionSummary::default()
        });
        model.selected = model.sessions.len() - 1;
        model.clear_session_view();
    }
    model.screen = model::Screen::Workspace;
    model.composer_open = true;
}

fn begin_memory(model: &mut AppModel, commands: &mpsc::Sender<UiCommand>, palette: &str) {
    if model.pending_message.is_some() || model.memory_draft.is_some() || !model.composer.is_empty()
    {
        model.notice =
            Some("Existing input must be resolved or explicitly discarded first".to_owned());
        return;
    }
    let draft = match gateway::MemoryDraft::parse(palette) {
        Ok(draft) => draft,
        Err(error) => {
            model.notice = Some(error.to_owned());
            return;
        }
    };
    begin_message(model, false);
    let Some(session) = model.selected_session() else {
        return;
    };
    let requires_input = draft.input_limit() != 0;
    model.memory_draft = Some((session.id.clone(), draft));
    if !requires_input {
        submit_message(model, commands);
    }
}

fn submit_message(model: &mut AppModel, commands: &mpsc::Sender<UiCommand>) {
    if model.pending_message.is_some()
        || model.memory_draft.is_none() && model.composer.trim().is_empty()
    {
        return;
    }
    let Some(session) = model.selected_session() else {
        return;
    };
    let memory = if let Some((session_id, draft)) = &model.memory_draft {
        if session_id != &session.id {
            model.notice =
                Some("Memory draft belongs to a different session; nothing was sent".to_owned());
            return;
        }
        match draft.finish(&model.composer) {
            Ok(command) => Some(command),
            Err(error) => {
                model.notice = Some(error.to_owned());
                return;
            }
        }
    } else {
        None
    };
    let idempotency_key = match random_message_identity() {
        Ok(id) => id,
        Err(error) => {
            model.notice = Some(error);
            return;
        }
    };
    let pending = model::PendingMessage {
        session_id: session.id.clone(),
        text: memory.as_ref().map_or_else(
            || model.composer.clone(),
            |command| format!("Memory {} (explicit, untrusted data)", command.action()),
        ),
        idempotency_key,
        unconfirmed: false,
        may_have_been_sent: false,
        memory,
    };
    if queue_command(model, commands, pending.command()) {
        model.pending_message = Some(pending);
        model.composer.clear();
        model.memory_draft = None;
        model.composer_open = false;
        model.notice = Some("Awaiting durable message receipt".to_owned());
    }
}

fn native_run_command(model: &mut AppModel, commands: &mpsc::Sender<UiCommand>, cancel: bool) {
    if let Some((session_id, run_id)) = model.active_run.clone() {
        if model
            .selected_session()
            .is_some_and(|session| session.id == session_id)
        {
            let command = if cancel {
                UiCommand::AbortRun { session_id, run_id }
            } else {
                UiCommand::QueryRun { session_id, run_id }
            };
            let _ = queue_command(model, commands, command);
        }
    } else {
        model.notice = Some("No confirmed run is selected".to_owned());
    }
}

fn partial_page_command(model: &mut AppModel, commands: &mpsc::Sender<UiCommand>, next: bool) {
    let Some((session_id, run_id)) = model.active_run.clone() else {
        model.notice = Some("No confirmed run is selected".to_owned());
        return;
    };
    let Some((Some(turn), revision)) = model.active_run_version else {
        model.notice = Some("A bound terminal run revision is required".to_owned());
        return;
    };
    let Some(session) = model
        .selected_session()
        .filter(|session| session.id == session_id)
    else {
        return;
    };
    let state = session.state;
    if !matches!(
        state,
        model::RunState::Completed
            | model::RunState::CompletedWithChanges
            | model::RunState::Failed
            | model::RunState::Cancelled
            | model::RunState::OutcomeUnknown
    ) {
        model.notice = Some("The selected run has not reached a terminal state".to_owned());
        return;
    }
    let request = if next {
        let Some(page) = model.partial_page.as_ref().filter(|page| {
            page.request.session_id == session_id
                && page.request.run_id == run_id
                && page.request.turn == turn
                && page.request.revision == revision
                && page.request.state == state
        }) else {
            model.notice = Some("No partial-text continuation is selected".to_owned());
            return;
        };
        let Some(offset) = page.next_offset else {
            model.notice = Some("End of retained partial text".to_owned());
            return;
        };
        gateway::PartialPageRequest {
            offset,
            total_bytes: Some(page.total_bytes),
            sha256: Some(page.sha256.clone()),
            ..page.request.clone()
        }
    } else {
        gateway::PartialPageRequest {
            session_id,
            run_id,
            revision,
            turn,
            state,
            offset: 0,
            total_bytes: None,
            sha256: None,
        }
    };
    if queue_command(model, commands, UiCommand::ReadPartial(request)) {
        model.screen = Screen::Workspace;
        model.notice = Some("Reading retained partial text".to_owned());
    }
}

fn load_screen(model: &mut AppModel, commands: &mpsc::Sender<UiCommand>) {
    let Some(session) = model.selected_session() else {
        return;
    };
    let command = match model.screen {
        Screen::Workspace => Some(UiCommand::SelectSession(session.id.clone())),
        Screen::Diff => Some(UiCommand::LoadDiff(session.id.clone())),
        Screen::Artifacts => Some(UiCommand::LoadArtifacts(session.id.clone())),
        Screen::Sessions | Screen::Runs | Screen::Help => None,
    };
    if let Some(command) = command {
        let _ = queue_command(model, commands, command);
    }
}

fn queue_command(
    model: &mut AppModel,
    commands: &mpsc::Sender<UiCommand>,
    command: UiCommand,
) -> bool {
    let command = if command.requires_connection() {
        let Some(connection_id) = model.connection_id else {
            model.notice = Some("Gateway is not ready; no command was sent".to_owned());
            return false;
        };
        command.for_connection(connection_id)
    } else {
        command
    };
    match commands.try_send(command) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            model.notice = Some("Gateway is busy; wait and try again".to_owned());
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            model.notice = Some("Gateway worker stopped; restart the TUI".to_owned());
            false
        }
    }
}

fn acknowledge_rendered_results(model: &mut AppModel, commands: &mpsc::Sender<UiCommand>) {
    if model.screen != Screen::Workspace || model.viewport.0 < 40 || model.viewport.1 < 10 {
        return;
    }
    while let Some((run_id, revision)) = model.pending_acks.front().cloned() {
        if !queue_command(
            model,
            commands,
            UiCommand::AcknowledgeRun { run_id, revision },
        ) {
            break;
        }
        model.pending_acks.pop_front();
    }
    if model.pending_acks.is_empty()
        && let Some(session_id) = model.pending_recovery.clone()
        && queue_command(model, commands, UiCommand::RecoverRuns(session_id))
    {
        model.pending_recovery = None;
    }
}

fn push_bounded(value: &mut String, character: char, max_bytes: usize) -> bool {
    if value.len().saturating_add(character.len_utf8()) > max_bytes {
        return false;
    }
    value.push(character);
    true
}

fn previous_screen(model: &mut AppModel) {
    let index = Screen::ALL
        .iter()
        .position(|screen| *screen == model.screen)
        .unwrap_or(0);
    model.screen = Screen::ALL[(index + Screen::ALL.len() - 1) % Screen::ALL.len()];
    model.scroll = 0;
}

fn apply_worker_event(model: &mut AppModel, event: WorkerEvent) {
    match event {
        WorkerEvent::Accepted {
            session_id,
            run_id,
            idempotency_key,
        } => {
            if let Some(pending) = model.pending_message.take() {
                if pending.idempotency_key != idempotency_key || pending.session_id != session_id {
                    model.pending_message = Some(pending);
                    return;
                }
                if model
                    .selected_session()
                    .is_some_and(|session| session.id == session_id)
                {
                    model.transcript.push_back(model::TranscriptEntry {
                        role: "user".to_owned(),
                        text: pending.text,
                    });
                    while model.transcript.len() > MAX_TRANSCRIPT {
                        model.transcript.pop_front();
                    }
                }
            }
            if model
                .selected_session()
                .is_some_and(|session| session.id == session_id)
            {
                model.active_run = Some((session_id, run_id));
                model.active_run_version = None;
            }
            model.notice = Some("Message accepted durably".to_owned());
        }
        WorkerEvent::SendUnconfirmed { idempotency_key } => {
            if let Some(pending) = model
                .pending_message
                .as_mut()
                .filter(|pending| pending.idempotency_key == idempotency_key)
            {
                pending.unconfirmed = true;
                pending.may_have_been_sent = true;
            }
            model.notice = Some(
                "Message delivery is unknown; retain and reconcile the original key".to_owned(),
            );
        }
        WorkerEvent::SendNotSent {
            idempotency_key,
            reason,
        } => {
            if let Some(pending) = model
                .pending_message
                .as_mut()
                .filter(|pending| pending.idempotency_key == idempotency_key)
            {
                pending.unconfirmed = true;
                model.notice = Some(if pending.may_have_been_sent {
                    format!(
                        "This attempt was not sent; earlier delivery remains unknown. {}",
                        bounded_owned(reason, MAX_NOTICE_BYTES / 2)
                    )
                } else {
                    format!("Not sent: {}", bounded_owned(reason, MAX_NOTICE_BYTES / 2))
                });
            }
        }
        WorkerEvent::PartialPage(mut page) => {
            if model.selected_session().is_none_or(|session| {
                session.id != page.request.session_id || session.state != page.request.state
            }) || model.active_run.as_ref().is_none_or(|(session, run)| {
                *session != page.request.session_id || *run != page.request.run_id
            }) || model.active_run_version
                != Some((Some(page.request.turn), page.request.revision))
            {
                return;
            }
            if model.partial_page.as_ref().is_some_and(|previous| {
                previous.request == page.request
                    && previous.end_offset == page.end_offset
                    && previous.sha256 == page.sha256
            }) {
                return;
            }
            if page.request.offset > 0
                && model.partial_page.as_ref().is_none_or(|previous| {
                    previous.next_offset != Some(page.request.offset)
                        || previous.sha256 != page.sha256
                        || previous.total_bytes != page.total_bytes
                        || previous.request.run_id != page.request.run_id
                        || previous.request.revision != page.request.revision
                })
            {
                return;
            }
            page.text = bounded_owned(
                crate::diagnostics::sanitize(&page.text),
                MAX_EVENT_TEXT_BYTES,
            );
            model.transcript.push_back(model::TranscriptEntry {
                role: format!(
                    "partial [{}..{}/{} bytes]",
                    page.request.offset, page.end_offset, page.total_bytes
                ),
                text: page.text.clone(),
            });
            while model.transcript.len() > MAX_TRANSCRIPT {
                model.transcript.pop_front();
            }
            model.notice = Some(format!(
                "Unconfirmed partial text: bytes {}..{} of {}",
                page.request.offset, page.end_offset, page.total_bytes
            ));
            model.partial_page = Some(page);
            model.scroll = 0;
        }
        WorkerEvent::NativeRun {
            session_id,
            run_id,
            state,
            turn,
            text,
            revision,
            provider_accounting,
        } => {
            if model
                .selected_session()
                .is_some_and(|session| session.id == session_id)
            {
                if let Some(text) = text {
                    if model
                        .received_results
                        .iter()
                        .any(|(received, current)| received == &run_id && *current >= revision)
                    {
                        return;
                    }
                    if model.pending_acks.len() >= MAX_TRANSCRIPT {
                        model.notice = Some("Result acknowledgement capacity reached; retained results remain on the server".to_owned());
                        return;
                    }
                    model.transcript.push_back(model::TranscriptEntry {
                        role: "assistant".to_owned(),
                        text,
                    });
                    while model.transcript.len() > MAX_TRANSCRIPT {
                        model.transcript.pop_front();
                    }
                    model.received_results.push_back((run_id.clone(), revision));
                    while model.received_results.len() > MAX_TRANSCRIPT {
                        model.received_results.pop_front();
                    }
                    model.pending_acks.push_back((run_id.clone(), revision));
                }
                if let Some((active_session, active_id)) = &model.active_run
                    && active_session == &session_id
                {
                    if active_id != &run_id {
                        if model.active_run_version.is_none_or(|(active_turn, _)| {
                            active_turn.is_none() || turn.is_none() || turn <= active_turn
                        }) {
                            return;
                        }
                    } else if model
                        .active_run_version
                        .is_some_and(|(_, current)| revision <= current)
                    {
                        return;
                    }
                }
                model.partial_page = None;
                model.active_run = Some((session_id, run_id));
                model.active_run_version = Some((turn, revision));
                model.provider_accounting = provider_accounting;
                if let Some(session) = model.sessions.get_mut(model.selected) {
                    session.state = state;
                }
            }
        }
        WorkerEvent::RecoveryAvailable(session_id) => {
            if model
                .selected_session()
                .is_some_and(|session| session.id == session_id)
            {
                model.pending_recovery = Some(session_id);
            }
        }
        WorkerEvent::ResultAcknowledged { .. } => {}
        WorkerEvent::Connection(connection) => {
            model.clear_session_view();
            model.connection_id = None;
            if let Some(pending) = model.pending_message.as_mut() {
                pending.may_have_been_sent |= !pending.unconfirmed;
                pending.unconfirmed = true;
            }
            model.approval_scroll = 0;
            model.connection = bounded_owned(connection, MAX_NOTICE_BYTES);
        }
        WorkerEvent::Ready {
            connection_id,
            description,
        } => {
            model.connection_id = Some(connection_id);
            model.connection = bounded_owned(description, MAX_NOTICE_BYTES);
        }
        WorkerEvent::Sessions(sessions) => {
            let selected = model.selected_session().cloned();
            let previous_id = selected.as_ref().map(|session| session.id.clone());
            let preserve_draft = selected
                .as_ref()
                .filter(|session| {
                    model.composer_open
                        || model
                            .pending_message
                            .as_ref()
                            .is_some_and(|pending| pending.session_id == session.id)
                })
                .cloned();
            model.sessions = sessions.into_iter().take(MAX_SESSIONS).collect();
            if let Some(draft) = preserve_draft
                && !model.sessions.iter().any(|session| session.id == draft.id)
            {
                model.sessions.truncate(MAX_SESSIONS.saturating_sub(1));
                model.sessions.push(draft);
            }
            model.selected = selected
                .and_then(|selected| {
                    model
                        .sessions
                        .iter()
                        .position(|session| session.id == selected.id)
                })
                .unwrap_or_else(|| model.selected.min(model.sessions.len().saturating_sub(1)));
            if previous_id.as_deref() != model.selected_session().map(|session| session.id.as_str())
            {
                model.clear_session_view();
            }
            model.scroll = model.scroll.min(model.sessions.len().saturating_sub(1));
            model.notice = None;
        }
        WorkerEvent::Message {
            session_id,
            mut message,
        } => {
            if model
                .selected_session()
                .is_none_or(|session| session.id != session_id)
            {
                return;
            }
            message.role = bounded_owned(message.role, 128);
            message.text = bounded_owned(message.text, MAX_EVENT_TEXT_BYTES);
            model.transcript.push_back(message);
            while model.transcript.len() > MAX_TRANSCRIPT {
                model.transcript.pop_front();
            }
        }
        WorkerEvent::History {
            session_id,
            messages,
        } => {
            if model
                .selected_session()
                .is_some_and(|session| session.id == session_id)
            {
                model.transcript = messages.into_iter().take(MAX_TRANSCRIPT).collect();
                model.partial_page = None;
                model.tools.clear();
                model.scroll = 0;
            }
        }
        WorkerEvent::Tool {
            session_id,
            mut tool,
        } => {
            if model
                .selected_session()
                .is_none_or(|session| session.id != session_id)
            {
                return;
            }
            tool.name = bounded_owned(tool.name, 128);
            tool.status = bounded_owned(tool.status, 128);
            tool.summary = bounded_owned(tool.summary, MAX_EVENT_TEXT_BYTES);
            model.tools.push_back(tool);
            while model.tools.len() > MAX_TOOLS {
                model.tools.pop_front();
            }
        }
        WorkerEvent::SessionPrompt { session_id, prompt } => {
            if model
                .selected_session()
                .is_some_and(|session| session.id == session_id)
            {
                apply_worker_event(model, WorkerEvent::Prompt(prompt));
            }
        }
        WorkerEvent::Prompt(prompt) => {
            if model.prompt.is_some() {
                model.notice =
                    Some("Another request is pending; the current preview was retained".to_owned());
                return;
            }
            model.approval_scroll = 0;
            model.prompt = Some(match prompt {
                Prompt::Approval {
                    id,
                    text,
                    preview_fingerprint,
                } => {
                    if id.len() > 128 || text.len() > MAX_EVENT_TEXT_BYTES {
                        model.notice =
                            Some("Approval preview exceeds the display limit".to_owned());
                        return;
                    }
                    Prompt::Approval {
                        id: bounded_owned(id, 1_024),
                        text,
                        preview_fingerprint,
                    }
                }
                Prompt::Question { id, text } => Prompt::Question {
                    id: bounded_owned(id, 1_024),
                    text: bounded_owned(text, MAX_EVENT_TEXT_BYTES),
                },
            });
            model.answer.clear();
        }
        WorkerEvent::PromptDismissed(id) => {
            if matches!(&model.prompt, Some(Prompt::Approval { id: pending, .. }) if pending == &id)
            {
                model.prompt = None;
                model.approval_scroll = 0;
            }
        }
        WorkerEvent::Diff {
            session_id,
            lines: diff,
        } => {
            if model
                .selected_session()
                .is_none_or(|session| session.id != session_id)
            {
                return;
            }
            model.diff = diff
                .into_iter()
                .take(MAX_DIFF_LINES)
                .map(|line| bounded_owned(line, MAX_EVENT_TEXT_BYTES))
                .collect();
            model.scroll = 0;
        }
        WorkerEvent::Artifacts {
            session_id,
            artifacts,
        } => {
            if model
                .selected_session()
                .is_none_or(|session| session.id != session_id)
            {
                return;
            }
            model.artifacts = artifacts
                .into_iter()
                .take(MAX_ARTIFACTS)
                .map(|name| bounded_owned(name, 1_024))
                .collect();
            model.artifact_content.clear();
            model.scroll = 0;
        }
        WorkerEvent::ArtifactContent {
            session_id,
            lines: content,
        } => {
            if model
                .selected_session()
                .is_none_or(|session| session.id != session_id)
            {
                return;
            }
            model.artifact_content = content
                .into_iter()
                .take(MAX_ARTIFACT_LINES)
                .map(|line| bounded_owned(line, MAX_EVENT_TEXT_BYTES))
                .collect();
        }
        WorkerEvent::Notice(notice) => {
            model.notice = Some(bounded_owned(notice, MAX_NOTICE_BYTES));
        }
    }
}

fn bounded_owned(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let suffix = if max_bytes >= '…'.len_utf8() {
        "…"
    } else {
        ""
    };
    let mut end = max_bytes.saturating_sub(suffix.len()).min(value.len());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.truncate(end);
    value.push_str(suffix);
    value
}

fn render_plain(model: &AppModel) -> String {
    let mut lines = vec![
        "GTA Claw terminal snapshot".to_owned(),
        model.connection.clone(),
    ];
    if model.sessions.is_empty() {
        lines.push("No sessions".to_owned());
    } else {
        lines.extend(model.sessions.iter().map(|session| {
            format!(
                "[{}] {} - {} ({})",
                session.state.marker(),
                session.title,
                session.state.label(),
                session.workspace
            )
        }));
    }
    if let Some(notice) = &model.notice {
        lines.push(format!("Notice: {notice}"));
    }
    lines.join("\n")
}

#[cfg(unix)]
async fn shutdown_signal() -> io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}

const fn help_text() -> &'static str {
    "Usage: gta-claw-tui [--gateway ws://HOST:PORT] [--no-color] [--plain]\n\
     Set GTA_CLAW_GATEWAY_TOKEN for authenticated Gateways.\n\
     \n\
     Options:\n\
     \x20 --gateway <url>  ws:// or wss:// Gateway endpoint.\n\
     \x20                  Default: GTA_CLAW_GATEWAY_URL, else ws://127.0.0.1:18789\n\
    \x20 --device-profile <alias>  persistent Windows/macOS OS-protected device identity\n\
    \x20                           Default: ephemeral; no fallback if profile storage fails\n\
     \x20 --no-color       monochrome rendering. Default: on when NO_COLOR is set\n\
     \x20 --plain          print one snapshot and exit instead of taking over the\n\
     \x20                  terminal. Default: on when stdin or stdout is not a TTY\n\
     \x20 -v, --verbose    write structured diagnostics to standard error as JSON\n\
     \x20                  lines. In full-screen mode they are written only when\n\
     \x20                  standard error is not the terminal being drawn, so\n\
     \x20                  redirect it (2>run.jsonl), pass --log-file, or add\n\
     \x20                  --plain to keep them. Default: none\n\
     \x20 -vv              as --verbose, plus correlation identifiers\n\
     \x20 --log-file <p>   append diagnostics to <p> instead of standard error.\n\
     \x20                  Always safe in full-screen mode. The directory must\n\
     \x20                  already exist; a file that cannot be opened stops the\n\
     \x20                  run instead of falling back to standard error\n\
     \x20 --help, -h       print this text and exit 0\n\
     \n\
     Environment:\n\
     \x20 GTA_CLAW_GATEWAY_URL    default endpoint, overridden by --gateway\n\
     \x20 GTA_CLAW_GATEWAY_TOKEN  shared token. There is no token flag, so the\n\
     \x20                         secret never appears in argv. It is never echoed\n\
     \x20                         or printed back\n\
     \x20 GTA_CLAW_LOG            tracing filter directives, honored when -v or\n\
     \x20                         -vv installs the shared subscriber\n\
     \x20 NO_COLOR                any value turns off color\n\
     \n\
     Keys: Tab screens  arrows or j/k navigate  Enter open  y/n approve\n\
     \x20     r refresh  : or Ctrl-P palette  1..6 jump  ? help  q quit\n\
     \n\
     Exit codes: 0 success, 2 usage, 1 terminal or runtime failure."
}

#[cfg(test)]
mod tests {
    #[test]
    fn native_session_events_and_selection_cannot_mix_views_or_acknowledgements() {
        use crate::model::{RunState, ToolActivity};

        let mut model = AppModel {
            sessions: vec![
                SessionSummary {
                    id: "current".to_owned(),
                    ..SessionSummary::default()
                },
                SessionSummary {
                    id: "other".to_owned(),
                    ..SessionSummary::default()
                },
            ],
            ..AppModel::default()
        };
        apply_worker_event(
            &mut model,
            WorkerEvent::Message {
                session_id: "other".to_owned(),
                message: TranscriptEntry {
                    role: "assistant".to_owned(),
                    text: "not current".to_owned(),
                },
            },
        );
        apply_worker_event(
            &mut model,
            WorkerEvent::Tool {
                session_id: "other".to_owned(),
                tool: ToolActivity {
                    name: "private".to_owned(),
                    status: "running".to_owned(),
                    summary: "not current".to_owned(),
                },
            },
        );
        apply_worker_event(
            &mut model,
            WorkerEvent::SessionPrompt {
                session_id: "other".to_owned(),
                prompt: Prompt::Question {
                    id: "question".to_owned(),
                    text: "not current".to_owned(),
                },
            },
        );
        apply_worker_event(
            &mut model,
            WorkerEvent::Diff {
                session_id: "other".to_owned(),
                lines: vec!["not current".to_owned()],
            },
        );
        apply_worker_event(
            &mut model,
            WorkerEvent::Artifacts {
                session_id: "other".to_owned(),
                artifacts: vec!["not current".to_owned()],
            },
        );
        apply_worker_event(
            &mut model,
            WorkerEvent::ArtifactContent {
                session_id: "other".to_owned(),
                lines: vec!["not current".to_owned()],
            },
        );
        assert!(
            model.diff.is_empty()
                && model.artifacts.is_empty()
                && model.artifact_content.is_empty()
        );
        apply_worker_event(
            &mut model,
            WorkerEvent::Accepted {
                session_id: "other".to_owned(),
                run_id: "a".repeat(64),
                idempotency_key: "other-key".to_owned(),
            },
        );
        assert!(
            model.transcript.is_empty()
                && model.tools.is_empty()
                && model.prompt.is_none()
                && model.active_run.is_none()
        );
        apply_worker_event(
            &mut model,
            WorkerEvent::NativeRun {
                session_id: "current".to_owned(),
                run_id: "b".repeat(64),
                state: RunState::Completed,
                turn: Some(1),
                text: Some("current complete result".to_owned()),
                revision: 4,
                provider_accounting: None,
            },
        );
        assert_eq!(model.pending_acks.len(), 1);
        model.select_next();
        assert_eq!(model.selected_session().expect("next session").id, "other");
        assert!(
            model.transcript.is_empty()
                && model.active_run.is_none()
                && model.pending_acks.is_empty()
        );
        apply_worker_event(
            &mut model,
            WorkerEvent::Message {
                session_id: "current".to_owned(),
                message: TranscriptEntry {
                    role: "assistant".to_owned(),
                    text: "late previous event".to_owned(),
                },
            },
        );
        assert!(model.transcript.is_empty());
        apply_worker_event(
            &mut model,
            WorkerEvent::Message {
                session_id: "other".to_owned(),
                message: TranscriptEntry {
                    role: "assistant".to_owned(),
                    text: "current event".to_owned(),
                },
            },
        );
        assert_eq!(model.transcript.len(), 1);
        apply_worker_event(
            &mut model,
            WorkerEvent::Connection("reconnecting".to_owned()),
        );
        assert!(model.transcript.is_empty());
    }

    #[test]
    fn partial_pages_preserve_unknown_state_and_never_enqueue_result_acknowledgements() {
        use crate::{
            gateway::{PartialPage, PartialPageRequest},
            model::{RunState, SessionSummary},
            partial_page_command,
        };

        let run_id = "a".repeat(64);
        let mut model = AppModel {
            connection_id: Some(1),
            screen: Screen::Workspace,
            sessions: vec![SessionSummary {
                id: "selected".to_owned(),
                state: RunState::OutcomeUnknown,
                ..SessionSummary::default()
            }],
            active_run: Some(("selected".to_owned(), run_id.clone())),
            active_run_version: Some((Some(2), 4)),
            ..AppModel::default()
        };
        let (commands, mut queued) = tokio::sync::mpsc::channel(4);
        partial_page_command(&mut model, &commands, false);
        let first = PartialPageRequest {
            session_id: "selected".to_owned(),
            run_id,
            revision: 4,
            turn: 2,
            state: RunState::OutcomeUnknown,
            offset: 0,
            total_bytes: None,
            sha256: None,
        };
        assert_eq!(
            queued.try_recv().expect("explicit read"),
            UiCommand::ReadPartial(first.clone()).for_connection(1)
        );
        let page = PartialPage {
            request: first,
            text: "untrusted text".to_owned(),
            end_offset: 14,
            next_offset: Some(14),
            total_bytes: 20,
            sha256: "b".repeat(64),
        };
        apply_worker_event(&mut model, WorkerEvent::PartialPage(page.clone()));
        apply_worker_event(&mut model, WorkerEvent::PartialPage(page));
        assert_eq!(model.transcript.len(), 1);
        assert!(model.transcript[0].role.starts_with("partial"));
        assert_eq!(model.sessions[0].state, RunState::OutcomeUnknown);
        assert!(model.pending_acks.is_empty() && model.received_results.is_empty());
        partial_page_command(&mut model, &commands, true);
        let expected = PartialPageRequest {
            offset: 14,
            total_bytes: Some(20),
            sha256: Some("b".repeat(64)),
            ..model.partial_page.as_ref().expect("cursor").request.clone()
        };
        assert_eq!(
            queued.try_recv().expect("pinned continuation"),
            UiCommand::ReadPartial(expected.clone()).for_connection(1)
        );
        let last = PartialPage {
            request: expected,
            text: "ending".to_owned(),
            end_offset: 20,
            next_offset: None,
            total_bytes: 20,
            sha256: "b".repeat(64),
        };
        model.active_run_version = Some((Some(2), 5));
        apply_worker_event(&mut model, WorkerEvent::PartialPage(last.clone()));
        assert_eq!(model.transcript.len(), 1);
        model.active_run_version = Some((Some(2), 4));
        apply_worker_event(&mut model, WorkerEvent::PartialPage(last.clone()));
        assert_eq!(model.transcript.len(), 2);
        partial_page_command(&mut model, &commands, true);
        assert!(queued.try_recv().is_err());
        assert!(model.pending_acks.is_empty());
        model.clear_session_view();
        apply_worker_event(&mut model, WorkerEvent::PartialPage(last));
        assert!(model.transcript.is_empty() && model.partial_page.is_none());
    }

    #[test]
    fn native_result_ack_queue_preserves_multiple_results_and_waits_for_workspace_render() {
        use crate::{acknowledge_rendered_results, model};
        use tokio::sync::mpsc;

        let mut model = AppModel {
            connection_id: Some(1),
            sessions: vec![model::SessionSummary {
                id: "selected".to_owned(),
                ..model::SessionSummary::default()
            }],
            viewport: (100, 30),
            ..AppModel::default()
        };
        for turn in [2, 1] {
            apply_worker_event(
                &mut model,
                WorkerEvent::NativeRun {
                    session_id: "selected".to_owned(),
                    run_id: format!("{turn:064x}"),
                    state: model::RunState::Completed,
                    turn: Some(turn),
                    text: Some("complete result shared text".to_owned()),
                    revision: 4,
                    provider_accounting: None,
                },
            );
        }
        assert_eq!(model.pending_acks.len(), 2);
        assert_eq!(model.transcript.len(), 2);
        assert_eq!(
            model
                .active_run
                .as_ref()
                .expect("latest cancellation target")
                .1,
            format!("{:064x}", 2)
        );
        let (commands, mut receiver) = mpsc::channel(1);
        acknowledge_rendered_results(&mut model, &commands);
        assert!(receiver.try_recv().is_err());
        assert_eq!(model.pending_acks.len(), 2);
        model.screen = Screen::Workspace;
        model.viewport = (20, 5);
        acknowledge_rendered_results(&mut model, &commands);
        assert!(receiver.try_recv().is_err());
        model.viewport = (100, 30);
        acknowledge_rendered_results(&mut model, &commands);
        assert_eq!(model.pending_acks.len(), 1);
        assert_eq!(
            receiver.try_recv().expect("first exact result ACK"),
            UiCommand::AcknowledgeRun {
                run_id: format!("{:064x}", 2),
                revision: 4
            }
            .for_connection(1)
        );
        acknowledge_rendered_results(&mut model, &commands);
        assert!(model.pending_acks.is_empty());
        assert_eq!(
            receiver.try_recv().expect("second exact result ACK"),
            UiCommand::AcknowledgeRun {
                run_id: format!("{:064x}", 1),
                revision: 4
            }
            .for_connection(1)
        );
    }

    #[test]
    fn memory_drafts_are_session_bound_and_paste_never_submits_or_truncates() {
        let mut model = AppModel {
            connection_id: Some(1),
            ..AppModel::default()
        };
        let (commands, mut queued) = tokio::sync::mpsc::channel(8);
        crate::begin_memory(&mut model, &commands, "memory save Note fact 0");
        let original = model
            .selected_session()
            .expect("original session")
            .id
            .clone();
        let text = "line one\n!tool {}\n\u{4e2d}\u{6587}";
        handle_input(&mut model, &Event::Paste(text.to_owned()), &commands);
        assert_eq!(model.composer, text);
        assert!(queued.try_recv().is_err());
        handle_input(&mut model, &Event::Paste("x".repeat(8_192)), &commands);
        assert_eq!(model.composer, text);
        handle_input(&mut model, &Event::Paste("\u{1b}[2J".to_owned()), &commands);
        assert_eq!(model.composer, text);
        model.sessions.push(crate::model::SessionSummary {
            id: "other-session".to_owned(),
            ..crate::model::SessionSummary::default()
        });
        model.selected = 1;
        model.clear_session_view();
        assert!(!model.composer_open);
        crate::begin_message(&mut model, false);
        assert!(!model.composer_open);
        crate::submit_message(&mut model, &commands);
        assert!(queued.try_recv().is_err());
        assert_eq!(model.composer, text);
        model.selected = 0;
        crate::begin_message(&mut model, false);
        assert!(model.composer_open);
        crate::submit_message(&mut model, &commands);
        let UiCommand::ForConnection { command, .. } =
            queued.try_recv().expect("original-session submit")
        else {
            panic!("connection envelope")
        };
        let UiCommand::InvokeMemory { session_id, .. } = *command else {
            panic!("typed memory")
        };
        assert_eq!(session_id, original);
    }

    #[test]
    fn memory_commands_validate_utf8_cursors_closed_archives_and_encoded_limits() {
        use crate::gateway::{MemoryCommand, MemoryDraft};
        for palette in [
            "memory list",
            "memory list 32 Note 9",
            "memory get Note 4 2048",
            "memory delete Note 0",
            "memory export 0",
            "memory export 4 4096",
        ] {
            let draft = MemoryDraft::parse(palette).expect("metadata command");
            assert!(draft.finish("").is_ok());
        }
        for palette in [
            "memory",
            "memory list 0",
            "memory list 33",
            "memory list 1 Note",
            "memory get Note 1 8193",
            "memory delete Note -1",
            "memory save _id fact 0",
            "memory save id system 0",
            "memory import 0 true",
            "memory export 18446744073709551616",
        ] {
            assert!(MemoryDraft::parse(palette).is_err(), "{palette}");
        }
        let save = MemoryDraft::parse("memory save Note fact 0").expect("save");
        let content = format!("{}ab", "\u{4e2d}".repeat(2_730));
        assert_eq!(content.len(), 8_192);
        assert!(save.finish(&content).is_ok());
        assert!(save.finish(&format!("{content}x")).is_err());
        assert!(save.finish(&"\\".repeat(8_192)).is_err());
        assert!(save.finish("\u{1b}[2J").is_err());
        assert!(save.finish(" \n ").is_err());
        assert!(
            MemoryDraft::parse("memory search 8")
                .expect("search")
                .finish(&"x".repeat(4_096))
                .is_ok()
        );
        assert!(MemoryCommand::new(serde_json::json!({"action":"list","after":"Note"})).is_err());
        assert!(
            MemoryCommand::new(serde_json::json!({"action":"get","id":"Note","offset":1})).is_err()
        );
        assert!(
            MemoryCommand::new(serde_json::json!({"action":"list","token":"never-a-parameter"}))
                .is_err()
        );
        let import = MemoryDraft::parse("memory import 0 overwrite").expect("import");
        assert!(
            import
                .finish(r#"{"schemaVersion":1,"notebook":{"revision":0,"entries":[]}}"#)
                .is_ok()
        );
        for archive in [
            r#"{"schemaVersion":1,"schemaVersion":1,"notebook":{"revision":0,"entries":[]}}"#,
            r#"{"schemaVersion":2,"notebook":{"revision":0,"entries":[]}}"#,
            r#"{"schemaVersion":1,"notebook":{"revision":0,"revision":0,"entries":[]}}"#,
            r#"{"schemaVersion":1,"notebook":{"revision":0,"entries":[]},"extra":true}"#,
            r#"{"schemaVersion":1,"notebook":{"revision":0,"entries":[{"id":"Note","kind":"fact","content":"note","sourceSession":"origin","revision":1}]}}"#,
            r#"{"schemaVersion":1,"notebook":{"revision":1,"entries":[{"id":"Note","id":"Other","kind":"fact","content":"note","sourceSession":"origin","revision":1}]}}"#,
        ] {
            assert!(import.finish(archive).is_err());
        }
    }

    #[test]
    fn memory_palette_keeps_case_data_revisions_and_unknown_retry_identity() {
        let mut model = AppModel {
            connection_id: Some(1),
            ..AppModel::default()
        };
        let (commands, mut queued) = tokio::sync::mpsc::channel(8);
        let enter = Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        model.palette_open = true;
        model.palette = "memory save Mixed.Case preference 7".to_owned();
        handle_input(&mut model, &enter, &commands);
        assert!(model.memory_draft.is_some());
        assert!(queued.try_recv().is_err());
        model.composer = "retained note\n!goal {\"action\":\"create\"}".to_owned();
        handle_input(&mut model, &enter, &commands);
        let sent = queued.try_recv().expect("typed memory send");
        let UiCommand::ForConnection { command, .. } = &sent else {
            panic!("connection envelope")
        };
        let UiCommand::InvokeMemory {
            command,
            idempotency_key,
            ..
        } = command.as_ref()
        else {
            panic!("memory command")
        };
        let envelope: serde_json::Value = serde_json::from_str(
            command
                .message()
                .strip_prefix("!tool ")
                .expect("direct prefix"),
        )
        .expect("JSON");
        assert_eq!(envelope["arguments"]["id"], "Mixed.Case");
        assert_eq!(envelope["arguments"]["expectedRevision"], 7);
        assert_eq!(
            envelope["arguments"]["content"],
            "retained note\n!goal {\"action\":\"create\"}"
        );
        assert_eq!(command.message().lines().count(), 1);
        assert!(!format!("{sent:?}").contains("retained note"));
        apply_worker_event(
            &mut model,
            WorkerEvent::SendNotSent {
                idempotency_key: idempotency_key.clone(),
                reason: "unsupported".to_owned(),
            },
        );
        assert!(
            !model
                .pending_message
                .as_ref()
                .expect("pending")
                .may_have_been_sent
        );
        model.palette_open = true;
        model.palette = "retry-send".to_owned();
        handle_input(&mut model, &enter, &commands);
        assert_eq!(queued.try_recv().expect("same typed retry"), sent);
        apply_worker_event(
            &mut model,
            WorkerEvent::SendUnconfirmed {
                idempotency_key: idempotency_key.clone(),
            },
        );
        apply_worker_event(
            &mut model,
            WorkerEvent::SendNotSent {
                idempotency_key: idempotency_key.clone(),
                reason: "disabled".to_owned(),
            },
        );
        assert!(
            model
                .pending_message
                .as_ref()
                .expect("pending")
                .may_have_been_sent
        );
        model.palette_open = true;
        model.palette = "discard-send".to_owned();
        handle_input(&mut model, &enter, &commands);
        assert!(model.pending_message.is_some());
        assert!(queued.try_recv().is_err());
    }

    #[test]
    fn native_message_input_preserves_draft_key_and_exact_run_cancellation() {
        let mut model = crate::model::AppModel {
            connection_id: Some(1),
            ..crate::model::AppModel::default()
        };
        let (commands, mut queued) = tokio::sync::mpsc::channel(8);
        let key = |code| {
            crossterm::event::Event::Key(crossterm::event::KeyEvent::new(
                code,
                crossterm::event::KeyModifiers::NONE,
            ))
        };
        crate::handle_input(
            &mut model,
            &key(crossterm::event::KeyCode::Char('c')),
            &commands,
        );
        assert!(model.composer_open);
        let session = model.selected_session().expect("draft session").id.clone();
        model.composer = "retained user input".to_owned();
        crate::apply_worker_event(
            &mut model,
            crate::gateway::WorkerEvent::Sessions(Vec::new()),
        );
        assert_eq!(
            model.selected_session().expect("retained draft").id,
            session
        );
        assert_eq!(model.composer, "retained user input");
        crate::handle_input(
            &mut model,
            &key(crossterm::event::KeyCode::Enter),
            &commands,
        );
        let sent = queued.try_recv().expect("one send");
        let UiCommand::ForConnection {
            connection_id: 1,
            command,
        } = &sent
        else {
            panic!("observed connection envelope");
        };
        let crate::gateway::UiCommand::SendMessage {
            session_id,
            text,
            idempotency_key,
        } = command.as_ref()
        else {
            panic!("send command");
        };
        assert_eq!(session_id, &session);
        assert_eq!(text, "retained user input");
        assert!(model.pending_message.is_some());
        crate::apply_worker_event(
            &mut model,
            crate::gateway::WorkerEvent::SendUnconfirmed {
                idempotency_key: idempotency_key.clone(),
            },
        );
        model.palette_open = true;
        model.palette = "retry-send".to_owned();
        crate::handle_input(
            &mut model,
            &key(crossterm::event::KeyCode::Enter),
            &commands,
        );
        assert_eq!(
            queued.try_recv().expect("explicit original-key retry"),
            sent
        );
        let run_id = "a".repeat(64);
        crate::apply_worker_event(
            &mut model,
            crate::gateway::WorkerEvent::Accepted {
                session_id: session.clone(),
                run_id: run_id.clone(),
                idempotency_key: idempotency_key.clone(),
            },
        );
        assert!(model.pending_message.is_none());
        assert_eq!(model.transcript.len(), 1);
        crate::handle_input(
            &mut model,
            &key(crossterm::event::KeyCode::Char('x')),
            &commands,
        );
        assert_eq!(
            queued.try_recv().expect("exact cancellation"),
            crate::gateway::UiCommand::AbortRun {
                session_id: session.clone(),
                run_id: run_id.clone()
            }
            .for_connection(1)
        );
        crate::apply_worker_event(
            &mut model,
            crate::gateway::WorkerEvent::NativeRun {
                session_id: session.clone(),
                run_id: run_id.clone(),
                state: crate::model::RunState::Completed,
                turn: Some(2),
                text: Some("complete answer".to_owned()),
                revision: 4,
                provider_accounting: None,
            },
        );
        crate::apply_worker_event(
            &mut model,
            crate::gateway::WorkerEvent::NativeRun {
                session_id: session.clone(),
                run_id: "b".repeat(64),
                state: crate::model::RunState::Running,
                turn: Some(1),
                text: None,
                revision: 9,
                provider_accounting: None,
            },
        );
        crate::apply_worker_event(
            &mut model,
            crate::gateway::WorkerEvent::NativeRun {
                session_id: session.clone(),
                run_id: run_id.clone(),
                state: crate::model::RunState::Running,
                turn: Some(2),
                text: None,
                revision: 2,
                provider_accounting: None,
            },
        );
        assert_eq!(model.active_run, Some((session, run_id.clone())));
        assert_eq!(
            model.selected_session().expect("selected session").state,
            crate::model::RunState::Completed
        );
        assert_eq!(model.pending_acks, [(run_id, 4)]);
        assert!(
            queued.try_recv().is_err(),
            "ACK cannot be queued before the render pass"
        );
    }

    #[test]
    fn accounting_is_current_run_scoped_and_cannot_acknowledge_text() {
        use claw_protocol::native_accounting::{AccountingSource, ProviderAccounting};
        let accounting = ProviderAccounting::parse(&serde_json::json!({
            "available":true,"recordedRounds":1,"completeCounterRounds":1,
            "partialCounterRounds":0,"unreportedRounds":0,"allPrimaryCountersReported":true,
            "observedTokens":{"inputTokens":0,"outputTokens":0,"totalTokens":0,"cachedInputTokens":0,"reasoningTokens":0},
            "aggregationOverflow":false,"costCalculated":false,"billingReconciled":false,
            "recordSource":"provider_journal","journalRevision":2,"journalClosed":false,
            "attemptsMayBeUnsent":true,
        })).expect("valid accounting");
        let mut model = AppModel {
            sessions: vec![
                crate::model::SessionSummary {
                    id: "owned".to_owned(),
                    ..crate::model::SessionSummary::default()
                },
                crate::model::SessionSummary {
                    id: "other".to_owned(),
                    ..crate::model::SessionSummary::default()
                },
            ],
            ..AppModel::default()
        };
        let event = |session: &str, run: &str, turn, revision, provider_accounting| {
            WorkerEvent::NativeRun {
                session_id: session.to_owned(),
                run_id: run.to_owned(),
                turn: Some(turn),
                revision,
                state: crate::model::RunState::OutcomeUnknown,
                text: None,
                provider_accounting,
            }
        };
        apply_worker_event(
            &mut model,
            event("owned", "current", 2, 4, accounting.clone()),
        );
        assert_eq!(model.provider_accounting, accounting);
        assert_eq!(
            model.provider_accounting.as_ref().expect("present").source,
            AccountingSource::ProviderJournal {
                revision: 2,
                closed: false
            }
        );
        assert!(model.transcript.is_empty() && model.pending_acks.is_empty());
        apply_worker_event(&mut model, event("owned", "current", 2, 3, None));
        apply_worker_event(&mut model, event("owned", "old", 1, 8, None));
        apply_worker_event(&mut model, event("other", "different", 9, 8, None));
        assert_eq!(model.provider_accounting, accounting);
        assert_eq!(
            model.selected_session().expect("selected").state,
            crate::model::RunState::OutcomeUnknown
        );
        apply_worker_event(&mut model, event("owned", "new", 3, 1, None));
        assert!(model.provider_accounting.is_none());
        apply_worker_event(&mut model, event("owned", "new", 3, 2, accounting));
        model.select_next();
        assert!(model.provider_accounting.is_none() && model.active_run.is_none());
        assert!(model.pending_acks.is_empty());
    }

    #[test]
    fn native_tui_profile_option_is_explicit_bounded_and_not_repeatable() {
        let base = [
            "gta-claw-tui",
            "--gateway",
            "ws://127.0.0.1:18789",
            "--device-profile",
        ];
        let valid = crate::Options::parse(
            base.into_iter()
                .chain(["work"])
                .map(std::ffi::OsString::from),
        )
        .expect("explicit native profile");
        assert_eq!(valid.device_profile.as_deref(), Some("work"));
        for alias in ["", "../private", "with space"] {
            assert!(
                crate::Options::parse(
                    base.into_iter()
                        .chain([alias])
                        .map(std::ffi::OsString::from)
                )
                .is_err()
            );
        }
        assert!(
            crate::Options::parse(
                base.into_iter()
                    .chain(["work", "--device-profile", "other"])
                    .map(std::ffi::OsString::from)
            )
            .is_err()
        );
    }

    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

    use super::{
        MAX_PALETTE_BYTES, MAX_SESSIONS, MAX_TRANSCRIPT, Screen, UiCommand, WorkerEvent,
        apply_worker_event, handle_input,
    };
    use crate::model::{AppModel, Prompt, SessionSummary, TranscriptEntry};

    fn key(code: KeyCode) -> Event {
        Event::Key(KeyEvent::new(code, KeyModifiers::empty()))
    }

    #[test]
    fn command_palette_input_is_bounded() {
        let (commands, _receiver) = tokio::sync::mpsc::channel(1);
        let mut model = AppModel {
            palette_open: true,
            ..AppModel::default()
        };
        for _ in 0..MAX_PALETTE_BYTES + 20 {
            assert!(!handle_input(
                &mut model,
                &key(KeyCode::Char('x')),
                &commands
            ));
        }
        assert_eq!(model.palette.len(), MAX_PALETTE_BYTES);
        assert_eq!(
            model.notice.as_deref(),
            Some("Command limit reached (128 bytes)")
        );
    }

    #[test]
    fn approval_requires_full_review_and_is_not_replaced_by_another_prompt() {
        let (commands, mut receiver) = tokio::sync::mpsc::channel(4);
        let text = format!("{}\nfinal-parameter", "bounded line\n".repeat(40));
        let mut model = AppModel {
            connection_id: Some(1),
            viewport: (60, 16),
            ..AppModel::default()
        };
        apply_worker_event(
            &mut model,
            WorkerEvent::Prompt(Prompt::Approval {
                id: "first".to_owned(),
                text,
                preview_fingerprint: Some("a".repeat(64)),
            }),
        );
        apply_worker_event(
            &mut model,
            WorkerEvent::Prompt(Prompt::Approval {
                id: "second".to_owned(),
                text: "replacement".to_owned(),
                preview_fingerprint: Some("b".repeat(64)),
            }),
        );
        assert!(matches!(&model.prompt, Some(Prompt::Approval { id, .. }) if id == "first"));
        let first = crate::render::render(&model, 60, 16, true).text();
        assert!(!first.contains("final-parameter"));
        handle_input(&mut model, &key(KeyCode::Char('y')), &commands);
        assert!(
            receiver.try_recv().is_err(),
            "unseen parameters must not be approved"
        );
        for _ in 0..8 {
            handle_input(&mut model, &key(KeyCode::PageDown), &commands);
        }
        let last = crate::render::render(&model, 60, 16, true).text();
        assert!(last.contains("final-parameter"));
        handle_input(&mut model, &key(KeyCode::Char('y')), &commands);
        let UiCommand::ForConnection {
            connection_id: 1,
            command,
        } = receiver.try_recv().expect("bound approval")
        else {
            panic!("approval lacks observed connection");
        };
        assert!(
            matches!(*command, UiCommand::ResolveApproval { id, preview_fingerprint, .. } if id == "first" && preview_fingerprint == "a".repeat(64))
        );
        assert!(model.prompt.is_none());
    }

    #[test]
    fn a_busy_gateway_does_not_consume_an_approval() {
        let (commands, _receiver) = tokio::sync::mpsc::channel(1);
        commands.try_send(UiCommand::Refresh).expect("fill queue");
        let mut model = AppModel {
            connection_id: Some(1),
            prompt: Some(Prompt::Approval {
                id: "approval-1".to_owned(),
                text: "Run tests?".to_owned(),
                preview_fingerprint: Some("a".repeat(64)),
            }),
            viewport: (100, 30),
            ..AppModel::default()
        };
        handle_input(&mut model, &key(KeyCode::Char('y')), &commands);
        assert!(matches!(model.prompt, Some(Prompt::Approval { .. })));
        assert_eq!(
            model.notice.as_deref(),
            Some("Gateway is busy; wait and try again")
        );
    }

    #[test]
    fn cycling_to_a_data_screen_requests_its_content() {
        let (commands, mut receiver) = tokio::sync::mpsc::channel(1);
        let mut model = AppModel {
            screen: Screen::Runs,
            sessions: vec![SessionSummary {
                id: "session-1".to_owned(),
                ..SessionSummary::default()
            }],
            ..AppModel::default()
        };
        handle_input(&mut model, &key(KeyCode::Tab), &commands);
        assert_eq!(model.screen, Screen::Diff);
        assert_eq!(
            receiver.try_recv().expect("diff request"),
            UiCommand::LoadDiff("session-1".to_owned())
        );
    }

    #[test]
    fn gateway_collections_and_event_text_are_bounded() {
        let mut model = AppModel::default();
        apply_worker_event(
            &mut model,
            WorkerEvent::Sessions(
                (0..MAX_SESSIONS + 5)
                    .map(|index| SessionSummary {
                        id: index.to_string(),
                        ..SessionSummary::default()
                    })
                    .collect(),
            ),
        );
        assert_eq!(model.sessions.len(), MAX_SESSIONS);

        for index in 0..=MAX_TRANSCRIPT {
            apply_worker_event(
                &mut model,
                WorkerEvent::Message {
                    session_id: "0".to_owned(),
                    message: TranscriptEntry {
                        role: "assistant".to_owned(),
                        text: if index == MAX_TRANSCRIPT {
                            "x".repeat(20_000)
                        } else {
                            index.to_string()
                        },
                    },
                },
            );
        }
        assert_eq!(model.transcript.len(), MAX_TRANSCRIPT);
        assert_eq!(model.transcript.front().expect("oldest retained").text, "1");
        assert!(model.transcript.back().expect("newest retained").text.len() <= 16 * 1024);
    }
}

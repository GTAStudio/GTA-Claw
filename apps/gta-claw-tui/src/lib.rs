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
            .finish()
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
                let grid = render::render(&model, width, height, no_color);
                render::flush_changes(&mut stdout, painted.as_ref(), &grid, no_color)?;
                painted = Some(grid);
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
    let Event::Key(key) = event else {
        return false;
    };
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return true;
    }
    if model.palette_open {
        return handle_palette(model, key, commands);
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
            match command.trim().to_ascii_lowercase().as_str() {
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
            load_screen(model, commands);
        }
        _ => {}
    }
    false
}

fn resolve_prompt(model: &mut AppModel, commands: &mpsc::Sender<UiCommand>, approved: bool) {
    if let Some(Prompt::Approval { id, .. }) = model.prompt.as_ref() {
        let command = UiCommand::ResolveApproval {
            id: id.clone(),
            approved,
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
        WorkerEvent::Connection(connection) => {
            model.connection = bounded_owned(connection, MAX_NOTICE_BYTES);
        }
        WorkerEvent::Sessions(sessions) => {
            model.sessions = sessions.into_iter().take(MAX_SESSIONS).collect();
            model.selected = model.selected.min(model.sessions.len().saturating_sub(1));
            model.scroll = model.scroll.min(model.sessions.len().saturating_sub(1));
            model.notice = None;
        }
        WorkerEvent::Message(mut message) => {
            message.role = bounded_owned(message.role, 128);
            message.text = bounded_owned(message.text, MAX_EVENT_TEXT_BYTES);
            model.transcript.push_back(message);
            while model.transcript.len() > MAX_TRANSCRIPT {
                model.transcript.pop_front();
            }
        }
        WorkerEvent::Tool(mut tool) => {
            tool.name = bounded_owned(tool.name, 128);
            tool.status = bounded_owned(tool.status, 128);
            tool.summary = bounded_owned(tool.summary, MAX_EVENT_TEXT_BYTES);
            model.tools.push_back(tool);
            while model.tools.len() > MAX_TOOLS {
                model.tools.pop_front();
            }
        }
        WorkerEvent::Prompt(prompt) => {
            model.prompt = Some(match prompt {
                Prompt::Approval { id, text } => Prompt::Approval {
                    id: bounded_owned(id, 1_024),
                    text: bounded_owned(text, MAX_EVENT_TEXT_BYTES),
                },
                Prompt::Question { id, text } => Prompt::Question {
                    id: bounded_owned(id, 1_024),
                    text: bounded_owned(text, MAX_EVENT_TEXT_BYTES),
                },
            });
            model.answer.clear();
        }
        WorkerEvent::Diff(diff) => {
            model.diff = diff
                .into_iter()
                .take(MAX_DIFF_LINES)
                .map(|line| bounded_owned(line, MAX_EVENT_TEXT_BYTES))
                .collect();
            model.scroll = 0;
        }
        WorkerEvent::Artifacts(artifacts) => {
            model.artifacts = artifacts
                .into_iter()
                .take(MAX_ARTIFACTS)
                .map(|name| bounded_owned(name, 1_024))
                .collect();
            model.artifact_content.clear();
            model.scroll = 0;
        }
        WorkerEvent::ArtifactContent(content) => {
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
    fn a_busy_gateway_does_not_consume_an_approval() {
        let (commands, _receiver) = tokio::sync::mpsc::channel(1);
        commands.try_send(UiCommand::Refresh).expect("fill queue");
        let mut model = AppModel {
            prompt: Some(Prompt::Approval {
                id: "approval-1".to_owned(),
                text: "Run tests?".to_owned(),
            }),
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
                WorkerEvent::Message(TranscriptEntry {
                    role: "assistant".to_owned(),
                    text: if index == MAX_TRANSCRIPT {
                        "x".repeat(20_000)
                    } else {
                        index.to_string()
                    },
                }),
            );
        }
        assert_eq!(model.transcript.len(), MAX_TRANSCRIPT);
        assert_eq!(model.transcript.front().expect("oldest retained").text, "1");
        assert!(model.transcript.back().expect("newest retained").text.len() <= 16 * 1024);
    }
}

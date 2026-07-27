//! Headless-first terminal application for GTA Claw.

use std::ffi::OsString;
use std::fmt::{self, Formatter};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal as crossterm_terminal;
use tokio::sync::mpsc;
use url::Url;

/// Asynchronous Gateway adapter and bounded UI channels.
pub mod gateway;
/// TUI state and the complete run-state vocabulary.
pub mod model;
/// Deterministic cell-buffer renderer and Crossterm flusher.
pub mod render;
/// Panic-safe terminal lifecycle and background input pump.
pub mod terminal;

use gateway::{GatewayOptions, UiCommand, WorkerEvent, endpoint_label, spawn_gateway_worker};
use model::{AppModel, Prompt, Screen};
use terminal::{CrosstermControl, InputThread, TerminalSession};

/// Endpoint used when `--gateway` and `GTA_CLAW_GATEWAY_URL` are both absent.
const DEFAULT_GATEWAY_URL: &str = "ws://127.0.0.1:18789";

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
        })
    }
}

/// Runs the TUI or its non-TTY snapshot fallback.
///
/// # Errors
///
/// Returns the message to show the user when the terminal cannot be entered,
/// restored, or written to. Gateway failures are not errors here: they are
/// surfaced in the interface as a notice so the session stays usable.
pub async fn run(options: Options) -> Result<(), String> {
    let worker_options = GatewayOptions {
        url: options.gateway_url,
        token: options.token,
    };
    if options.plain || !terminal::is_interactive() {
        return run_plain(worker_options).await;
    }
    run_interactive(worker_options, options.no_color)
        .await
        .map_err(|error| error.to_string())
}

async fn run_plain(options: GatewayOptions) -> Result<(), String> {
    let endpoint = endpoint_label(&options.url);
    let (commands, mut events) = spawn_gateway_worker(options);
    let mut model = AppModel::default();
    let deadline = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            event = events.recv() => {
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
    let _ = commands.send(UiCommand::Shutdown).await;
    println!("{}", render_plain(&model));
    Ok(())
}

async fn run_interactive(options: GatewayOptions, no_color: bool) -> io::Result<()> {
    terminal::install_panic_hook();
    let control = Arc::new(CrosstermControl::default());
    let _terminal = TerminalSession::enter(control)?;
    let (_input_thread, mut inputs) = InputThread::spawn(64);
    let (commands, mut worker_events) = spawn_gateway_worker(options);
    let mut model = AppModel::default();
    let mut stdout = io::stdout();
    let mut redraw = true;
    let mut painted: Option<render::Grid> = None;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut signal = Box::pin(shutdown_signal());

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
                if handle_input(&mut model, input, &commands).await {
                    break;
                }
                redraw = true;
            }
            event = worker_events.recv() => {
                let Some(event) = event else {
                    break;
                };
                apply_worker_event(&mut model, event);
                redraw = true;
            }
            _ = tick.tick() => {}
            () = &mut signal => break,
        }
    }
    let _ = commands.try_send(UiCommand::Shutdown);
    Ok(())
}

async fn handle_input(
    model: &mut AppModel,
    event: Event,
    commands: &mpsc::Sender<UiCommand>,
) -> bool {
    let Event::Key(key) = event else {
        return false;
    };
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return true;
    }
    if model.palette_open {
        return handle_palette(model, key, commands).await;
    }
    if matches!(model.prompt, Some(Prompt::Question { .. })) {
        match key.code {
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                model.answer.push(character);
                return false;
            }
            KeyCode::Backspace => {
                model.answer.pop();
                return false;
            }
            KeyCode::Enter => {
                if let (Some(Prompt::Question { id, .. }), Some(session)) =
                    (model.prompt.take(), model.selected_session().cloned())
                {
                    let text = std::mem::take(&mut model.answer);
                    let _ = commands
                        .send(UiCommand::Answer {
                            session_id: session.id,
                            question_id: id,
                            text,
                        })
                        .await;
                }
                return false;
            }
            _ => {}
        }
    }
    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Tab => model.next_screen(),
        KeyCode::BackTab => previous_screen(model),
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
                let _ = commands.send(UiCommand::SelectSession(session.id)).await;
            }
        }
        KeyCode::Char('y') => resolve_prompt(model, commands, true).await,
        KeyCode::Char('n') => resolve_prompt(model, commands, false).await,
        KeyCode::Char('r') => {
            let _ = commands.send(UiCommand::Refresh).await;
            model.notice = Some("Refreshing sessions...".to_owned());
        }
        KeyCode::Char(':') => model.palette_open = true,
        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            model.palette_open = true;
        }
        KeyCode::Char('?') => model.screen = Screen::Help,
        KeyCode::Char(character @ '1'..='6') => {
            let index = usize::from(character as u8 - b'1');
            model.screen = Screen::ALL[index];
            load_screen(model, commands).await;
        }
        _ => {}
    }
    false
}

async fn handle_palette(
    model: &mut AppModel,
    key: KeyEvent,
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
            model.palette.push(character);
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
                    let _ = commands.send(UiCommand::Refresh).await;
                }
                "quit" | "q" => return true,
                "" => {}
                unknown => model.notice = Some(format!("Unknown command: {unknown}")),
            }
            load_screen(model, commands).await;
        }
        _ => {}
    }
    false
}

async fn resolve_prompt(model: &mut AppModel, commands: &mpsc::Sender<UiCommand>, approved: bool) {
    if let Some(Prompt::Approval { id, .. }) = model.prompt.take() {
        let _ = commands
            .send(UiCommand::ResolveApproval { id, approved })
            .await;
    }
}

async fn load_screen(model: &AppModel, commands: &mpsc::Sender<UiCommand>) {
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
        let _ = commands.send(command).await;
    }
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
        WorkerEvent::Connection(connection) => model.connection = connection,
        WorkerEvent::Sessions(sessions) => {
            model.sessions = sessions;
            model.selected = model.selected.min(model.sessions.len().saturating_sub(1));
            model.notice = None;
        }
        WorkerEvent::Message(message) => {
            const MAX_TRANSCRIPT: usize = 2_000;
            model.transcript.push_back(message);
            while model.transcript.len() > MAX_TRANSCRIPT {
                model.transcript.pop_front();
            }
        }
        WorkerEvent::Tool(tool) => {
            const MAX_TOOLS: usize = 500;
            model.tools.push_back(tool);
            while model.tools.len() > MAX_TOOLS {
                model.tools.pop_front();
            }
        }
        WorkerEvent::Prompt(prompt) => model.prompt = Some(prompt),
        WorkerEvent::Diff(diff) => model.diff = diff,
        WorkerEvent::Artifacts(artifacts) => {
            model.artifacts = artifacts;
            model.artifact_content.clear();
        }
        WorkerEvent::ArtifactContent(content) => model.artifact_content = content,
        WorkerEvent::Notice(notice) => model.notice = Some(notice),
    }
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
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate =
        signal(SignalKind::terminate()).expect("install SIGTERM handler for terminal restoration");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
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
     \x20 --help, -h       print this text and exit 0\n\
     \n\
     Environment:\n\
     \x20 GTA_CLAW_GATEWAY_URL    default endpoint, overridden by --gateway\n\
     \x20 GTA_CLAW_GATEWAY_TOKEN  shared token. There is no token flag, so the\n\
     \x20                         secret never appears in argv. It is never echoed\n\
     \x20                         or printed back\n\
     \x20 NO_COLOR                any value turns off color\n\
     \n\
     Keys: Tab screens  arrows or j/k navigate  Enter open  y/n approve\n\
     \x20     r refresh  : or Ctrl-P palette  1..6 jump  ? help  q quit\n\
     \n\
     Exit codes: 0 success, 2 usage, 1 terminal or runtime failure."
}

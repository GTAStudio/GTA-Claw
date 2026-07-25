//! Headless-first terminal application for GTA Claw.

use std::ffi::OsString;
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

use gateway::{GatewayOptions, UiCommand, WorkerEvent, spawn_gateway_worker};
use model::{AppModel, Prompt, Screen, TranscriptEntry};
use terminal::{CrosstermControl, InputThread, TerminalSession};

/// Process options accepted by the TUI executable.
#[derive(Clone, Debug)]
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

impl Options {
    /// Parses OS-native arguments without assuming they contain UTF-8.
    pub fn parse<I>(arguments: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut gateway = std::env::var_os("GTA_CLAW_GATEWAY_URL")
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| "ws://127.0.0.1:18789".to_owned());
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
        Ok(Self {
            gateway_url,
            token,
            no_color,
            plain,
        })
    }
}

/// Runs the TUI or its non-TTY snapshot fallback.
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
                model.notice = Some("Gateway snapshot timed out".to_owned());
                break;
            }
        }
    }
    let _ = commands.send(UiCommand::Shutdown).await;
    println!("{}", render_plain(&model));
    Ok(())
}

async fn run_interactive(options: GatewayOptions, no_color: bool) -> io::Result<()> {
    let control = Arc::new(CrosstermControl::default());
    let _terminal = TerminalSession::enter(control)?;
    let (_input_thread, mut inputs) = InputThread::spawn(64);
    let (commands, mut worker_events) = spawn_gateway_worker(options);
    let mut model = AppModel::default();
    let mut stdout = io::stdout();
    let mut redraw = true;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut signal = Box::pin(shutdown_signal());

    loop {
        if redraw {
            let (width, height) = crossterm_terminal::size().unwrap_or((100, 30));
            let grid = render::render(&model, width, height, no_color);
            render::flush(&mut stdout, &grid, no_color)?;
            redraw = false;
        }
        tokio::select! {
            input = inputs.recv() => {
                let Some(input) = input else {
                    break;
                };
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
                model.scroll = model.scroll.saturating_sub(1);
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if model.screen == Screen::Sessions {
                model.select_next();
            } else {
                model.scroll = model.scroll.saturating_add(1);
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
            model.transcript.push_back(TranscriptEntry {
                role: message.role,
                text: message.text,
            });
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

fn help_text() -> &'static str {
    "Usage: gta-claw-tui [--gateway ws://HOST:PORT] [--no-color] [--plain]\nSet GTA_CLAW_GATEWAY_TOKEN for authenticated Gateways."
}

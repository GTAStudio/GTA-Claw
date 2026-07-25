use std::io::{self, Write};

use crossterm::cursor::MoveTo;
use crossterm::queue;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};

use crate::model::{AppModel, Prompt, RunState, Screen};

/// Styling attached to one terminal cell.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CellStyle {
    /// Optional ANSI 256-color foreground.
    pub foreground: Option<u8>,
}

/// One deterministic terminal cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cell {
    /// Displayed scalar value.
    pub symbol: char,
    /// Cell styling.
    pub style: CellStyle,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            symbol: ' ',
            style: CellStyle::default(),
        }
    }
}

/// A pure in-memory terminal backend used by production rendering and tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grid {
    width: u16,
    height: u16,
    cells: Vec<Cell>,
}

impl Grid {
    /// Creates a blank bounded cell grid.
    #[must_use]
    pub fn new(width: u16, height: u16) -> Self {
        Self {
            width,
            height,
            cells: vec![Cell::default(); usize::from(width) * usize::from(height)],
        }
    }

    /// Returns the grid width.
    #[must_use]
    pub const fn width(&self) -> u16 {
        self.width
    }

    /// Returns the grid height.
    #[must_use]
    pub const fn height(&self) -> u16 {
        self.height
    }

    /// Reads one cell.
    #[must_use]
    pub fn cell(&self, x: u16, y: u16) -> Option<Cell> {
        self.index(x, y).map(|index| self.cells[index])
    }

    /// Returns a row as plain text, preserving deterministic cell positions.
    #[must_use]
    pub fn line(&self, y: u16) -> String {
        if y >= self.height {
            return String::new();
        }
        (0..self.width)
            .filter_map(|x| self.cell(x, y))
            .map(|cell| cell.symbol)
            .collect()
    }

    /// Returns all rows as plain text.
    #[must_use]
    pub fn text(&self) -> String {
        (0..self.height)
            .map(|row| self.line(row))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub(crate) fn put(&mut self, x: u16, y: u16, symbol: char, style: CellStyle) {
        if let Some(index) = self.index(x, y) {
            self.cells[index] = Cell { symbol, style };
        }
    }

    pub(crate) fn write(&mut self, x: u16, y: u16, text: &str, style: CellStyle) {
        let available = self.width.saturating_sub(x);
        for (offset, symbol) in sanitize(text)
            .chars()
            .take(usize::from(available))
            .enumerate()
        {
            self.put(
                x + u16::try_from(offset).unwrap_or(u16::MAX),
                y,
                symbol,
                style,
            );
        }
    }

    fn index(&self, x: u16, y: u16) -> Option<usize> {
        if x >= self.width || y >= self.height {
            return None;
        }
        Some(usize::from(y) * usize::from(self.width) + usize::from(x))
    }
}

/// Renders the complete application into a deterministic grid.
#[must_use]
pub fn render(model: &AppModel, width: u16, height: u16, no_color: bool) -> Grid {
    let mut grid = Grid::new(width.max(20), height.max(8));
    let normal = CellStyle::default();
    let accent = colored(45, no_color);
    grid.write(0, 0, " GTA Claw ", accent);
    grid.write(11, 0, &model.connection, normal);
    draw_rule(&mut grid, 1);
    let tabs = Screen::ALL
        .iter()
        .map(|screen| {
            if *screen == model.screen {
                format!("[{}]", screen.title())
            } else {
                screen.title().to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("  ");
    grid.write(1, 2, &tabs, accent);
    draw_rule(&mut grid, 3);

    match model.screen {
        Screen::Sessions => draw_sessions(&mut grid, model, no_color),
        Screen::Workspace => draw_workspace(&mut grid, model, no_color),
        Screen::Runs => draw_runs(&mut grid, model, no_color),
        Screen::Diff => draw_diff(&mut grid, model, no_color),
        Screen::Artifacts => draw_artifacts(&mut grid, model),
        Screen::Help => draw_help(&mut grid),
    }
    draw_footer(&mut grid, model, no_color);
    if model.palette_open {
        draw_palette(&mut grid, model, no_color);
    }
    grid
}

/// Flushes a grid to a Crossterm output without blocking on network work.
pub fn flush<W: Write>(writer: &mut W, grid: &Grid, no_color: bool) -> io::Result<()> {
    for y in 0..grid.height() {
        queue!(writer, MoveTo(0, y))?;
        let mut active = None;
        for x in 0..grid.width() {
            let cell = grid.cell(x, y).unwrap_or_default();
            if !no_color && cell.style.foreground != active {
                match cell.style.foreground {
                    Some(value) => queue!(writer, SetForegroundColor(Color::AnsiValue(value)))?,
                    None => queue!(writer, ResetColor)?,
                }
                active = cell.style.foreground;
            }
            queue!(writer, Print(cell.symbol))?;
        }
        queue!(writer, ResetColor)?;
    }
    writer.flush()
}

fn draw_sessions(grid: &mut Grid, model: &AppModel, no_color: bool) {
    grid.write(2, 4, "SESSION", colored(45, no_color));
    grid.write(28, 4, "STATE", colored(45, no_color));
    grid.write(55, 4, "WORKSPACE", colored(45, no_color));
    for (row, session) in model.sessions.iter().skip(model.scroll).enumerate() {
        let y = 5 + u16::try_from(row).unwrap_or(u16::MAX);
        if y >= grid.height().saturating_sub(2) {
            break;
        }
        let selector = if row + model.scroll == model.selected {
            ">"
        } else {
            " "
        };
        grid.write(0, y, selector, colored(231, no_color));
        grid.write(2, y, &session.title, CellStyle::default());
        draw_state(grid, 28, y, session.state, no_color);
        grid.write(55, y, &session.workspace, CellStyle::default());
    }
    if model.sessions.is_empty() {
        grid.write(
            2,
            6,
            "No sessions returned by the Gateway. Press r to refresh.",
            CellStyle::default(),
        );
    }
}

fn draw_workspace(grid: &mut Grid, model: &AppModel, no_color: bool) {
    let split = grid.width().saturating_mul(2) / 3;
    let title = model
        .selected_session()
        .map_or("No session selected", |session| session.title.as_str());
    grid.write(
        1,
        4,
        &format!("Transcript - {title}"),
        colored(45, no_color),
    );
    grid.write(split + 1, 4, "Tool activity", colored(45, no_color));
    for y in 4..grid.height().saturating_sub(2) {
        grid.put(split, y, '|', colored(238, no_color));
    }
    let body_height = usize::from(grid.height().saturating_sub(8));
    let start = model
        .transcript
        .len()
        .saturating_sub(body_height + model.scroll);
    for (row, entry) in model
        .transcript
        .iter()
        .skip(start)
        .take(body_height)
        .enumerate()
    {
        let y = 6 + u16::try_from(row).unwrap_or(u16::MAX);
        grid.write(
            1,
            y,
            &format!("{}: {}", entry.role, entry.text),
            CellStyle::default(),
        );
    }
    for (row, tool) in model.tools.iter().rev().take(body_height).rev().enumerate() {
        let y = 6 + u16::try_from(row).unwrap_or(u16::MAX);
        grid.write(
            split + 1,
            y,
            &format!("{} [{}] {}", tool.name, tool.status, tool.summary),
            CellStyle::default(),
        );
    }
    if let Some(prompt) = &model.prompt {
        let (marker, text) = match prompt {
            Prompt::Approval { text, .. } => ("APPROVAL y/n", text),
            Prompt::Question { text, .. } => ("ANSWER Enter", text),
        };
        let y = grid.height().saturating_sub(4);
        grid.write(1, y, marker, colored(220, no_color));
        grid.write(18, y, text, CellStyle::default());
        if matches!(prompt, Prompt::Question { .. }) {
            grid.write(
                1,
                y + 1,
                &format!("> {}", model.answer),
                colored(231, no_color),
            );
        }
    }
}

fn draw_runs(grid: &mut Grid, model: &AppModel, no_color: bool) {
    grid.write(2, 4, "Run monitor", colored(45, no_color));
    for (row, session) in model.sessions.iter().enumerate() {
        let y = 6 + u16::try_from(row).unwrap_or(u16::MAX);
        if y >= grid.height().saturating_sub(2) {
            break;
        }
        grid.write(2, y, &session.title, CellStyle::default());
        draw_state(grid, 30, y, session.state, no_color);
        let progress = session
            .progress
            .map_or_else(|| "--".to_owned(), |value| format!("{value:>3}%"));
        grid.write(61, y, &progress, CellStyle::default());
    }
    if model.sessions.is_empty() {
        for (row, state) in RunState::ALL.iter().enumerate() {
            let y = 6 + u16::try_from(row).unwrap_or(u16::MAX);
            if y >= grid.height().saturating_sub(2) {
                break;
            }
            draw_state(grid, 2, y, *state, no_color);
        }
    }
}

fn draw_diff(grid: &mut Grid, model: &AppModel, no_color: bool) {
    grid.write(2, 4, "Workspace diff", colored(45, no_color));
    for (row, line) in model.diff.iter().skip(model.scroll).enumerate() {
        let y = 6 + u16::try_from(row).unwrap_or(u16::MAX);
        if y >= grid.height().saturating_sub(2) {
            break;
        }
        let style = if line.starts_with('+') && !line.starts_with("+++") {
            colored(42, no_color)
        } else if line.starts_with('-') && !line.starts_with("---") {
            colored(196, no_color)
        } else if line.starts_with("@@") {
            colored(45, no_color)
        } else {
            CellStyle::default()
        };
        grid.write(1, y, line, style);
    }
    if model.diff.is_empty() {
        grid.write(
            2,
            6,
            "No diff for the selected session.",
            CellStyle::default(),
        );
    }
}

fn draw_artifacts(grid: &mut Grid, model: &AppModel) {
    grid.write(2, 4, "Artifacts", CellStyle::default());
    for (row, artifact) in model.artifacts.iter().skip(model.scroll).enumerate() {
        let y = 6 + u16::try_from(row).unwrap_or(u16::MAX);
        if y >= grid.height().saturating_sub(2) {
            break;
        }
        grid.write(2, y, &format!("* {artifact}"), CellStyle::default());
    }
    if model.artifacts.is_empty() {
        grid.write(
            2,
            6,
            "No artifacts for the selected session.",
            CellStyle::default(),
        );
    }
}

fn draw_help(grid: &mut Grid) {
    const HELP: [&str; 10] = [
        "Tab / Shift-Tab  cycle screens",
        "Up/Down or j/k    select and scroll",
        "Enter             open session / submit answer",
        "y / n             approve / deny",
        "r                 refresh from Gateway",
        "Ctrl-P or :       command palette",
        "1..6              jump to a screen",
        "Esc               close palette",
        "?                 keyboard help",
        "q / Ctrl-C        quit safely",
    ];
    grid.write(2, 4, "Keyboard navigation", CellStyle::default());
    for (row, text) in HELP.iter().enumerate() {
        grid.write(
            2,
            6 + u16::try_from(row).unwrap_or(u16::MAX),
            text,
            CellStyle::default(),
        );
    }
}

fn draw_footer(grid: &mut Grid, model: &AppModel, no_color: bool) {
    let y = grid.height().saturating_sub(1);
    let text = model
        .notice
        .as_deref()
        .unwrap_or("Tab screens  arrows navigate  : commands  ? help  q quit");
    grid.write(0, y, text, colored(245, no_color));
}

fn draw_palette(grid: &mut Grid, model: &AppModel, no_color: bool) {
    let width = grid.width().saturating_sub(8).min(70);
    let x = (grid.width().saturating_sub(width)) / 2;
    let y = grid.height() / 3;
    for row in y..y.saturating_add(5).min(grid.height()) {
        for column in x..x.saturating_add(width).min(grid.width()) {
            grid.put(column, row, ' ', colored(236, no_color));
        }
    }
    grid.write(x + 2, y, "Command palette", colored(45, no_color));
    grid.write(
        x + 2,
        y + 2,
        &format!(":{}", model.palette),
        colored(231, no_color),
    );
    grid.write(
        x + 2,
        y + 3,
        "sessions | workspace | runs | diff | artifacts | refresh | quit",
        colored(245, no_color),
    );
}

fn draw_rule(grid: &mut Grid, y: u16) {
    for x in 0..grid.width() {
        grid.put(x, y, '-', CellStyle::default());
    }
}

fn draw_state(grid: &mut Grid, x: u16, y: u16, state: RunState, no_color: bool) {
    grid.write(
        x,
        y,
        &format!("[{} {}]", state.marker(), state.label()),
        colored(state.color(), no_color),
    );
}

const fn colored(value: u8, no_color: bool) -> CellStyle {
    CellStyle {
        foreground: if no_color { None } else { Some(value) },
    }
}

fn sanitize(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character == '\n' || character == '\r' || character == '\t' {
                ' '
            } else if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

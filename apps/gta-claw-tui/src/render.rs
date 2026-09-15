use std::io::{self, Write};

use crossterm::cursor::MoveTo;
use crossterm::queue;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use unicode_width::UnicodeWidthChar;

use crate::model::{AppModel, Prompt, RunState, Screen};

const MAX_GRID_WIDTH: u16 = 512;
const MAX_GRID_HEIGHT: u16 = 256;

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
    /// Occupied by the preceding double-width glyph; never printed independently.
    pub continuation: bool,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            symbol: ' ',
            style: CellStyle::default(),
            continuation: false,
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
        let width = width.clamp(1, MAX_GRID_WIDTH);
        let height = height.clamp(1, MAX_GRID_HEIGHT);
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
            .filter(|cell| !cell.continuation)
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
            self.cells[index] = Cell {
                symbol,
                style,
                continuation: false,
            };
        }
    }

    pub(crate) fn write(&mut self, x: u16, y: u16, text: &str, style: CellStyle) {
        let mut column = x;
        for symbol in text.chars().map(sanitize_character) {
            let width = u16::try_from(symbol.width().unwrap_or(1))
                .unwrap_or(1)
                .max(1);
            if column.saturating_add(width) > self.width {
                break;
            }
            self.put(column, y, symbol, style);
            if width == 2
                && let Some(index) = self.index(column + 1, y)
            {
                self.cells[index] = Cell {
                    symbol: ' ',
                    style,
                    continuation: true,
                };
            }
            column = column.saturating_add(width);
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
    let mut grid = Grid::new(width, height);
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
    if model.composer_open && model.prompt.is_none() {
        let row = grid.height().saturating_sub(5);
        for target in row..grid.height().saturating_sub(2) {
            for column in 0..grid.width() {
                grid.put(column, target, ' ', CellStyle::default());
            }
        }
        let title = model.memory_draft.as_ref().map_or_else(
            || "Message".to_owned(),
            |(_, draft)| format!("Memory {}", draft.action()),
        );
        grid.write(1, row, &title, accent);
        let columns = usize::from(grid.width().saturating_sub(4)).max(1);
        let mut used_columns = 0;
        let tail: Vec<char> = model
            .composer
            .chars()
            .rev()
            .map(|character| {
                if matches!(character, '\n' | '\r' | '\t') {
                    ' '
                } else {
                    character
                }
            })
            .take_while(|character| {
                used_columns += unicode_width::UnicodeWidthChar::width(*character).unwrap_or(1);
                used_columns <= columns
            })
            .collect();
        let visible: String = tail.into_iter().rev().collect();
        grid.write(1, row.saturating_add(1), &format!("> {visible}"), normal);
    }
    if matches!(
        &model.prompt,
        Some(Prompt::Approval {
            preview_fingerprint: Some(_),
            ..
        })
    ) {
        draw_approval(&mut grid, model, no_color);
    }
    if model.palette_open {
        draw_palette(&mut grid, model, no_color);
    }
    grid
}

fn approval_lines(text: &str, width: u16) -> Vec<String> {
    let columns = usize::from(width.saturating_sub(4).max(1));
    let mut rows = Vec::new();
    for line in text.split('\n') {
        let escaped: String = line
            .chars()
            .flat_map(|character| {
                if character.is_ascii() && !character.is_control() {
                    character.to_string()
                } else {
                    character.escape_unicode().to_string()
                }
                .chars()
                .collect::<Vec<_>>()
            })
            .collect();
        if escaped.is_empty() {
            rows.push(String::new());
        }
        for chunk in escaped.as_bytes().chunks(columns) {
            rows.push(String::from_utf8_lossy(chunk).into_owned());
        }
    }
    rows
}

pub(crate) fn approval_fully_visible(model: &AppModel, width: u16, height: u16) -> bool {
    let (width, height) = (width.min(MAX_GRID_WIDTH), height.min(MAX_GRID_HEIGHT));
    let Some(Prompt::Approval {
        text,
        preview_fingerprint: Some(_),
        ..
    }) = &model.prompt
    else {
        return false;
    };
    width >= 24
        && height >= 12
        && model
            .approval_scroll
            .saturating_add(usize::from(height.saturating_sub(9)))
            >= approval_lines(text, width).len()
}

fn draw_approval(grid: &mut Grid, model: &AppModel, no_color: bool) {
    let Some(Prompt::Approval { text, .. }) = &model.prompt else {
        return;
    };
    for row in 4..grid.height().saturating_sub(2) {
        for column in 0..grid.width() {
            grid.put(column, row, ' ', CellStyle::default());
        }
    }
    grid.write(2, 4, "EXECUTION APPROVAL", colored(220, no_color));
    let lines = approval_lines(text, grid.width());
    let visible = usize::from(grid.height().saturating_sub(9));
    let start = model
        .approval_scroll
        .min(lines.len().saturating_sub(visible));
    for (index, line) in lines.iter().skip(start).take(visible).enumerate() {
        grid.write(
            2,
            6 + u16::try_from(index).unwrap_or(u16::MAX),
            line,
            CellStyle::default(),
        );
    }
    let status = if approval_fully_visible(model, grid.width(), grid.height()) {
        "y Approve   n Deny"
    } else {
        "PageDown Review more   n Deny"
    };
    grid.write(
        2,
        grid.height().saturating_sub(3),
        status,
        colored(220, no_color),
    );
}

/// Flushes a complete grid to a Crossterm output without blocking on network work.
///
/// # Errors
///
/// Returns the first write error reported by `writer`, including the final
/// flush. A partially written frame is left on screen; the caller is expected to
/// treat the error as fatal and restore the terminal.
pub fn flush<W: Write>(writer: &mut W, grid: &Grid, no_color: bool) -> io::Result<()> {
    for y in 0..grid.height() {
        queue!(writer, MoveTo(0, y))?;
        let mut active = None;
        let mut cursor_known = true;
        for x in 0..grid.width() {
            let cell = grid.cell(x, y).unwrap_or_default();
            if cell.continuation {
                continue;
            }
            if !cursor_known {
                queue!(writer, MoveTo(x, y))?;
            }
            active = queue_style(writer, cell, active, no_color)?;
            queue!(writer, Print(cell.symbol))?;
            cursor_known = cell.symbol.is_ascii();
        }
        queue!(writer, ResetColor)?;
    }
    writer.flush()
}

/// Flushes only the cells that differ from the previously drawn grid.
///
/// A full-screen repaint of every cell on every keystroke is what makes a TUI
/// flicker and what makes it unusable over a slow link. When `previous` is
/// `None`, or when the terminal was resized so the two grids no longer describe
/// the same screen, this falls back to [`flush`].
///
/// # Errors
///
/// Returns the first write error reported by `writer`, including the final
/// flush.
pub fn flush_changes<W: Write>(
    writer: &mut W,
    previous: Option<&Grid>,
    grid: &Grid,
    no_color: bool,
) -> io::Result<()> {
    let Some(previous) = previous
        .filter(|previous| previous.width() == grid.width() && previous.height() == grid.height())
    else {
        return flush(writer, grid, no_color);
    };
    let mut active = None;
    let mut cursor = None;
    for y in 0..grid.height() {
        for x in 0..grid.width() {
            let cell = grid.cell(x, y).unwrap_or_default();
            if cell.continuation {
                continue;
            }
            if previous.cell(x, y) == Some(cell) {
                continue;
            }
            if cursor != Some((x, y)) {
                queue!(writer, MoveTo(x, y))?;
            }
            active = queue_style(writer, cell, active, no_color)?;
            queue!(writer, Print(cell.symbol))?;
            cursor = cell.symbol.is_ascii().then_some((x.saturating_add(1), y));
        }
    }
    if active.is_some() {
        queue!(writer, ResetColor)?;
    }
    writer.flush()
}

/// Emits a foreground change only when it differs from the active color and
/// returns the color now in effect.
fn queue_style<W: Write>(
    writer: &mut W,
    cell: Cell,
    active: Option<u8>,
    no_color: bool,
) -> io::Result<Option<u8>> {
    if no_color || cell.style.foreground == active {
        return Ok(active);
    }
    match cell.style.foreground {
        Some(value) => queue!(writer, SetForegroundColor(Color::AnsiValue(value)))?,
        None => queue!(writer, ResetColor)?,
    }
    Ok(cell.style.foreground)
}

fn draw_sessions(grid: &mut Grid, model: &AppModel, no_color: bool) {
    grid.write(2, 4, "SESSION", colored(45, no_color));
    grid.write(28, 4, "STATE", colored(45, no_color));
    grid.write(55, 4, "WORKSPACE", colored(45, no_color));
    let visible_rows = usize::from(grid.height().saturating_sub(7));
    let max_start = model.sessions.len().saturating_sub(visible_rows);
    let mut start = model.scroll.min(max_start);
    if model.selected < start {
        start = model.selected;
    } else if visible_rows > 0 && model.selected >= start.saturating_add(visible_rows) {
        start = model
            .selected
            .saturating_add(1)
            .saturating_sub(visible_rows)
            .min(max_start);
    }
    for (row, session) in model.sessions.iter().skip(start).enumerate() {
        let y = 5_u16.saturating_add(u16::try_from(row).unwrap_or(u16::MAX));
        if y >= grid.height().saturating_sub(2) {
            break;
        }
        let selector = if row + start == model.selected {
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
    let transcript_columns = usize::from(split.saturating_sub(2)).max(1);
    let title = model
        .selected_session()
        .map_or("No session selected", |session| session.title.as_str());
    grid.write(
        1,
        4,
        &wrap_columns(&format!("Transcript - {title}"), transcript_columns)
            .into_iter()
            .next()
            .unwrap_or_default(),
        colored(45, no_color),
    );
    grid.write(
        split.saturating_add(1),
        4,
        "Tool activity",
        colored(45, no_color),
    );
    for y in 4..grid.height().saturating_sub(2) {
        grid.put(split, y, '|', colored(238, no_color));
    }
    let occupied = if model.composer_open || model.prompt.is_some() {
        3
    } else {
        0
    };
    let body_height = usize::from(grid.height().saturating_sub(8 + occupied));
    let rows = transcript_rows(model, transcript_columns);
    let start = model
        .scroll
        .checked_add(body_height)
        .map_or(0, |window| rows.len().saturating_sub(window));
    for (row, line) in rows.iter().skip(start).take(body_height).enumerate() {
        let y = 6_u16.saturating_add(u16::try_from(row).unwrap_or(u16::MAX));
        grid.write(1, y, line, CellStyle::default());
    }
    for (row, tool) in model.tools.iter().rev().take(body_height).rev().enumerate() {
        let y = 6_u16.saturating_add(u16::try_from(row).unwrap_or(u16::MAX));
        grid.write(
            split.saturating_add(1),
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
                y.saturating_add(1),
                &format!("> {}", model.answer),
                colored(231, no_color),
            );
        }
    }
}

fn wrap_columns(text: &str, columns: usize) -> Vec<String> {
    let columns = columns.max(1);
    let mut rows = Vec::new();
    let mut row = String::new();
    let mut used = 0;
    for character in text.chars() {
        if character == '\n' {
            rows.push(std::mem::take(&mut row));
            used = 0;
            continue;
        }
        let mut character = sanitize_character(character);
        let mut width = character.width().unwrap_or(1).max(1);
        if width > columns {
            character = '\u{fffd}';
            width = 1;
        }
        if used + width > columns {
            rows.push(std::mem::take(&mut row));
            used = 0;
        }
        row.push(character);
        used += width;
    }
    rows.push(row);
    rows
}

fn transcript_rows(model: &AppModel, columns: usize) -> Vec<String> {
    model
        .transcript
        .iter()
        .flat_map(|entry| wrap_columns(&format!("{}: {}", entry.role, entry.text), columns))
        .collect()
}

pub(crate) fn transcript_row_count(model: &AppModel) -> usize {
    if model.viewport.0 < 8 {
        return model.transcript.len();
    }
    transcript_rows(
        model,
        usize::from((model.viewport.0.min(MAX_GRID_WIDTH) * 2 / 3).saturating_sub(2)).max(1),
    )
    .len()
}

fn draw_runs(grid: &mut Grid, model: &AppModel, no_color: bool) {
    grid.write(2, 4, "Run monitor", colored(45, no_color));
    for (row, session) in model.sessions.iter().skip(model.scroll).enumerate() {
        let y = 6_u16.saturating_add(u16::try_from(row).unwrap_or(u16::MAX));
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
            let y = 6_u16.saturating_add(u16::try_from(row).unwrap_or(u16::MAX));
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
        let y = 6_u16.saturating_add(u16::try_from(row).unwrap_or(u16::MAX));
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
    let split = grid.width().saturating_mul(2) / 5;
    grid.write(2, 4, "Artifacts", CellStyle::default());
    grid.write(split.saturating_add(1), 4, "Preview", CellStyle::default());
    for y in 4..grid.height().saturating_sub(2) {
        grid.put(split, y, '|', CellStyle::default());
    }
    for (row, artifact) in model.artifacts.iter().skip(model.scroll).enumerate() {
        let y = 6_u16.saturating_add(u16::try_from(row).unwrap_or(u16::MAX));
        if y >= grid.height().saturating_sub(2) {
            break;
        }
        grid.write(2, y, &format!("* {artifact}"), CellStyle::default());
    }
    for (row, line) in model.artifact_content.iter().skip(model.scroll).enumerate() {
        let y = 6_u16.saturating_add(u16::try_from(row).unwrap_or(u16::MAX));
        if y >= grid.height().saturating_sub(2) {
            break;
        }
        grid.write(split.saturating_add(1), y, line, CellStyle::default());
    }
    if model.artifacts.is_empty() {
        grid.write(
            2,
            6,
            "No artifacts for the selected session.",
            CellStyle::default(),
        );
    } else if model.artifact_content.is_empty() {
        grid.write(
            split.saturating_add(1),
            6,
            "No textual preview available.",
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
            6_u16.saturating_add(u16::try_from(row).unwrap_or(u16::MAX)),
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
    for row in y..y.saturating_add(6).min(grid.height()) {
        for column in x..x.saturating_add(width).min(grid.width()) {
            grid.put(column, row, ' ', colored(236, no_color));
        }
    }
    grid.write(
        x.saturating_add(2),
        y,
        "Command palette",
        colored(45, no_color),
    );
    grid.write(
        x.saturating_add(2),
        y.saturating_add(2),
        &format!(":{}", model.palette),
        colored(231, no_color),
    );
    grid.write(
        x.saturating_add(2),
        y.saturating_add(3),
        "screens: sessions workspace runs diff artifacts help",
        colored(245, no_color),
    );
    grid.write(
        x.saturating_add(2),
        y.saturating_add(4),
        "run  partial  partial-next  cancel  refresh  quit",
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

fn sanitize_character(character: char) -> char {
    if character == '\n' || character == '\r' || character == '\t' {
        ' '
    } else if character.is_control()
        || character.width() == Some(0)
        || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    {
        '\u{fffd}'
    } else {
        character
    }
}

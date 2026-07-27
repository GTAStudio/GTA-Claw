//! Deterministic rendering and terminal restoration coverage.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use gta_claw_tui::model::{
    AppModel, Prompt, RunState, Screen, SessionSummary, ToolActivity, TranscriptEntry,
};
use gta_claw_tui::render::{flush, flush_changes, render};
use gta_claw_tui::terminal::{TerminalControl, TerminalSession};

#[test]
fn fake_backend_renders_every_run_state_with_unique_marker_and_color() {
    let mut model = AppModel {
        screen: Screen::Runs,
        ..AppModel::default()
    };
    model.sessions = RunState::ALL
        .iter()
        .enumerate()
        .map(|(index, state)| SessionSummary {
            id: format!("session-{index}"),
            title: format!("Run {index:02}"),
            workspace: format!("C:\\work\\{index:02}"),
            state: *state,
            progress: u8::try_from(index * 9).ok(),
        })
        .collect();

    let grid = render(&model, 100, 24, false);
    let expected = [
        "[D Draft]",
        "[Q Queued]",
        "[S Starting]",
        "[R Running]",
        "[A Waiting for approval]",
        "[? Waiting for answer]",
        "[P Paused]",
        "[B Blocked]",
        "[F Failed]",
        "[X Cancelled]",
        "[C Completed]",
        "[+ Completed with changes]",
    ];
    let mut colors = HashSet::new();
    for (index, text) in expected.iter().enumerate() {
        let y = 6 + u16::try_from(index).expect("small row");
        let rendered: String = (30..30 + u16::try_from(text.len()).expect("short label"))
            .map(|x| grid.cell(x, y).expect("state cell").symbol)
            .collect();
        assert_eq!(rendered, *text);
        colors.insert(
            grid.cell(30, y)
                .expect("styled state marker")
                .style
                .foreground,
        );
    }
    assert_eq!(colors.len(), 12);
}

#[test]
fn fake_backend_renders_workspace_diff_artifacts_and_palette_cells() {
    let mut model = AppModel {
        screen: Screen::Workspace,
        connection: "Gateway: ready".to_owned(),
        sessions: vec![SessionSummary {
            id: "s-1".to_owned(),
            title: "Shipping fix".to_owned(),
            workspace: "D:\\repo".to_owned(),
            state: RunState::WaitingForApproval,
            progress: Some(60),
        }],
        prompt: Some(Prompt::Approval {
            id: "approval-1".to_owned(),
            text: "Run cargo test?".to_owned(),
        }),
        palette_open: true,
        palette: "diff".to_owned(),
        ..AppModel::default()
    };
    model.transcript.push_back(TranscriptEntry {
        role: "assistant".to_owned(),
        text: "I prepared the patch".to_owned(),
    });
    model.tools.push_back(ToolActivity {
        name: "powershell".to_owned(),
        status: "completed".to_owned(),
        summary: "tests passed".to_owned(),
    });

    let workspace = render(&model, 100, 30, true);
    assert_eq!(
        workspace.line(4),
        " Transcript - Shipping fix                                        |Tool activity                    "
    );
    assert_eq!(
        workspace.line(6),
        " assistant: I prepared the patch                                  |powershell [completed] tests pass"
    );
    assert_eq!(
        workspace.line(10),
        "                 Command palette                                                                    "
    );
    assert_eq!(
        workspace.line(12),
        "                 :diff                                                                              "
    );

    model.palette_open = false;
    model.screen = Screen::Diff;
    model.diff = vec![
        "@@ -1 +1 @@".to_owned(),
        "-old".to_owned(),
        "+new".to_owned(),
    ];
    let diff = render(&model, 60, 16, false);
    assert_eq!(
        diff.line(6),
        " @@ -1 +1 @@                                                "
    );
    assert_eq!(
        diff.line(7),
        " -old                                                       "
    );
    assert_eq!(
        diff.line(8),
        " +new                                                       "
    );
    assert_eq!(
        diff.cell(1, 7).expect("removed cell").style.foreground,
        Some(196)
    );
    assert_eq!(
        diff.cell(1, 8).expect("added cell").style.foreground,
        Some(42)
    );

    model.screen = Screen::Artifacts;
    model.artifacts = vec!["report.json".to_owned(), "trace.log".to_owned()];
    model.artifact_content = vec!["{\"status\":\"ok\"}".to_owned()];
    let artifacts = render(&model, 50, 14, true);
    assert_eq!(
        artifacts.line(6),
        "  * report.json     |{\"status\":\"ok\"}              "
    );
    assert_eq!(
        artifacts.line(7),
        "  * trace.log       |                             "
    );
}

#[derive(Default)]
struct MockTerminal {
    entered: AtomicUsize,
    restored: AtomicUsize,
}

#[derive(Default)]
struct FailOnceTerminal {
    restores: AtomicUsize,
}

impl TerminalControl for FailOnceTerminal {
    fn enter(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn restore(&self) -> std::io::Result<()> {
        if self.restores.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(std::io::Error::other("simulated restore failure"))
        } else {
            Ok(())
        }
    }
}

impl TerminalControl for MockTerminal {
    fn enter(&self) -> std::io::Result<()> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn restore(&self) -> std::io::Result<()> {
        self.restored.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn panic_unwind_always_restores_terminal() {
    let control = Arc::new(MockTerminal::default());
    let panic_control = Arc::clone(&control);
    let result = std::panic::catch_unwind(move || {
        let _terminal = TerminalSession::enter(panic_control).expect("enter mock terminal");
        panic!("simulated render panic");
    });

    assert!(result.is_err());
    assert_eq!(control.entered.load(Ordering::SeqCst), 1);
    assert_eq!(control.restored.load(Ordering::SeqCst), 1);
}

#[test]
fn explicit_shutdown_reports_restoration_and_restores_only_once() {
    let control = Arc::new(MockTerminal::default());
    let terminal = TerminalSession::enter(Arc::clone(&control)).expect("enter mock terminal");
    terminal.restore().expect("restore mock terminal");
    assert_eq!(control.restored.load(Ordering::SeqCst), 1);
}

#[test]
fn a_failed_explicit_restoration_is_retried_by_the_drop_guard() {
    let control = Arc::new(FailOnceTerminal::default());
    let terminal = TerminalSession::enter(Arc::clone(&control)).expect("enter mock terminal");
    assert!(terminal.restore().is_err());
    assert_eq!(control.restores.load(Ordering::SeqCst), 2);
}

#[test]
fn monochrome_render_retains_distinct_state_markers() {
    let mut model = AppModel {
        screen: Screen::Runs,
        ..AppModel::default()
    };
    model.sessions = RunState::ALL
        .iter()
        .enumerate()
        .map(|(index, state)| SessionSummary {
            id: index.to_string(),
            title: format!("run-{index}"),
            workspace: String::new(),
            state: *state,
            progress: None,
        })
        .collect();
    let grid = render(&model, 90, 24, true);
    let markers: String = (0..12)
        .map(|index| {
            grid.cell(31, 6 + index)
                .expect("monochrome marker cell")
                .symbol
        })
        .collect();
    assert_eq!(markers, "DQSRA?PBFXC+");
    assert_eq!(
        (0..12)
            .map(|index| {
                grid.cell(30, 6 + index)
                    .expect("monochrome state cell")
                    .style
                    .foreground
            })
            .collect::<Vec<_>>(),
        vec![None; 12]
    );
}

/// Builds a model with every optional area populated so the tiny-terminal sweep
/// exercises each drawing path, not just the empty-state fallbacks.
fn populated_model(screen: Screen, scroll: usize) -> AppModel {
    let mut model = AppModel {
        screen,
        connection: "Gateway: ready (protocol 4, epoch 1)".to_owned(),
        sessions: vec![SessionSummary {
            id: "s-1".to_owned(),
            title: "Shipping fix".to_owned(),
            workspace: "D:\\repo".to_owned(),
            state: RunState::Running,
            progress: Some(60),
        }],
        prompt: Some(Prompt::Question {
            id: "question-1".to_owned(),
            text: "Which branch?".to_owned(),
        }),
        palette_open: true,
        palette: "diff".to_owned(),
        answer: "main".to_owned(),
        notice: Some("Refreshing sessions...".to_owned()),
        diff: vec!["@@ -1 +1 @@".to_owned(), "+added".to_owned()],
        artifacts: vec!["report.txt".to_owned()],
        artifact_content: vec!["line one".to_owned()],
        ..AppModel::default()
    };
    model.scroll = scroll;
    model.transcript.push_back(TranscriptEntry {
        role: "assistant".to_owned(),
        text: "I prepared the patch".to_owned(),
    });
    model.tools.push_back(ToolActivity {
        name: "powershell".to_owned(),
        status: "completed".to_owned(),
        summary: "tests passed".to_owned(),
    });
    model
}

#[test]
fn degenerate_terminal_sizes_render_and_flush_without_panicking() {
    let screens = [
        Screen::Sessions,
        Screen::Workspace,
        Screen::Runs,
        Screen::Diff,
        Screen::Artifacts,
        Screen::Help,
    ];
    for screen in screens {
        for scroll in [0, 1, usize::MAX] {
            let model = populated_model(screen, scroll);
            for width in 0..=12_u16 {
                for height in 0..=12_u16 {
                    let grid = render(&model, width, height, false);
                    assert!(grid.width() >= 1 && grid.height() >= 1);
                    let mut out = Vec::new();
                    flush(&mut out, &grid, false).expect("flush a degenerate frame");
                }
            }
        }
    }
}

#[test]
fn extreme_terminal_dimensions_are_capped_to_a_responsive_grid() {
    let grid = render(
        &populated_model(Screen::Workspace, usize::MAX),
        u16::MAX,
        u16::MAX,
        false,
    );
    assert_eq!(grid.width(), 512);
    assert_eq!(grid.height(), 256);
    let mut out = Vec::new();
    flush(&mut out, &grid, false).expect("flush capped large frame");
}

#[test]
fn selected_sessions_and_scrolled_runs_remain_visible() {
    let mut model = AppModel {
        screen: Screen::Sessions,
        ..AppModel::default()
    };
    model.sessions = (0..20)
        .map(|index| SessionSummary {
            id: format!("s-{index}"),
            title: format!("Run {index:02}"),
            ..SessionSummary::default()
        })
        .collect();
    model.selected = 19;
    let sessions = render(&model, 60, 10, true);
    assert!(
        sessions.text().contains("> Run 19"),
        "the selected session must be scrolled into view"
    );

    model.screen = Screen::Runs;
    model.scroll = 5;
    let runs = render(&model, 60, 12, true);
    assert!(runs.line(6).contains("Run 05"));
}

#[test]
fn unchanged_frames_write_nothing_and_a_changed_line_writes_far_less_than_a_repaint() {
    let quiet = AppModel {
        connection: "Gateway: ready".to_owned(),
        ..AppModel::default()
    };
    let noticed = AppModel {
        connection: "Gateway: ready".to_owned(),
        notice: Some("Refreshing sessions...".to_owned()),
        ..AppModel::default()
    };
    let first = render(&quiet, 80, 24, true);
    let second = render(&noticed, 80, 24, true);

    let mut repaint = Vec::new();
    flush_changes(&mut repaint, None, &first, true).expect("first paint");
    assert!(!repaint.is_empty());

    let mut idle = Vec::new();
    flush_changes(&mut idle, Some(&first), &first, true).expect("idle frame");
    assert!(
        idle.is_empty(),
        "an unchanged frame must not redraw the terminal"
    );

    let mut partial = Vec::new();
    flush_changes(&mut partial, Some(&first), &second, true).expect("partial frame");
    assert!(!partial.is_empty());
    assert!(
        partial.len() * 4 < repaint.len(),
        "a one-line change wrote {} bytes against a {}-byte full repaint",
        partial.len(),
        repaint.len()
    );
}

#[test]
fn unicode_output_reanchors_the_terminal_cursor() {
    let model = AppModel {
        connection: "界 ready".to_owned(),
        ..AppModel::default()
    };
    let grid = render(&model, 40, 10, true);
    let mut out = Vec::new();
    flush(&mut out, &grid, true).expect("flush unicode frame");
    assert!(
        out.windows(b"\x1b[1;13H".len())
            .any(|window| window == b"\x1b[1;13H"),
        "the cell after a non-ASCII glyph must use an absolute cursor position"
    );
}

#[test]
fn a_resize_falls_back_to_a_full_repaint() {
    let model = populated_model(Screen::Sessions, 0);
    let small = render(&model, 60, 20, false);
    let large = render(&model, 100, 30, false);

    let mut resized = Vec::new();
    flush_changes(&mut resized, Some(&small), &large, false).expect("resized frame");
    let mut full = Vec::new();
    flush(&mut full, &large, false).expect("full frame");
    assert_eq!(resized, full);
}

/// A minimal ANSI screen that understands exactly the sequences the renderer
/// emits: absolute cursor moves, 256-color foreground, reset, and printable
/// scalars. It exists so an incremental repaint can be proven to land on the
/// same visible screen as a full one.
#[derive(Clone)]
struct FakeScreen {
    width: u16,
    height: u16,
    cells: Vec<(char, Option<u8>)>,
}

impl FakeScreen {
    fn new(width: u16, height: u16) -> Self {
        Self {
            width,
            height,
            cells: vec![(' ', None); usize::from(width) * usize::from(height)],
        }
    }

    fn apply(&mut self, bytes: &[u8]) {
        let text = String::from_utf8(bytes.to_vec()).expect("renderer emits UTF-8");
        let mut characters = text.chars();
        let (mut x, mut y) = (0_u16, 0_u16);
        let mut foreground = None;
        while let Some(character) = characters.next() {
            if character != '\u{1b}' {
                if x < self.width && y < self.height {
                    let index = usize::from(y) * usize::from(self.width) + usize::from(x);
                    self.cells[index] = (character, foreground);
                }
                x = x.saturating_add(1);
                continue;
            }
            assert_eq!(characters.next(), Some('['), "only CSI sequences are used");
            let mut body = String::new();
            let final_byte = loop {
                let next = characters.next().expect("terminated CSI sequence");
                if next.is_ascii_alphabetic() {
                    break next;
                }
                body.push(next);
            };
            let parameters = body
                .split(';')
                .filter(|part| !part.is_empty())
                .map(|part| part.parse::<u32>().expect("numeric CSI parameter"))
                .collect::<Vec<_>>();
            match final_byte {
                'H' => {
                    y = u16::try_from(parameters.first().copied().unwrap_or(1).saturating_sub(1))
                        .expect("row fits a terminal");
                    x = u16::try_from(parameters.get(1).copied().unwrap_or(1).saturating_sub(1))
                        .expect("column fits a terminal");
                }
                'm' => {
                    foreground = match parameters.as_slice() {
                        [38, 5, value] => {
                            Some(u8::try_from(*value).expect("256-color palette index"))
                        }
                        _ => None,
                    };
                }
                other => panic!("unexpected CSI final byte {other}"),
            }
        }
    }

    fn matches(&self, grid: &gta_claw_tui::render::Grid) -> bool {
        (0..self.height).all(|y| {
            (0..self.width).all(|x| {
                let cell = grid.cell(x, y).expect("rendered cell");
                let index = usize::from(y) * usize::from(self.width) + usize::from(x);
                self.cells[index] == (cell.symbol, cell.style.foreground)
            })
        })
    }
}

#[test]
fn an_incremental_repaint_lands_on_the_same_screen_as_a_full_one() {
    let frames = [
        populated_model(Screen::Runs, 0),
        populated_model(Screen::Diff, 0),
        populated_model(Screen::Workspace, 0),
        populated_model(Screen::Artifacts, 0),
    ];
    let mut screen = FakeScreen::new(90, 24);
    let mut previous: Option<gta_claw_tui::render::Grid> = None;
    let mut incremental = 0_usize;
    let mut repaints = 0_usize;
    for model in &frames {
        let grid = render(model, 90, 24, false);
        let mut bytes = Vec::new();
        flush_changes(&mut bytes, previous.as_ref(), &grid, false).expect("incremental frame");
        incremental += bytes.len();
        screen.apply(&bytes);
        assert!(
            screen.matches(&grid),
            "incremental repaint diverged from the rendered frame"
        );
        let mut full = Vec::new();
        flush(&mut full, &grid, false).expect("full frame");
        repaints += full.len();
        previous = Some(grid);
    }
    assert!(
        incremental < repaints,
        "incremental repaints wrote {incremental} bytes against {repaints} for full ones"
    );
}

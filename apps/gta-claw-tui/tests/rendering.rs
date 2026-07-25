//! Deterministic rendering and terminal restoration coverage.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use gta_claw_tui::model::{
    AppModel, Prompt, RunState, Screen, SessionSummary, ToolActivity, TranscriptEntry,
};
use gta_claw_tui::render::render;
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
    let artifacts = render(&model, 50, 14, true);
    assert_eq!(
        artifacts.line(6),
        "  * report.json                                   "
    );
    assert_eq!(
        artifacts.line(7),
        "  * trace.log                                     "
    );
}

#[derive(Default)]
struct MockTerminal {
    entered: AtomicUsize,
    restored: AtomicUsize,
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

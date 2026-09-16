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
fn accounting_wraps_without_overlapping_and_does_not_turn_missing_usage_into_zero() {
    use claw_protocol::native_accounting::ProviderAccounting;
    let mut value = serde_json::json!({
        "available":true,"recordedRounds":1,"completeCounterRounds":1,
        "partialCounterRounds":0,"unreportedRounds":0,"allPrimaryCountersReported":true,
        "observedTokens":{"inputTokens":0,"outputTokens":0,"totalTokens":0,"cachedInputTokens":0,"reasoningTokens":0},
        "aggregationOverflow":false,"costCalculated":false,"billingReconciled":false,
        "recordSource":"provider_journal","journalRevision":2,"journalClosed":false,
        "attemptsMayBeUnsent":true,
    });
    for mode in ["complete", "partial", "unreported", "missing"] {
        value["completeCounterRounds"] = serde_json::json!(u16::from(mode == "complete"));
        value["partialCounterRounds"] = serde_json::json!(u16::from(mode == "partial"));
        value["unreportedRounds"] =
            serde_json::json!(u16::from(matches!(mode, "unreported" | "missing")));
        value["allPrimaryCountersReported"] = serde_json::json!(mode == "complete");
        let accounting = if mode == "missing" {
            None
        } else {
            ProviderAccounting::parse(&value).expect("valid report")
        };
        for width in [40, 80, 120] {
            for height in [10, 24] {
                let mut model = AppModel {
                    screen: Screen::Workspace,
                    active_run: Some(("owned".to_owned(), "a".repeat(64))),
                    provider_accounting: accounting.clone(),
                    ..AppModel::default()
                };
                let split = width * 2 / 3;
                let mut visible = String::new();
                for scroll in 0..40 {
                    model.scroll = scroll;
                    let grid = render(&model, width, height, true);
                    for row in 6..height - 2 {
                        assert_eq!(grid.cell(split, row).expect("separator").symbol, '|');
                        visible.push_str(&grid.line(row));
                        visible.push('\n');
                    }
                }
                assert!(visible.contains("Billing:"), "{mode} {width}x{height}");
                assert!(visible.contains("unreconciled"));
                if matches!(mode, "complete" | "partial") {
                    assert!(visible.contains(&format!("Tokens ({mode}): 0")));
                    assert!(visible.contains("journal r2"));
                    assert!(visible.contains("open"));
                } else {
                    assert!(visible.contains("Tokens: unknown"));
                    assert!(!visible.contains("Tokens (complete): 0"));
                }
                assert!(model.transcript.is_empty() && model.pending_acks.is_empty());
            }
        }
    }
}

#[test]
fn model_catalogue_rows_wrap_and_keep_unknown_metadata_distinct() {
    let mut model = AppModel {
        screen: Screen::Models,
        model_catalogue: Some(serde_json::json!({
            "available":true,"provider":"fixture","providerGeneration":2,"selectedModel":"fixture-model","selectionPinned":true,
            "observedAtMs":123,"offset":0,"endOffset":1,"totalModels":1,"models":[{"id":"fixture-model",
                "aliases":[format!("{}ALIAS-END", "a".repeat(240))],
                "displayName":format!("{}MODEL-END", "\u{754c}".repeat(80)),"contextWindow":null,"maxOutputTokens":1024,"advertisedCapabilities":["completion","vision"]}]
        })),
        ..AppModel::default()
    };
    for width in [20, 40, 80, 120] {
        for height in [10, 24] {
            let mut visible = String::new();
            let mut logical = String::new();
            for scroll in 0..60 {
                model.scroll = scroll;
                let grid = render(&model, width, height, true);
                assert!(
                    grid.line(2).contains("[Models]"),
                    "active tab remains visible"
                );
                logical.extend(
                    grid.line(6)
                        .chars()
                        .filter(|character| !character.is_whitespace()),
                );
                for row in 6..height - 2 {
                    assert!(
                        grid.line(row)
                            .chars()
                            .all(|character| !character.is_control())
                    );
                    visible.push_str(&grid.line(row));
                    visible.push('\n');
                }
            }
            assert!(visible.contains("MODEL-END"), "{width}x{height}");
            assert!(logical.contains("Alias(config):") && logical.contains("ALIAS-END"));
            assert!(visible.contains("unverified"));
            assert!(logical.contains("Context:notreported"));
            assert!(!visible.contains("Context: 0"));
            assert!(visible.contains("Output: 1024"));
        }
    }
    for reason in [
        claw_protocol::native_models::CatalogueUnavailableReason::Disabled,
        claw_protocol::native_models::CatalogueUnavailableReason::AuthenticationPending,
        claw_protocol::native_models::CatalogueUnavailableReason::NotInitialized,
        claw_protocol::native_models::CatalogueUnavailableReason::Retired,
    ] {
        model.model_catalogue =
            Some(serde_json::json!({"available":false,"unavailableReason":reason}));
        for width in [20, 40, 80, 120] {
            for height in [10, 24] {
                let mut logical = String::new();
                for scroll in 0..8 {
                    model.scroll = scroll;
                    let grid = render(&model, width, height, true);
                    logical.extend(
                        grid.line(6)
                            .chars()
                            .filter(|character| !character.is_whitespace()),
                    );
                }
                let expected: String = reason
                    .to_string()
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .collect();
                assert!(logical.contains(&expected), "{width}x{height}: {reason}");
            }
        }
    }
    assert!(model.transcript.is_empty() && model.pending_acks.is_empty());
}

#[tokio::test]
async fn local_configuration_receipts_render_long_ids_without_secrets_or_chat_results() {
    struct OwnedRoot(std::path::PathBuf);
    impl Drop for OwnedRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let root = OwnedRoot(std::env::temp_dir().join(format!(
            "claw-tui-config-render-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )));
    std::fs::create_dir(&root.0).expect("owned render fixture");
    let source = root.0.join("source.json5");
    let exact = format!("{}MODEL-END", "m".repeat(240));
    std::fs::write(&source,serde_json::json!({"schema_version":1,"core":{"role":{"source_url":"http://127.0.0.1:9/role"},
        "channels":{"teams":{"enabled":false}},"auth":{},"server":{},"logging":{},"sessions":{},"copilot":{},"legacy":{},"updates":{},"admin":{},"network":{},
        "provider":{"kind":"openai","model":exact,"api_key":"env:DO_NOT_RENDER_REFERENCE"}}}).to_string()).expect("source");
    let mut model = AppModel {
        screen: Screen::Models,
        ..AppModel::default()
    };
    model
        .local_configuration
        .begin(
            &serde_json::json!({"action":"inspect","source":source}).to_string(),
            None,
        )
        .expect("local inspect");
    model.local_configuration.receive().await;
    for width in [20, 40, 80, 120] {
        for height in [10, 24] {
            let mut text = String::new();
            for scroll in 0..85 {
                model.scroll = scroll;
                let grid = render(&model, width, height, true);
                assert_eq!(grid.width(), width);
                assert_eq!(grid.height(), height);
                assert!(grid.line(2).contains("[Models]"));
                text.extend(
                    grid.line(6)
                        .chars()
                        .filter(|character| !character.is_whitespace()),
                );
                for row in 6..height - 2 {
                    assert!(
                        grid.line(row)
                            .chars()
                            .all(|character| !character.is_control())
                    );
                }
            }
            assert!(text.contains("SourceSHA256:"), "{width}x{height}");
            assert!(text.contains("Savedmodel:") && text.contains("MODEL-END"));
            assert!(!text.contains("DO_NOT_RENDER_REFERENCE"));
        }
    }
    assert!(model.transcript.is_empty() && model.pending_acks.is_empty());
}

#[test]
fn accounting_round_details_wrap_with_unknown_and_explicit_zero_kept_distinct() {
    use claw_protocol::native_accounting::{
        AccountingResponse, AccountingRound, ObservedTokens, ProviderAccounting,
    };
    use gta_claw_tui::gateway::{AccountingPage, AccountingPageRequest};
    let summary = ProviderAccounting::parse(&serde_json::json!({"available":true,"recordedRounds":2,"completeCounterRounds":1,"partialCounterRounds":0,"unreportedRounds":1,
        "allPrimaryCountersReported":false,"observedTokens":{"inputTokens":0,"outputTokens":0,"totalTokens":0,"cachedInputTokens":0,"reasoningTokens":0},
        "aggregationOverflow":false,"costCalculated":false,"billingReconciled":false,"recordSource":"terminal_turn","attemptsMayBeUnsent":true})).expect("summary").expect("present");
    let mut model = AppModel {
        screen: Screen::Workspace,
        active_run: Some(("owned".to_owned(), "a".repeat(64))),
        provider_accounting: Some(summary.clone()),
        ..AppModel::default()
    };
    model.accounting_page = Some(AccountingPage {
        request: AccountingPageRequest {
            connection_id: 1,
            session_id: "owned".to_owned(),
            run_id: "a".repeat(64),
            revision: 4,
            turn: 0,
            state: RunState::OutcomeUnknown,
            offset: 0,
            total_rounds: None,
            sha256: None,
            summary: None,
        },
        end_offset: 2,
        next_offset: None,
        total_rounds: 2,
        sha256: "b".repeat(64),
        summary,
        rounds: vec![
            AccountingRound {
                round: 0,
                response: None,
            },
            AccountingRound {
                round: 1,
                response: Some(AccountingResponse {
                    provider: "fixture".to_owned(),
                    model: format!("{}MODEL-END", "\u{754c}".repeat(80)),
                    response_id: Some("response-123".to_owned()),
                    usage_reporting: "complete".to_owned(),
                    finish_reason: "stop".to_owned(),
                    observed_tokens: ObservedTokens {
                        input_tokens: 0,
                        output_tokens: 0,
                        total_tokens: 0,
                        cached_input_tokens: 0,
                        reasoning_tokens: 0,
                    },
                }),
            },
        ],
    });
    for width in [40, 80, 120] {
        for height in [10, 24] {
            let mut visible = String::new();
            for scroll in 0..90 {
                model.scroll = scroll;
                let grid = render(&model, width, height, true);
                for row in 6..height - 2 {
                    assert_eq!(
                        grid.cell(width * 2 / 3, row).expect("separator").symbol,
                        '|'
                    );
                    visible.push_str(&grid.line(row));
                    visible.push('\n');
                }
            }
            assert!(visible.contains("delivery unknown"), "{width}x{height}");
            assert!(visible.contains("Tokens (complete): 0"));
            assert!(visible.contains("MODEL-END"));
            assert!(visible.contains("response-123"));
            assert!(model.pending_acks.is_empty());
        }
    }
}

#[test]
fn composer_tail_keeps_latest_wide_character_input_visible_at_small_widths() {
    let model = AppModel {
        screen: Screen::Workspace,
        composer_open: true,
        composer: format!("old input\n{}TAIL", "\u{4e2d}\u{6587}".repeat(80)),
        ..AppModel::default()
    };
    for width in [20, 40, 80, 120] {
        for height in [10, 24] {
            let grid = render(&model, width, height, true);
            assert_eq!(grid.width(), width);
            assert_eq!(grid.height(), height);
            assert!(
                grid.line(height - 4).trim_end().ends_with("TAIL"),
                "{width}x{height}"
            );
            assert!(!grid.line(height - 4).contains("old input"));
        }
    }
}

#[test]
fn partial_transcript_pages_wrap_inside_the_workspace_at_narrow_and_wide_sizes() {
    let mut model = AppModel {
        screen: Screen::Workspace,
        sessions: vec![SessionSummary {
            id: "owned".to_owned(),
            state: RunState::OutcomeUnknown,
            ..SessionSummary::default()
        }],
        ..AppModel::default()
    };
    model.transcript.push_back(TranscriptEntry {
        role: "partial [0..2048/4096 bytes]".to_owned(),
        text: format!("{}Z", "\u{4e2d}\u{6587}".repeat(120)),
    });
    for width in [40, 80, 120] {
        for height in [10, 24] {
            model.scroll = 0;
            let grid = render(&model, width, height, true);
            assert_eq!((grid.width(), grid.height()), (width, height));
            assert!((6..height - 2).any(|row| grid.line(row).contains('Z')));
            let split = width * 2 / 3;
            for row in 6..height - 2 {
                assert_eq!(grid.cell(split, row).expect("column separator").symbol, '|');
                assert!(
                    grid.line(row)
                        .chars()
                        .all(|character| !character.is_control())
                );
            }
            model.scroll = usize::MAX;
            assert!(
                render(&model, width, height, true)
                    .line(6)
                    .contains("partial")
            );
        }
    }
}

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
        "[! Outcome unknown]",
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
    assert_eq!(colors.len(), 13);
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
            preview_fingerprint: None,
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
    let markers: String = (0..13)
        .map(|index| {
            grid.cell(31, 6 + index)
                .expect("monochrome marker cell")
                .symbol
        })
        .collect();
    assert_eq!(markers, "DQSRA?PB!FXC+");
    assert_eq!(
        (0..13)
            .map(|index| {
                grid.cell(30, 6 + index)
                    .expect("monochrome state cell")
                    .style
                    .foreground
            })
            .collect::<Vec<_>>(),
        vec![None; 13]
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
        out.windows(b"\x1b[1;14H".len())
            .any(|window| window == b"\x1b[1;14H"),
        "the cell after a non-ASCII glyph must use an absolute cursor position"
    );
}

#[test]
fn native_long_transcripts_wrap_without_overwriting_the_tool_column() {
    let mut model = AppModel {
        screen: Screen::Workspace,
        viewport: (60, 16),
        ..AppModel::default()
    };
    model.transcript.push_back(TranscriptEntry {
        role: "assistant".to_owned(),
        text: format!("FIRST {} LAST", "long reply ".repeat(40)),
    });
    model.tools.push_back(ToolActivity {
        name: "tool".to_owned(),
        status: "ok".to_owned(),
        summary: "separate".to_owned(),
    });
    let tail = render(&model, 60, 16, true);
    assert!(tail.text().contains("LAST"));
    assert!(tail.text().contains("tool [ok] separate"));
    for row in 6..14 {
        assert_eq!(tail.cell(40, row).expect("column separator").symbol, '|');
    }
    model.scroll = 1000;
    let start = render(&model, 60, 16, true);
    assert!(start.text().contains("FIRST"));
    model.composer_open = true;
    model.composer = "visible draft".to_owned();
    let composing = render(&model, 60, 16, true);
    assert!(composing.line(11).contains("Message"));
    assert!(composing.line(12).contains("visible draft"));
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

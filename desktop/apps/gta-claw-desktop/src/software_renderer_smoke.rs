//! Headless smoke coverage for the complete external Slint component tree.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::command_palette::CommandPaletteState;
use crate::generated_ui::{
    ActivityItem, AppWindow, CommandItem, DeliverableItem, DiffItem, ExtensionItem, FileItem,
    RunItem, ScheduleItem, StatusKind, TranscriptItem, VisualPreferences, WorkspaceItem,
};
use slint::platform::software_renderer::{
    MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType, TargetPixel,
};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle as _, Model as _};

const SUPPORTED_DENSITIES: [f32; 6] = [0.8, 1.0, 1.25, 1.5, 1.75, 2.0];
const CARD_FIXTURE_COUNT: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CardGeometry {
    text_bounds_fit: bool,
    icon_bounds_fit: bool,
    badge_bounds_fit: bool,
    button_bounds_fit: bool,
    no_overlap: bool,
    stacked: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RgbPixel {
    red: u8,
    green: u8,
    blue: u8,
}

impl TargetPixel for RgbPixel {
    fn blend(&mut self, color: PremultipliedRgbaColor) {
        let inverse_alpha = 255_u32 - u32::from(color.alpha);
        self.red =
            (u32::from(color.red) + u32::from(self.red) * inverse_alpha / 255).min(255) as u8;
        self.green =
            (u32::from(color.green) + u32::from(self.green) * inverse_alpha / 255).min(255) as u8;
        self.blue =
            (u32::from(color.blue) + u32::from(self.blue) * inverse_alpha / 255).min(255) as u8;
    }

    fn from_rgb(red: u8, green: u8, blue: u8) -> Self {
        Self { red, green, blue }
    }
}

struct SoftwarePlatform {
    window: Rc<MinimalSoftwareWindow>,
    started: Instant,
}

impl Platform for SoftwarePlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.window.clone())
    }

    fn duration_since_start(&self) -> Duration {
        self.started.elapsed()
    }
}

fn fingerprint(pixels: &[RgbPixel]) -> u64 {
    pixels.iter().fold(0xcbf2_9ce4_8422_2325, |hash, pixel| {
        [pixel.red, pixel.green, pixel.blue]
            .into_iter()
            .fold(hash, |value, channel| {
                (value ^ u64::from(channel)).wrapping_mul(0x0000_0100_0000_01b3)
            })
    })
}

fn changed_pixel_count(before: &[RgbPixel], after: &[RgbPixel]) -> usize {
    before
        .iter()
        .zip(after)
        .filter(|(before, after)| before != after)
        .count()
}

fn assert_card_geometries(
    geometries: &RefCell<BTreeMap<i32, CardGeometry>>,
    expected_stacked: bool,
    surface: &str,
) {
    let geometries = geometries.borrow();
    assert_eq!(
        geometries.len(),
        CARD_FIXTURE_COUNT,
        "{surface} must report every repeated card"
    );
    for (index, geometry) in geometries.iter() {
        assert!(geometry.text_bounds_fit, "{surface} card {index} text bounds");
        assert!(geometry.icon_bounds_fit, "{surface} card {index} icon bounds");
        assert!(geometry.badge_bounds_fit, "{surface} card {index} badge bounds");
        assert!(geometry.button_bounds_fit, "{surface} card {index} button bounds");
        assert!(geometry.no_overlap, "{surface} card {index} overlap");
        assert_eq!(
            geometry.stacked, expected_stacked,
            "{surface} card {index} stacked policy"
        );
    }
}

fn model<T: Clone + 'static>(rows: Vec<T>) -> slint::ModelRc<T> {
    Rc::new(slint::VecModel::from(rows)).into()
}

fn dispatch_key(app: &AppWindow, text: slint::SharedString) {
    app.window()
        .dispatch_event(slint::platform::WindowEvent::KeyPressed { text: text.clone() });
    app.window()
        .dispatch_event(slint::platform::WindowEvent::KeyReleased { text });
}

fn dispatch_modified_key(
    app: &AppWindow,
    modifier: slint::platform::Key,
    text: slint::SharedString,
) {
    app.window()
        .dispatch_event(slint::platform::WindowEvent::KeyPressed {
            text: modifier.into(),
        });
    dispatch_key(app, text);
    app.window()
        .dispatch_event(slint::platform::WindowEvent::KeyReleased {
            text: modifier.into(),
        });
}

fn click(
    app: &AppWindow,
    window: &MinimalSoftwareWindow,
    width: usize,
    height: usize,
    x: f32,
    y: f32,
) {
    let position = slint::LogicalPosition { x, y };
    app.window()
        .dispatch_event(slint::platform::WindowEvent::PointerPressed {
            position,
            button: slint::platform::PointerEventButton::Left,
        });
    let _ = render(window, width, height);
    app.window()
        .dispatch_event(slint::platform::WindowEvent::PointerReleased {
            position,
            button: slint::platform::PointerEventButton::Left,
        });
    let _ = render(window, width, height);
}

fn scroll(app: &AppWindow, x: f32, y: f32, delta_y: f32) {
    app.window()
        .dispatch_event(slint::platform::WindowEvent::PointerScrolled {
            position: slint::LogicalPosition { x, y },
            delta_x: 0.0,
            delta_y,
        });
}

fn region(pixels: &[RgbPixel], width: usize, x: usize, y: usize) -> Vec<RgbPixel> {
    pixels
        .chunks_exact(width)
        .skip(y)
        .flat_map(|row| row[x..].iter().copied())
        .collect()
}

fn render(window: &MinimalSoftwareWindow, width: usize, height: usize) -> Vec<RgbPixel> {
    window.request_redraw();
    let mut pixels = vec![RgbPixel::default(); width * height];
    assert!(window.draw_if_needed(|renderer| {
        renderer.render(&mut pixels, width);
    }));
    pixels
}

fn tab_until_connection_action(
    app: &AppWindow,
    window: &MinimalSoftwareWindow,
    width: usize,
    height: usize,
    target: &str,
) {
    let mut previous = render(window, width, height);
    for _ in 0..16 {
        dispatch_key(app, slint::platform::Key::Tab.into());
        let current = render(window, width, height);
        if app.get_connection_focused_action() == target {
            assert!(
                changed_pixel_count(&previous, &current) > 8,
                "focused {target} action must be visibly revealed"
            );
            return;
        }
        previous = current;
    }
    panic!("{target} action must be keyboard reachable");
}

#[test]
fn software_renderer_constructs_onboarding_and_every_product_screen() {
    let software_window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(SoftwarePlatform {
        window: software_window.clone(),
        started: Instant::now(),
    }))
    .expect("install isolated software-renderer platform");

    let app = AppWindow::new().expect("construct the complete external Slint tree");
    let palette = CommandPaletteState::new(app.get_command_catalog().iter())
        .expect("translated command catalog");
    assert_eq!(palette.visible_count(), 10);
    app.set_runs(model(vec![RunItem {
        id: "run-smoke".into(),
        title: "Renderer smoke run".into(),
        workspace: "GTA-Claw".into(),
        state: "Waiting for approval".into(),
        detail: "Review a bounded command".into(),
        updated: "Now".into(),
        tone: 2,
    }]));
    app.set_workspaces(model(vec![
        WorkspaceItem {
            name: "Gateway compatibility workspace preview".into(),
            location:
                "No trusted path loaded; remote discovery and workspace enrollment are unavailable"
                    .into(),
            kind: "Preview workspace".into(),
            branch:
                "Workspace trust is not composed for this long generated branch and repository summary"
                    .into(),
            active_runs: 1,
        },
        WorkspaceItem {
            name: "Release coordination workspace preview".into(),
            location: "No remote workspace loaded for this generated release environment".into(),
            kind: "Preview workspace".into(),
            branch: "Remote release branch metadata remains sample-only and intentionally long".into(),
            active_runs: 0,
        },
        WorkspaceItem {
            name: "Accessibility verification workspace preview".into(),
            location: "No local directory selected for keyboard and screen-reader verification".into(),
            kind: "Preview workspace".into(),
            branch: "High-density layout review branch with no trusted filesystem access".into(),
            active_runs: 2,
        },
    ]));
    app.set_schedules(model(vec![
        ScheduleItem {
            name: "Desktop dependency and Gateway compatibility health preview".into(),
            cadence: "Every weekday at 09:00 in the configured workspace time zone".into(),
            next_run: "Tomorrow at 09:00 after the unavailable scheduler service is composed".into(),
            enabled: true,
            configured: true,
            state: "Enabled".into(),
            can_toggle: true,
            workspace: "GTA-Claw".into(),
        },
        ScheduleItem {
            name: "Weekly accessibility and renderer audit preview".into(),
            cadence: "Every Friday after the generated desktop verification window".into(),
            next_run: "Friday after a real scheduler adapter is connected".into(),
            enabled: false,
            configured: true,
            state: "Paused".into(),
            can_toggle: false,
            workspace: "Gateway lab".into(),
        },
        ScheduleItem {
            name: "Draft release readiness schedule preview".into(),
            cadence: "Cadence has not been configured for this sample draft".into(),
            next_run: "Not scheduled".into(),
            enabled: false,
            configured: false,
            state: "Draft".into(),
            can_toggle: false,
            workspace: "Release workspace".into(),
        },
    ]));
    app.set_deliverables(model(vec![DeliverableItem {
        name: "desktop-architecture.md".into(),
        kind: "Document".into(),
        source: "run-smoke".into(),
        size: "18 KB".into(),
        pinned: true,
    }]));
    app.set_selected_deliverable_name("desktop-architecture.md".into());
    app.set_selected_deliverable_kind("Document".into());
    app.set_selected_deliverable_source("run-smoke".into());
    app.set_selected_deliverable_size("18 KB".into());
    app.set_selected_deliverable_content("Rust owns state; Slint presents it.".into());
    app.set_selected_deliverable_pinned(true);
    app.set_extensions(model(vec![
        ExtensionItem {
            name: "Accessibility and responsive desktop quality audit preview".into(),
            category: "Skill".into(),
            detail:
                "Keyboard focus, contrast, labels, high-density geometry, and assistive technology checks"
                    .into(),
            permission:
                "Workspace read only after a trusted workspace and extension registry are composed"
                    .into(),
            enabled: true,
        },
        ExtensionItem {
            name: "GitHub repository connector preview".into(),
            category: "Connector".into(),
            detail: "Issues, pull requests, repository metadata, and long permission descriptions".into(),
            permission: "Ask before every write; no connector backend is active in this preview".into(),
            enabled: false,
        },
        ExtensionItem {
            name: "Bounded local shell permission preview".into(),
            category: "Permission".into(),
            detail: "Per-command approval and trusted-workspace policy would be required".into(),
            permission: "Unavailable until workspace trust and execution policy are composed".into(),
            enabled: false,
        },
    ]));
    app.set_transcript(model(vec![TranscriptItem {
        role: "GTA Claw".into(),
        text: "The software renderer is active.".into(),
        detail: "Auditable activity summary".into(),
        timestamp: "Now".into(),
        tone: 1,
    }]));
    app.set_activity(model(vec![ActivityItem {
        title: "Render product shell".into(),
        detail: "Software fallback".into(),
        state: "Completed".into(),
        duration: "12 ms".into(),
        tone: 4,
    }]));
    app.set_diff_lines(model(vec![DiffItem {
        old_line: "1".into(),
        new_line: "1".into(),
        text: "+render_product_shell();".into(),
        old_text: String::new().into(),
        new_text: "render_product_shell();".into(),
        kind: 1,
    }]));
    app.set_session_files(model(vec![FileItem {
        name: "product-shell.slint".into(),
        status: "Modified".into(),
    }]));
    app.set_selected_file_name("product-shell.slint".into());
    app.set_session_title(
        "Renderer smoke run with a long generated workspace and lifecycle title".into(),
    );
    app.set_session_state("Waiting for approval".into());
    app.set_session_detail(
        "Gateway compatibility workspace preview · Review a bounded command after inspecting the complete generated context".into(),
    );
    app.set_session_tone(2);
    app.set_can_approve(true);
    app.set_approval_prompt(
        "Allow this bounded renderer action after reviewing the complete sample scope?".into(),
    );
    app.set_approval_scope(
        "run-smoke · read-only preview · no network access · no workspace mutation".into(),
    );
    app.set_question(
        "Renderer smoke run needs a decision after reviewing the generated workspace context. Continue execution or pause the run?".into(),
    );
    app.set_status_text("Connected".into());
    app.set_status_label("Gateway status".into());
    app.set_status_icon("OK".into());
    app.set_status_kind(StatusKind::Success);
    app.set_server_summary("Gateway test fixture".into());
    app.set_role_summary("operator".into());
    app.set_scopes_summary("operator.read".into());
    app.set_health_summary("Health RPC returned ok=true".into());
    app.set_dashboard_awaiting_review(1);
    app.set_dashboard_running(1);
    app.set_dashboard_blocked(1);
    app.set_dashboard_workspaces(1);
    let workspace_geometries = Rc::new(RefCell::new(BTreeMap::new()));
    let observed_workspace_geometries = Rc::clone(&workspace_geometries);
    app.on_workspace_card_geometry_observed(
        move |index, text, icon, badge, button, no_overlap, stacked| {
            observed_workspace_geometries.borrow_mut().insert(
                index,
                CardGeometry {
                    text_bounds_fit: text,
                    icon_bounds_fit: icon,
                    badge_bounds_fit: badge,
                    button_bounds_fit: button,
                    no_overlap,
                    stacked,
                },
            );
        },
    );
    let schedule_geometries = Rc::new(RefCell::new(BTreeMap::new()));
    let observed_schedule_geometries = Rc::clone(&schedule_geometries);
    app.on_schedule_card_geometry_observed(
        move |index, text, icon, badge, button, no_overlap, stacked| {
            observed_schedule_geometries.borrow_mut().insert(
                index,
                CardGeometry {
                    text_bounds_fit: text,
                    icon_bounds_fit: icon,
                    badge_bounds_fit: badge,
                    button_bounds_fit: button,
                    no_overlap,
                    stacked,
                },
            );
        },
    );
    let extension_geometries = Rc::new(RefCell::new(BTreeMap::new()));
    let observed_extension_geometries = Rc::clone(&extension_geometries);
    app.on_extension_card_geometry_observed(
        move |index, text, icon, badge, button, no_overlap, stacked| {
            observed_extension_geometries.borrow_mut().insert(
                index,
                CardGeometry {
                    text_bounds_fit: text,
                    icon_bounds_fit: icon,
                    badge_bounds_fit: badge,
                    button_bounds_fit: button,
                    no_overlap,
                    stacked,
                },
            );
        },
    );
    app.set_layout_width(1080.0);
    software_window.set_size(slint::PhysicalSize::new(1080, 720));
    app.show().expect("show the software-rendered window");

    let mut rendered_surfaces = Vec::new();
    let mut fingerprints = BTreeSet::new();
    for onboarding_stage in 0..=3 {
        app.set_product_preview_open(false);
        app.set_onboarding_stage(onboarding_stage);
        software_window.request_redraw();
        let mut pixels = vec![RgbPixel::default(); 1080 * 720];
        let rendered = software_window.draw_if_needed(|renderer| {
            renderer.render(&mut pixels, 1080);
        });
        assert!(rendered);
        assert!(
            pixels
                .iter()
                .filter(|pixel| **pixel != RgbPixel::default())
                .count()
                > 10_000
        );
        assert!(fingerprints.insert(fingerprint(&pixels)));
        rendered_surfaces.push(format!("onboarding-{onboarding_stage}"));
    }

    app.set_layout_width(720.0);
    software_window.set_size(slint::PhysicalSize::new(720, 520));
    for density in SUPPORTED_DENSITIES {
        app.global::<VisualPreferences>().set_density_scale(density);
        for onboarding_stage in 0..=3 {
            app.set_onboarding_stage(onboarding_stage);
            let pixels = render(&software_window, 720, 520);
            assert!(
                pixels
                    .iter()
                    .filter(|pixel| **pixel != RgbPixel::default())
                    .count()
                    > 10_000,
                "onboarding stage {onboarding_stage} must render at {}% density",
                density * 100.0,
            );
            assert!(
                app.get_first_run_content_bounds_fit(),
                "first-run padded content must remain inside the 720px viewport"
            );
            if density == 2.0 && matches!(onboarding_stage, 1 | 2) {
                let _ = render(&software_window, 720, 520);
                assert!(
                    app.get_first_run_heading_text_bounds_fit(),
                    "first-run availability heading text must fit its card bounds at 200%"
                );
                assert!(
                    app.get_first_run_heading_high_density_wrapped(),
                    "long first-run availability headings must wrap at 720px/200%"
                );
            }
        }
    }

    app.global::<VisualPreferences>().set_density_scale(1.0);
    app.set_layout_width(1080.0);
    software_window.set_size(slint::PhysicalSize::new(1080, 720));
    app.set_product_preview_open(true);
    let mut body_fingerprints = BTreeSet::new();
    for screen in 0..=9 {
        app.set_selected_screen(screen);
        software_window.request_redraw();
        let mut pixels = vec![RgbPixel::default(); 1080 * 720];
        let rendered = software_window.draw_if_needed(|renderer| {
            renderer.render(&mut pixels, 1080);
        });
        assert!(rendered);
        assert!(
            pixels
                .iter()
                .filter(|pixel| **pixel != RgbPixel::default())
                .count()
                > 10_000
        );
        assert!(fingerprints.insert(fingerprint(&pixels)));
        let body = region(&pixels, 1080, 330, 90);
        assert!(
            body.iter()
                .filter(|pixel| **pixel != RgbPixel::default())
                .count()
                > 5_000
        );
        assert!(body_fingerprints.insert(fingerprint(&body)));
        rendered_surfaces.push(format!("screen-{screen}"));
    }

    assert_eq!(
        rendered_surfaces,
        vec![
            "onboarding-0",
            "onboarding-1",
            "onboarding-2",
            "onboarding-3",
            "screen-0",
            "screen-1",
            "screen-2",
            "screen-3",
            "screen-4",
            "screen-5",
            "screen-6",
            "screen-7",
            "screen-8",
            "screen-9",
        ]
    );
    assert_eq!(fingerprints.len(), 14);
    assert_eq!(body_fingerprints.len(), 10);

    app.set_selected_settings_section(3);
    app.set_layout_width(720.0);
    software_window.set_size(slint::PhysicalSize::new(720, 520));
    let mut density_fingerprints = Vec::new();
    for density in SUPPORTED_DENSITIES {
        app.global::<VisualPreferences>().set_density_scale(density);
        for screen in 0..=9 {
            match screen {
                1 => workspace_geometries.borrow_mut().clear(),
                3 => schedule_geometries.borrow_mut().clear(),
                5 => extension_geometries.borrow_mut().clear(),
                _ => {}
            }
            app.set_selected_screen(screen);
            let pixels = render(&software_window, 720, 520);
            let body = region(&pixels, 720, 120, 72);
            assert!(
                body.iter()
                    .filter(|pixel| **pixel != RgbPixel::default())
                    .count()
                    > 3_000,
                "screen {screen} must retain viable geometry at {}% density",
                density * 100.0,
            );
            assert!(app.get_product_viewport_bounds_fit());
            assert!(app.get_application_header_title_bounds_fit());
            assert!(app.get_application_header_badge_bounds_fit());
            if screen == 6 {
                assert!(app.get_settings_rail_bounds_fit());
            }
            if screen == 7 {
                assert!(app.get_session_narrow_layout());
            }
            if screen == 6 {
                density_fingerprints.push(fingerprint(&body));
            }
            if screen == 1 {
                assert_card_geometries(&workspace_geometries, true, "workspace");
            }
            if screen == 3 {
                assert_card_geometries(&schedule_geometries, true, "schedule");
            }
            if screen == 5 {
                assert_card_geometries(&extension_geometries, true, "extension");
            }
            if screen == 7 && density == 2.0 {
                let _ = render(&software_window, 720, 520);
                assert!(
                    app.get_session_header_stacked(),
                    "session header must stack at 720px/200%"
                );
                assert!(
                    app.get_session_header_text_bounds_fit(),
                    "long session title/detail text must fit the header copy bounds"
                );
                assert!(
                    app.get_session_header_back_bounds_fit(),
                    "session Back action and its text must remain inside the header"
                );
                assert!(
                    app.get_session_header_status_bounds_fit(),
                    "session status badge and text must remain inside the header"
                );
                assert!(
                    app.get_session_header_no_overlap(),
                    "Back, session copy, and status badge must not overlap"
                );
                assert!(
                    app.get_approval_actions_stacked(),
                    "approval actions must stack at 200% density in the 720px viewport"
                );
                assert!(
                    app.get_approval_text_bounds_fit(),
                    "approval title, prompt, and scope text must fit their allocated bounds"
                );
                assert!(
                    app.get_approval_controls_bounds_fit(),
                    "approval controls must remain inside the card and viewport"
                );
                assert!(
                    app.get_approval_controls_no_overlap(),
                    "approval copy and controls must not overlap at 200% density"
                );

                app.set_can_approve(false);
                app.set_can_answer(true);
                let _ = render(&software_window, 720, 520);
                let _ = render(&software_window, 720, 520);
                assert!(
                    app.get_question_actions_stacked(),
                    "answer actions must stack at 200% density in the 720px viewport"
                );
                assert!(
                    app.get_question_text_bounds_fit(),
                    "generated-length question title and text must fit their allocated bounds"
                );
                assert!(
                    app.get_question_controls_bounds_fit(),
                    "answer controls and their text must remain inside the card and viewport"
                );
                assert!(
                    app.get_question_controls_no_overlap(),
                    "question copy and answer controls must not overlap at 200% density"
                );
                app.set_can_answer(false);
                app.set_can_approve(true);
            }
        }
    }
    assert_eq!(density_fingerprints.len(), SUPPORTED_DENSITIES.len());
    assert_ne!(
        density_fingerprints.first(),
        density_fingerprints.last(),
        "80% and 200% must produce distinct but viable settings geometry"
    );

    app.set_product_preview_open(false);
    app.set_layout_width(1080.0);
    software_window.set_size(slint::PhysicalSize::new(1080, 720));
    for density in SUPPORTED_DENSITIES {
        app.global::<VisualPreferences>().set_density_scale(density);
        for onboarding_stage in 0..=3 {
            app.set_onboarding_stage(onboarding_stage);
            let pixels = render(&software_window, 1080, 720);
            assert!(
                pixels
                    .iter()
                    .filter(|pixel| **pixel != RgbPixel::default())
                    .count()
                    > 10_000,
                "1080px onboarding stage {onboarding_stage} at {}%",
                density * 100.0
            );
            if onboarding_stage < 3 {
                assert!(app.get_first_run_content_bounds_fit());
            }
        }
    }

    app.set_product_preview_open(true);
    for density in SUPPORTED_DENSITIES {
        app.global::<VisualPreferences>().set_density_scale(density);
        let expected_stacked = density > 1.25;
        for screen in 0..=9 {
            match screen {
                1 => workspace_geometries.borrow_mut().clear(),
                3 => schedule_geometries.borrow_mut().clear(),
                5 => extension_geometries.borrow_mut().clear(),
                _ => {}
            }
            app.set_selected_screen(screen);
            let pixels = render(&software_window, 1080, 720);
            assert!(
                pixels
                    .iter()
                    .filter(|pixel| **pixel != RgbPixel::default())
                    .count()
                    > 10_000,
                "1080px product screen {screen} at {}%",
                density * 100.0
            );
            assert!(app.get_product_viewport_bounds_fit());
            assert!(app.get_application_header_title_bounds_fit());
            assert!(app.get_application_header_badge_bounds_fit());
            match screen {
                1 => assert_card_geometries(
                    &workspace_geometries,
                    expected_stacked,
                    "1080px workspace",
                ),
                3 => assert_card_geometries(
                    &schedule_geometries,
                    expected_stacked,
                    "1080px schedule",
                ),
                5 => assert_card_geometries(
                    &extension_geometries,
                    expected_stacked,
                    "1080px extension",
                ),
                6 => assert!(app.get_settings_rail_bounds_fit()),
                7 => {
                    assert_eq!(app.get_session_narrow_layout(), expected_stacked);
                    assert!(app.get_session_header_text_bounds_fit());
                    assert!(app.get_session_header_back_bounds_fit());
                    assert!(app.get_session_header_status_bounds_fit());
                    assert!(app.get_session_header_no_overlap());
                }
                _ => {}
            }
        }
    }

    app.set_layout_width(720.0);
    software_window.set_size(slint::PhysicalSize::new(720, 520));

    app.set_palette_query("run".into());
    app.set_palette_commands(model(vec![CommandItem {
        action_id: 2,
        glyph: "R".into(),
        title: "Open Run Preview".into(),
        detail: "Ctrl/Cmd+3".into(),
        keywords: "runs sessions tasks monitor".into(),
    }]));
    app.set_palette_selected_index(0);
    app.set_palette_command_count(1);
    app.set_palette_selected_action_id(2);
    app.set_palette_selected_label("Open Run Preview".into());
    let selection_step = Rc::new(Cell::new(0));
    let observed_step = Rc::clone(&selection_step);
    app.on_palette_selection_step_requested(move |step| {
        observed_step.set(step);
    });
    let weak_app = app.as_weak();
    app.on_palette_selection_index_requested(move |index| {
        if let Some(app) = weak_app.upgrade() {
            app.set_palette_selected_index(index);
        }
    });
    let activated_action = Rc::new(Cell::new(-1));
    let observed_action = Rc::clone(&activated_action);
    app.on_palette_command_requested(move |action_id| {
        observed_action.set(action_id);
    });
    let weak_app = app.as_weak();
    app.on_palette_dismiss_requested(move || {
        if let Some(app) = weak_app.upgrade() {
            app.set_palette_open(false);
        }
    });
    let weak_app = app.as_weak();
    app.on_palette_toggle_requested(move || {
        if let Some(app) = weak_app.upgrade() {
            app.set_palette_open(!app.get_palette_open());
        }
    });
    app.set_palette_open(true);
    let mut palette_density_fingerprints = BTreeSet::new();
    let mut populated_palette = Vec::new();
    for density in [0.8, 2.0] {
        app.global::<VisualPreferences>().set_density_scale(density);
        software_window.request_redraw();
        let mut pixels = vec![RgbPixel::default(); 720 * 520];
        assert!(software_window.draw_if_needed(|renderer| {
            renderer.render(&mut pixels, 720);
        }));
        assert!(
            pixels
                .iter()
                .filter(|pixel| **pixel != RgbPixel::default())
                .count()
                > 10_000
        );
        assert!(palette_density_fingerprints.insert(fingerprint(&pixels)));
        populated_palette = pixels;
    }
    assert_eq!(palette_density_fingerprints.len(), 2);
    dispatch_key(&app, "x".into());
    assert_ne!(app.get_palette_query(), "run");
    dispatch_key(&app, slint::platform::Key::DownArrow.into());
    assert_eq!(selection_step.get(), 1);
    dispatch_key(&app, "\n".into());
    assert_eq!(activated_action.get(), 2);

    app.set_palette_query("missing".into());
    app.set_palette_commands(model(Vec::<CommandItem>::new()));
    app.set_palette_command_count(0);
    app.set_palette_selected_action_id(-1);
    app.set_palette_selected_label(slint::SharedString::default());
    software_window.request_redraw();
    let mut empty_palette = vec![RgbPixel::default(); 720 * 520];
    assert!(software_window.draw_if_needed(|renderer| {
        renderer.render(&mut empty_palette, 720);
    }));
    assert_ne!(fingerprint(&populated_palette), fingerprint(&empty_palette));
    dispatch_key(&app, slint::platform::Key::Escape.into());
    assert!(!app.get_palette_open());
    dispatch_key(&app, slint::platform::Key::F1.into());
    assert!(app.get_palette_open());
    dispatch_key(&app, slint::platform::Key::F1.into());
    assert!(!app.get_palette_open());
    app.window()
        .dispatch_event(slint::platform::WindowEvent::KeyPressed {
            text: slint::platform::Key::Control.into(),
        });
    dispatch_key(&app, "k".into());
    app.window()
        .dispatch_event(slint::platform::WindowEvent::KeyReleased {
            text: slint::platform::Key::Control.into(),
        });
    assert!(app.get_palette_open());
}

#[test]
fn palette_geometry_and_every_tab_stop_are_visible() {
    const WIDTH: usize = 720;
    const HEIGHT: usize = 520;

    let software_window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(SoftwarePlatform {
        window: software_window.clone(),
        started: Instant::now(),
    }))
    .expect("install isolated software-renderer platform");

    let app = AppWindow::new().expect("construct the complete external Slint tree");
    let commands = app.get_command_catalog().iter().collect::<Vec<_>>();
    app.set_palette_commands(model(commands.clone()));
    app.set_palette_command_count(10);
    app.set_palette_selected_action_id(0);
    app.set_palette_selected_label("Go to Preview Focus".into());
    let callback_commands = Rc::new(commands.clone());
    let selected_index = Rc::new(Cell::new(0_i32));
    let observed_selected_index = Rc::clone(&selected_index);
    let focused_commands = Rc::clone(&callback_commands);
    let weak_app = app.as_weak();
    app.on_palette_selection_index_requested(move |index| {
        let Ok(index_usize) = usize::try_from(index) else {
            return;
        };
        if let Some(command) = focused_commands.get(index_usize)
            && let Some(app) = weak_app.upgrade()
        {
            observed_selected_index.set(index);
            app.set_palette_selected_index(index);
            app.set_palette_selected_action_id(command.action_id);
            app.set_palette_selected_label(command.title.clone());
        }
    });
    let stepped_commands = Rc::clone(&callback_commands);
    let stepped_selected_index = Rc::clone(&selected_index);
    let weak_app = app.as_weak();
    app.on_palette_selection_step_requested(move |step| {
        let count = i32::try_from(stepped_commands.len()).expect("bounded command fixture");
        let next = (stepped_selected_index.get() + step).rem_euclid(count);
        let command = &stepped_commands[usize::try_from(next).expect("non-negative index")];
        stepped_selected_index.set(next);
        if let Some(app) = weak_app.upgrade() {
            app.set_palette_selected_index(next);
            app.set_palette_selected_action_id(command.action_id);
            app.set_palette_selected_label(command.title.clone());
        }
    });
    let activated_action = Rc::new(Cell::new(-1));
    let observed_action = Rc::clone(&activated_action);
    app.on_palette_command_requested(move |action| {
        observed_action.set(action);
    });
    app.set_product_preview_open(true);
    app.set_layout_width(f32::from(u16::try_from(WIDTH).expect("logical width")));
    app.global::<VisualPreferences>().set_density_scale(2.0);
    software_window.set_size(slint::PhysicalSize::new(
        u32::try_from(WIDTH).expect("width"),
        u32::try_from(HEIGHT).expect("height"),
    ));
    app.show().expect("show the software-rendered window");

    let closed = render(&software_window, WIDTH, HEIGHT);
    app.set_palette_open(true);
    let mut previous = render(&software_window, WIDTH, HEIGHT);
    assert!(
        changed_pixel_count(&closed, &previous) > WIDTH * HEIGHT / 8,
        "opening the palette must paint a full-window scrim and a positive-height sheet"
    );
    dispatch_key(&app, slint::platform::Key::DownArrow.into());
    previous = render(&software_window, WIDTH, HEIGHT);
    assert_eq!(app.get_palette_focused_command_index(), -1);
    assert_eq!(app.get_palette_selected_index(), 1);
    assert_eq!(app.get_palette_selected_label(), commands[1].title.clone());
    assert_eq!(app.get_palette_selected_action_id(), commands[1].action_id);
    dispatch_key(&app, "\n".into());
    assert_eq!(
        activated_action.get(),
        commands[1].action_id,
        "Enter from search must invoke the same action shown by selection and footer"
    );
    activated_action.set(-1);
    selected_index.set(0);
    app.set_palette_selected_index(0);
    app.set_palette_selected_action_id(commands[0].action_id);
    app.set_palette_selected_label(commands[0].title.clone());

    // Search, ten commands, the footer close button, and the title-bar close
    // button form one complete cycle.
    for tab_stop in 0..13 {
        dispatch_key(&app, slint::platform::Key::Tab.into());
        let current = render(&software_window, WIDTH, HEIGHT);
        assert!(
            changed_pixel_count(&previous, &current) > 8,
            "tab stop {tab_stop} must move a visible focus indicator or scroll the focused row"
        );
        if tab_stop < 10 {
            assert_eq!(
                app.get_palette_focused_command_index(),
                tab_stop,
                "Tab must reach every command row in order, including rows below the viewport"
            );
            assert_eq!(
                app.get_palette_selected_index(),
                tab_stop,
                "focused and visually selected command must stay synchronized"
            );
            assert_eq!(
                app.get_palette_selected_label(),
                commands[usize::try_from(tab_stop).expect("tab index")]
                    .title
                    .clone()
            );
            assert_eq!(
                app.get_palette_selected_action_id(),
                commands[usize::try_from(tab_stop).expect("tab index")].action_id
            );
            if tab_stop == 4 {
                dispatch_key(&app, "\n".into());
                assert_eq!(
                    activated_action.get(),
                    app.get_palette_selected_action_id(),
                    "Enter must invoke the command named by focus, selection, and footer"
                );
            }
        }
        previous = current;
    }

    app.set_palette_open(false);
    let _ = render(&software_window, WIDTH, HEIGHT);
    assert!(
        !software_window.draw_if_needed(|_| panic!("an idle UI must not render continuously")),
        "the closed, idle palette must remain at zero frames per second"
    );
}

#[test]
fn global_shortcuts_survive_conditional_focus_destruction() {
    const WIDTH: usize = 720;
    const HEIGHT: usize = 520;

    let software_window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(SoftwarePlatform {
        window: software_window.clone(),
        started: Instant::now(),
    }))
    .expect("install isolated software-renderer platform");

    let app = AppWindow::new().expect("construct the complete external Slint tree");
    let commands = app.get_command_catalog().iter().collect::<Vec<_>>();
    app.set_palette_commands(model(commands));
    app.set_palette_command_count(10);
    app.set_palette_selected_action_id(0);
    app.set_palette_selected_label("Go to Preview Focus".into());
    app.set_product_preview_open(true);
    app.set_layout_width(f32::from(u16::try_from(WIDTH).expect("logical width")));
    software_window.set_size(slint::PhysicalSize::new(
        u32::try_from(WIDTH).expect("width"),
        u32::try_from(HEIGHT).expect("height"),
    ));

    let weak_app = app.as_weak();
    app.on_palette_toggle_requested(move || {
        if let Some(app) = weak_app.upgrade() {
            app.set_palette_open(!app.get_palette_open());
        }
    });
    let weak_app = app.as_weak();
    app.on_palette_dismiss_requested(move || {
        if let Some(app) = weak_app.upgrade() {
            app.set_palette_open(false);
        }
    });
    let weak_app = app.as_weak();
    app.on_navigate_requested(move |screen| {
        if let Some(app) = weak_app.upgrade() {
            app.set_palette_open(false);
            app.set_selected_screen(screen);
        }
    });
    let weak_app = app.as_weak();
    app.on_onboarding_stage_requested(move |stage| {
        if let Some(app) = weak_app.upgrade() {
            app.set_onboarding_stage(stage);
        }
    });
    let weak_app = app.as_weak();
    app.global::<VisualPreferences>()
        .on_high_contrast_requested(move |enabled| {
            if let Some(app) = weak_app.upgrade() {
                app.set_high_contrast(enabled);
            }
        });

    app.show().expect("show the software-rendered window");
    let _ = render(&software_window, WIDTH, HEIGHT);
    let _ = render(&software_window, WIDTH, HEIGHT);

    dispatch_key(&app, slint::platform::Key::F1.into());
    assert!(app.get_palette_open());
    let background_scroll = app.get_background_scroll_position();
    scroll(&app, 360.0, 450.0, -180.0);
    let _ = render(&software_window, WIDTH, HEIGHT);
    assert_eq!(
        app.get_background_scroll_position(),
        background_scroll,
        "modal scrim must consume wheel input before the background viewport"
    );
    assert!(app.get_palette_open());
    dispatch_modified_key(&app, slint::platform::Key::Control, "2".into());
    assert_eq!(
        app.get_selected_screen(),
        0,
        "a modal palette must suppress background destination shortcuts"
    );
    assert!(app.get_palette_open());
    click(
        &app,
        &software_window,
        WIDTH,
        HEIGHT,
        5.0,
        180.0,
    );
    assert_eq!(
        app.get_selected_screen(),
        0,
        "scrim pointer activation must not reach background navigation"
    );
    assert!(!app.get_palette_open());
    dispatch_key(&app, slint::platform::Key::F1.into());
    assert!(app.get_palette_open());
    dispatch_key(&app, slint::platform::Key::Escape.into());
    assert!(!app.get_palette_open());

    let _ = render(&software_window, WIDTH, HEIGHT);
    for _ in 0..16 {
        dispatch_key(&app, slint::platform::Key::Tab.into());
        let _ = render(&software_window, WIDTH, HEIGHT);
        if app.get_palette_trigger_focused() {
            break;
        }
    }
    assert!(
        app.get_palette_trigger_focused(),
        "the visible palette trigger must remain keyboard reachable"
    );
    dispatch_key(&app, "\n".into());
    assert!(app.get_palette_open());
    dispatch_key(&app, slint::platform::Key::Escape.into());
    let _ = render(&software_window, WIDTH, HEIGHT);
    assert!(
        app.get_palette_trigger_focused(),
        "closing a trigger-opened palette must restore its invoking focus"
    );

    dispatch_modified_key(
        &app,
        slint::platform::Key::Shift,
        slint::platform::Key::Tab.into(),
    );
    let _ = render(&software_window, WIDTH, HEIGHT);
    assert!(
        app.get_preview_dismiss_trigger_focused(),
        "the control before the palette trigger must be focused before the pointer opens it"
    );
    assert!(!app.get_palette_trigger_focused());
    dispatch_key(&app, slint::platform::Key::F1.into());
    assert!(app.get_palette_open());
    dispatch_key(&app, slint::platform::Key::Escape.into());
    let _ = render(&software_window, WIDTH, HEIGHT);
    assert!(
        app.get_preview_dismiss_trigger_focused(),
        "global keyboard activation must preserve and restore its actual invoking control"
    );
    click(
        &app,
        &software_window,
        WIDTH,
        HEIGHT,
        638.0,
        30.0,
    );
    assert!(app.get_palette_open());
    dispatch_key(&app, slint::platform::Key::Escape.into());
    let _ = render(&software_window, WIDTH, HEIGHT);
    assert!(
        app.get_palette_trigger_focused(),
        "pointer activation must synchronously capture and restore the palette trigger"
    );
    assert!(!app.get_preview_dismiss_trigger_focused());

    app.set_selected_screen(6);
    app.set_selected_settings_section(3);
    let _ = render(&software_window, WIDTH, HEIGHT);
    for _ in 0..64 {
        dispatch_key(&app, slint::platform::Key::Tab.into());
        let _ = render(&software_window, WIDTH, HEIGHT);
        if app.get_appearance_contrast_focused() {
            break;
        }
    }
    assert!(
        app.get_appearance_contrast_focused(),
        "the appearance contrast toggle must be keyboard reachable"
    );
    assert!(!app.get_high_contrast());
    dispatch_key(&app, "\n".into());
    let _ = render(&software_window, WIDTH, HEIGHT);
    assert!(app.get_high_contrast());
    assert!(
        app.get_appearance_contrast_focused(),
        "changing the contrast label must not change the focused control identity"
    );
    dispatch_key(&app, slint::platform::Key::F1.into());
    assert!(app.get_palette_open());
    dispatch_key(&app, slint::platform::Key::Escape.into());
    let _ = render(&software_window, WIDTH, HEIGHT);
    assert!(
        app.get_appearance_contrast_focused(),
        "palette close must restore the contrast toggle by immutable focus id after its label changes"
    );

    dispatch_modified_key(&app, slint::platform::Key::Control, "2".into());
    let _ = render(&software_window, WIDTH, HEIGHT);
    assert_eq!(app.get_selected_screen(), 1);
    assert!(
        app.get_navigation_global_focus_active(),
        "destination shortcuts must hand focus to the persistent global scope"
    );
    dispatch_modified_key(&app, slint::platform::Key::Control, "2".into());
    let _ = render(&software_window, WIDTH, HEIGHT);
    assert_eq!(app.get_selected_screen(), 1);
    assert!(
        app.get_navigation_global_focus_active(),
        "same-destination shortcuts must still repair focus"
    );
    dispatch_key(&app, slint::platform::Key::F1.into());
    assert!(
        app.get_palette_open(),
        "F1 must survive destruction of the prior screen subtree"
    );
    dispatch_key(&app, slint::platform::Key::Escape.into());
    assert!(!app.get_palette_open());
    let _ = render(&software_window, WIDTH, HEIGHT);
    assert!(
        app.get_navigation_global_focus_active(),
        "palette dismissal must restore the global scope that invoked it"
    );

    dispatch_modified_key(&app, slint::platform::Key::Meta, "7".into());
    assert_eq!(
        app.get_selected_screen(),
        6,
        "the macOS command modifier must navigate through the persistent host"
    );

    app.set_product_preview_open(false);
    app.set_onboarding_stage(0);
    let _ = render(&software_window, WIDTH, HEIGHT);
    for _ in 0..4 {
        dispatch_key(&app, slint::platform::Key::Tab.into());
        dispatch_key(&app, "\n".into());
        if app.get_onboarding_stage() == 1 {
            break;
        }
    }
    assert_eq!(app.get_onboarding_stage(), 1);
    dispatch_key(&app, slint::platform::Key::Escape.into());
    assert_eq!(
        app.get_onboarding_stage(),
        0,
        "Escape must work after the focused Continue button is destroyed"
    );

    app.set_product_preview_open(true);
    let _ = render(&software_window, WIDTH, HEIGHT);
    dispatch_key(&app, slint::platform::Key::F1.into());
    assert!(
        app.get_palette_open(),
        "F1 must recover after the first-run surface is destroyed"
    );
}

#[test]
fn unavailable_first_run_steps_still_reach_the_gateway_with_keys() {
    const WIDTH: usize = 720;
    const HEIGHT: usize = 520;

    let software_window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(SoftwarePlatform {
        window: software_window.clone(),
        started: Instant::now(),
    }))
    .expect("install isolated software-renderer platform");

    let app = AppWindow::new().expect("construct the complete external Slint tree");
    app.set_product_preview_open(false);
    app.set_onboarding_stage(0);
    app.set_layout_width(f32::from(u16::try_from(WIDTH).expect("logical width")));
    software_window.set_size(slint::PhysicalSize::new(
        u32::try_from(WIDTH).expect("width"),
        u32::try_from(HEIGHT).expect("height"),
    ));
    let weak_app = app.as_weak();
    app.on_onboarding_stage_requested(move |stage| {
        if let Some(app) = weak_app.upgrade() {
            app.set_onboarding_stage(stage);
        }
    });

    app.show().expect("show the software-rendered window");
    for expected_stage in 1..=3 {
        let _ = render(&software_window, WIDTH, HEIGHT);
        dispatch_modified_key(
            &app,
            slint::platform::Key::Shift,
            slint::platform::Key::Tab.into(),
        );
        dispatch_key(&app, "\n".into());
        assert_eq!(
            app.get_onboarding_stage(),
            expected_stage,
            "the final action in each honest availability step must advance"
        );
    }
}

#[test]
fn tab_focus_scrolls_every_bounded_run_row_into_view() {
    const WIDTH: usize = 720;
    const HEIGHT: usize = 520;

    let software_window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(SoftwarePlatform {
        window: software_window.clone(),
        started: Instant::now(),
    }))
    .expect("install isolated software-renderer platform");

    let app = AppWindow::new().expect("construct the complete external Slint tree");
    app.set_runs(model(
        (0..24)
            .map(|index| RunItem {
                id: format!("run-{index}").into(),
                title: format!("Keyboard run {index}").into(),
                workspace: "GTA-Claw".into(),
                state: "Running".into(),
                detail: "Verify focus scrolling".into(),
                updated: "Now".into(),
                tone: 1,
            })
            .collect(),
    ));
    app.set_product_preview_open(true);
    app.set_selected_screen(0);
    app.set_can_previous_run_page(true);
    app.set_layout_width(f32::from(u16::try_from(WIDTH).expect("logical width")));
    app.global::<VisualPreferences>().set_density_scale(2.0);
    software_window.set_size(slint::PhysicalSize::new(
        u32::try_from(WIDTH).expect("width"),
        u32::try_from(HEIGHT).expect("height"),
    ));
    app.show().expect("show the software-rendered window");
    let _ = render(&software_window, WIDTH, HEIGHT);

    for _ in 0..32 {
        dispatch_key(&app, slint::platform::Key::Tab.into());
        if app.get_focused_run_index() == 0 {
            break;
        }
    }
    assert_eq!(app.get_focused_run_index(), 0);
    assert!(app.get_focused_run_visibility_generation() > 0);
    assert!(
        app.get_focused_run_visible(),
        "first focused run must be visible through both scroll layers"
    );

    let mut previous = render(&software_window, WIDTH, HEIGHT);
    for expected_index in 1..24 {
        let visibility_generation = app.get_focused_run_visibility_generation();
        dispatch_key(&app, slint::platform::Key::Tab.into());
        let current = render(&software_window, WIDTH, HEIGHT);
        assert!(
            app.get_focused_run_visibility_generation() > visibility_generation,
            "run row {expected_index} must publish fresh visibility geometry"
        );
        assert_eq!(
            app.get_focused_run_index(),
            expected_index,
            "Tab must reach virtualized run row {expected_index}"
        );
        assert!(
            app.get_focused_run_visible(),
            "run row {expected_index} must be visible in the inner and outer viewports"
        );
        assert!(
            changed_pixel_count(&previous, &current) > 8,
            "run row {expected_index} must be visibly focused or scroll into view"
        );
        previous = current;
    }

    dispatch_key(&app, slint::platform::Key::Tab.into());
    let after_list = render(&software_window, WIDTH, HEIGHT);
    assert!(changed_pixel_count(&previous, &after_list) > 8);
    dispatch_modified_key(
        &app,
        slint::platform::Key::Shift,
        slint::platform::Key::Tab.into(),
    );
    let mut previous = render(&software_window, WIDTH, HEIGHT);
    assert_eq!(app.get_focused_run_index(), 23);
    assert!(app.get_focused_run_visible());
    assert!(changed_pixel_count(&after_list, &previous) > 8);

    for expected_index in (0..23).rev() {
        let visibility_generation = app.get_focused_run_visibility_generation();
        dispatch_modified_key(
            &app,
            slint::platform::Key::Shift,
            slint::platform::Key::Tab.into(),
        );
        let current = render(&software_window, WIDTH, HEIGHT);
        assert!(
            app.get_focused_run_visibility_generation() > visibility_generation,
            "reverse-focused run row {expected_index} must publish fresh visibility geometry"
        );
        assert_eq!(
            app.get_focused_run_index(),
            expected_index,
            "Shift+Tab must reach bounded run row {expected_index}"
        );
        assert!(
            app.get_focused_run_visible(),
            "reverse-focused run row {expected_index} must be visible"
        );
        assert!(
            changed_pixel_count(&previous, &current) > 8,
            "run row {expected_index} must visibly scroll back into view"
        );
        previous = current;
    }
}

#[test]
fn connection_actions_keep_focus_and_disabled_buttons_consume_activation() {
    const WIDTH: usize = 900;
    const HEIGHT: usize = 720;

    let software_window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(SoftwarePlatform {
        window: software_window.clone(),
        started: Instant::now(),
    }))
    .expect("install isolated software-renderer platform");

    let app = AppWindow::new().expect("construct the complete external Slint tree");
    app.set_product_preview_open(false);
    app.set_onboarding_stage(3);
    app.set_can_connect(true);
    app.set_can_retry(false);
    app.set_can_cancel(false);
    app.set_can_disconnect(false);
    app.set_scopes_summary(
        "operator.read diagnostic scope, session-only and read-only".into(),
    );
    app.set_identity_summary(
        "claw device identity fingerprint for this ephemeral diagnostic session".into(),
    );
    app.set_layout_width(f32::from(u16::try_from(WIDTH).expect("logical width")));
    app.global::<VisualPreferences>().set_density_scale(2.0);
    software_window.set_size(slint::PhysicalSize::new(
        u32::try_from(WIDTH).expect("width"),
        u32::try_from(HEIGHT).expect("height"),
    ));

    let connect_count = Rc::new(Cell::new(0));
    let observed_connects = Rc::clone(&connect_count);
    let weak_app = app.as_weak();
    app.on_connect_requested(move |_, _, _| {
        observed_connects.set(observed_connects.get() + 1);
        if let Some(app) = weak_app.upgrade() {
            app.set_can_connect(false);
            app.set_can_cancel(true);
            app.set_busy(true);
        }
    });
    let retry_count = Rc::new(Cell::new(0));
    let observed_retries = Rc::clone(&retry_count);
    let weak_app = app.as_weak();
    app.on_retry_requested(move |_, _, _| {
        observed_retries.set(observed_retries.get() + 1);
        if let Some(app) = weak_app.upgrade() {
            app.set_can_retry(false);
            app.set_can_disconnect(true);
        }
    });
    let preview_count = Rc::new(Cell::new(0));
    let observed_previews = Rc::clone(&preview_count);
    app.on_preview_requested(move || {
        observed_previews.set(observed_previews.get() + 1);
    });
    let cancel_count = Rc::new(Cell::new(0));
    let observed_cancels = Rc::clone(&cancel_count);
    let weak_app = app.as_weak();
    app.on_cancel_requested(move || {
        observed_cancels.set(observed_cancels.get() + 1);
        if let Some(app) = weak_app.upgrade() {
            app.set_busy(false);
            app.set_can_cancel(false);
            app.set_can_retry(true);
        }
    });
    let disconnect_count = Rc::new(Cell::new(0));
    let observed_disconnects = Rc::clone(&disconnect_count);
    let weak_app = app.as_weak();
    app.on_disconnect_requested(move || {
        observed_disconnects.set(observed_disconnects.get() + 1);
        if let Some(app) = weak_app.upgrade() {
            app.set_can_disconnect(false);
            app.set_can_connect(true);
        }
    });

    app.show().expect("show the software-rendered window");
    let _ = render(&software_window, WIDTH, HEIGHT);
    let _ = render(&software_window, WIDTH, HEIGHT);
    assert!(
        app.get_gateway_summary_high_density_stacked(),
        "200% density must stack long summary labels above their values"
    );
    assert!(
        app.get_gateway_summary_text_bounds_fit(),
        "every summary label and value text box must fit its allocated row bounds at 200%"
    );

    tab_until_connection_action(&app, &software_window, WIDTH, HEIGHT, "Connect");
    assert_eq!(app.get_connection_focused_action(), "Connect");
    dispatch_key(&app, "\n".into());
    assert_eq!(connect_count.get(), 1);
    assert_eq!(
        app.get_connection_focused_action(),
        "Connect",
        "disabling a retained action must not discard focus"
    );
    dispatch_key(&app, " ".into());
    dispatch_key(&app, "\n".into());
    assert_eq!(
        connect_count.get(),
        1,
        "a disabled custom control must consume Space and Enter without activation"
    );

    tab_until_connection_action(&app, &software_window, WIDTH, HEIGHT, "Cancel");
    assert_eq!(app.get_connection_focused_action(), "Cancel");
    dispatch_key(&app, "\n".into());
    assert_eq!(cancel_count.get(), 1);
    assert_eq!(app.get_connection_focused_action(), "Cancel");
    dispatch_key(&app, " ".into());
    dispatch_key(&app, "\n".into());
    assert_eq!(cancel_count.get(), 1);

    tab_until_connection_action(&app, &software_window, WIDTH, HEIGHT, "Retry");
    assert_eq!(app.get_connection_focused_action(), "Retry");
    dispatch_key(&app, "\n".into());
    assert_eq!(retry_count.get(), 1);
    assert_eq!(app.get_connection_focused_action(), "Retry");
    dispatch_key(&app, " ".into());
    dispatch_key(&app, "\n".into());
    assert_eq!(retry_count.get(), 1);
    assert!(
        !app.get_product_preview_open(),
        "diagnostic readiness alone must stay on the real diagnostic surface"
    );

    tab_until_connection_action(&app, &software_window, WIDTH, HEIGHT, "Open preview");
    dispatch_key(&app, "\n".into());
    assert_eq!(preview_count.get(), 1);
    assert!(
        !app.get_product_preview_open(),
        "only the application callback may explicitly enter the read-only preview"
    );

    tab_until_connection_action(&app, &software_window, WIDTH, HEIGHT, "Disconnect");
    assert_eq!(app.get_connection_focused_action(), "Disconnect");
    dispatch_key(&app, "\n".into());
    assert_eq!(disconnect_count.get(), 1);
    assert_eq!(app.get_connection_focused_action(), "Disconnect");
    dispatch_key(&app, " ".into());
    dispatch_key(&app, "\n".into());
    assert_eq!(disconnect_count.get(), 1);
}

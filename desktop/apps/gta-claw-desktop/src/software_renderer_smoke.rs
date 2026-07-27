//! Headless smoke coverage for the complete external Slint component tree.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::command_palette::CommandPaletteState;
use crate::generated_ui::{
    ActivityItem, AppWindow, CommandItem, DeliverableItem, DiffItem, ExtensionItem, FileItem,
    RunItem, ScheduleItem, TranscriptItem, VisualPreferences, WorkspaceItem,
};
use slint::platform::software_renderer::{
    MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType, TargetPixel,
};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle as _, Model as _};

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
    app.set_workspaces(model(vec![WorkspaceItem {
        name: "GTA-Claw".into(),
        location: r"C:\work\GTA-Claw".into(),
        kind: "Git repository".into(),
        branch: "desktop-slint-application".into(),
        active_runs: 1,
    }]));
    app.set_schedules(model(vec![ScheduleItem {
        name: "Desktop health".into(),
        cadence: "Weekdays at 09:00".into(),
        next_run: "Tomorrow".into(),
        enabled: true,
        can_toggle: true,
        workspace: "GTA-Claw".into(),
    }]));
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
    app.set_extensions(model(vec![ExtensionItem {
        name: "Accessibility audit".into(),
        category: "Skill".into(),
        detail: "Keyboard, contrast, and labels".into(),
        permission: "Workspace read".into(),
        enabled: true,
    }]));
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
    app.set_session_title("Renderer smoke run".into());
    app.set_session_state("Waiting for approval".into());
    app.set_session_detail("GTA-Claw · Review a bounded command".into());
    app.set_session_tone(2);
    app.set_can_approve(true);
    app.set_approval_prompt("Allow this bounded renderer action?".into());
    app.set_approval_scope("run-smoke · no network access".into());
    app.set_question("Continue execution or pause the run?".into());
    app.set_layout_width(1080.0);
    software_window.set_size(slint::PhysicalSize::new(1080, 720));
    app.show().expect("show the software-rendered window");

    let mut rendered_surfaces = Vec::new();
    let mut fingerprints = BTreeSet::new();
    for onboarding_stage in 0..=3 {
        app.set_workspace_ready(false);
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

    app.set_workspace_ready(true);
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

    app.set_selected_screen(6);
    app.set_selected_settings_section(3);
    app.set_layout_width(720.0);
    software_window.set_size(slint::PhysicalSize::new(720, 520));
    let mut density_fingerprints = BTreeSet::new();
    for density in [0.8, 2.0] {
        app.global::<VisualPreferences>().set_density_scale(density);
        software_window.request_redraw();
        let mut pixels = vec![RgbPixel::default(); 720 * 520];
        assert!(software_window.draw_if_needed(|renderer| {
            renderer.render(&mut pixels, 720);
        }));
        let body = region(&pixels, 720, 150, 90);
        assert!(
            body.iter()
                .filter(|pixel| **pixel != RgbPixel::default())
                .count()
                > 3_000
        );
        assert!(density_fingerprints.insert(fingerprint(&body)));
    }
    assert_eq!(density_fingerprints.len(), 2);

    app.set_palette_query("run".into());
    app.set_palette_commands(model(vec![CommandItem {
        action_id: 2,
        glyph: "R".into(),
        title: "Open Run Monitor".into(),
        detail: "Ctrl/Cmd+3".into(),
        keywords: "runs sessions tasks monitor".into(),
    }]));
    app.set_palette_selected_index(0);
    app.set_palette_command_count(1);
    app.set_palette_selected_action_id(2);
    app.set_palette_selected_label("Open Run Monitor".into());
    let selection_step = Rc::new(Cell::new(0));
    let observed_step = Rc::clone(&selection_step);
    app.on_palette_selection_step_requested(move |step| {
        observed_step.set(step);
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
    app.set_palette_commands(model(commands));
    app.set_palette_command_count(10);
    app.set_palette_selected_action_id(0);
    app.set_palette_selected_label("Go to Focus".into());
    app.set_workspace_ready(true);
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
    app.set_palette_selected_label("Go to Focus".into());
    app.set_workspace_ready(true);
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

    app.show().expect("show the software-rendered window");
    let _ = render(&software_window, WIDTH, HEIGHT);

    dispatch_key(&app, slint::platform::Key::F1.into());
    assert!(app.get_palette_open());
    dispatch_key(&app, slint::platform::Key::Escape.into());
    assert!(!app.get_palette_open());

    dispatch_modified_key(&app, slint::platform::Key::Control, "2".into());
    assert_eq!(app.get_selected_screen(), 1);
    dispatch_key(&app, slint::platform::Key::F1.into());
    assert!(
        app.get_palette_open(),
        "F1 must survive destruction of the prior screen subtree"
    );
    dispatch_key(&app, slint::platform::Key::Escape.into());
    assert!(!app.get_palette_open());

    dispatch_modified_key(&app, slint::platform::Key::Meta, "7".into());
    assert_eq!(
        app.get_selected_screen(),
        6,
        "the macOS command modifier must navigate through the persistent host"
    );

    app.set_workspace_ready(false);
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

    app.set_workspace_ready(true);
    let _ = render(&software_window, WIDTH, HEIGHT);
    dispatch_key(&app, slint::platform::Key::F1.into());
    assert!(
        app.get_palette_open(),
        "F1 must recover after the first-run surface is destroyed"
    );
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
    app.set_workspace_ready(true);
    app.set_selected_screen(2);
    app.set_can_previous_run_page(true);
    app.set_layout_width(f32::from(u16::try_from(WIDTH).expect("logical width")));
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

    let mut previous = render(&software_window, WIDTH, HEIGHT);
    for expected_index in 1..24 {
        dispatch_key(&app, slint::platform::Key::Tab.into());
        let current = render(&software_window, WIDTH, HEIGHT);
        assert_eq!(
            app.get_focused_run_index(),
            expected_index,
            "Tab must reach virtualized run row {expected_index}"
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
    assert!(changed_pixel_count(&after_list, &previous) > 8);

    for expected_index in (0..23).rev() {
        dispatch_modified_key(
            &app,
            slint::platform::Key::Shift,
            slint::platform::Key::Tab.into(),
        );
        let current = render(&software_window, WIDTH, HEIGHT);
        assert_eq!(
            app.get_focused_run_index(),
            expected_index,
            "Shift+Tab must reach bounded run row {expected_index}"
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
    app.set_workspace_ready(false);
    app.set_onboarding_stage(3);
    app.set_can_connect(true);
    app.set_can_retry(false);
    app.set_can_cancel(false);
    app.set_can_disconnect(false);
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

    tab_until_connection_action(&app, &software_window, WIDTH, HEIGHT, "Disconnect");
    assert_eq!(app.get_connection_focused_action(), "Disconnect");
    dispatch_key(&app, "\n".into());
    assert_eq!(disconnect_count.get(), 1);
    assert_eq!(app.get_connection_focused_action(), "Disconnect");
    dispatch_key(&app, " ".into());
    dispatch_key(&app, "\n".into());
    assert_eq!(disconnect_count.get(), 1);
}

//! Headless smoke coverage for the complete external Slint component tree.

use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::generated_ui::{
    ActivityItem, AppWindow, DeliverableItem, DiffItem, ExtensionItem, FileItem, RunItem,
    ScheduleItem, TranscriptItem, VisualPreferences, WorkspaceItem,
};
use slint::ComponentHandle as _;
use slint::platform::software_renderer::{
    MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType, TargetPixel,
};
use slint::platform::{Platform, PlatformError, WindowAdapter};

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

fn model<T: Clone + 'static>(rows: Vec<T>) -> slint::ModelRc<T> {
    Rc::new(slint::VecModel::from(rows)).into()
}

fn region(pixels: &[RgbPixel], width: usize, x: usize, y: usize) -> Vec<RgbPixel> {
    pixels
        .chunks_exact(width)
        .skip(y)
        .flat_map(|row| row[x..].iter().copied())
        .collect()
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
}

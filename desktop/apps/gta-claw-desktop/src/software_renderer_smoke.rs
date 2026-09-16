//! Headless smoke coverage for the complete external Slint component tree.

use std::cell::Cell;
use std::collections::BTreeSet;
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
fn native_local_model_editor_callbacks_create_a_verified_candidate_without_applying() {
    use crate::controller::{DesktopController, ProductConnection, ProductUpdate};
    use serde_json::json;
    struct OwnedRoot(std::path::PathBuf);
    impl Drop for OwnedRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let root = OwnedRoot(std::env::temp_dir().join(format!(
            "claw-slint-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )));
    std::fs::create_dir(&root.0).expect("owned local config root");
    let source = root.0.join("source.json5");
    let destination = root.0.join("candidate.json5");
    let original=json!({"schema_version":1,"core":{"role":{"source_url":"http://127.0.0.1:9/role"},"channels":{"teams":{"enabled":false}},
        "auth":{},"server":{},"logging":{},"sessions":{},"copilot":{},"legacy":{},"updates":{},"admin":{},"network":{},
        "provider":{"kind":"openai","model":"model-0","api_key":"env:SLINT_NOT_RESOLVED"}}}).to_string();
    std::fs::write(&source, &original).expect("complete local source");
    let software_window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(SoftwarePlatform {
        window: software_window,
        started: Instant::now(),
    }))
    .expect("local editor renderer");
    let app = AppWindow::new().expect("component tree");
    let view = std::rc::Rc::new(
        crate::ProductView::attach(&app, crate::product_state::ProductState::native())
            .expect("native view"),
    );
    let (updates, observed) = std::sync::mpsc::sync_channel(8);
    let controller = DesktopController::spawn_product(
        |_| {},
        move |update| {
            assert!(updates.try_send(update).is_ok());
        },
    )
    .expect("local controller");
    crate::wire_native_callbacks(&app, controller.sender(), &view);
    let connection = ProductConnection {
        generation: 0,
        epoch: 1,
    };
    view.state
        .borrow_mut()
        .apply_native(ProductUpdate::Ready { connection });
    let parameters = view
        .state
        .borrow()
        .native_model_catalogue(0)
        .expect("page read");
    view.state
        .borrow_mut()
        .native_model_catalogue_enqueued(&parameters);
    view.state.borrow_mut().apply_native(ProductUpdate::Response {connection,method:"models.list",params:parameters,
        payload:json!({"schemaVersion":1,"available":true,"offset":0,"endOffset":8,"nextOffset":8,"totalModels":9,"sha256":"a".repeat(64),
            "provider":"openai","providerGeneration":1,"selectedModel":"model-0","selectionPinned":true,"observedAtMs":123,
            "source":"provider_sdk_catalogue","liveCapabilitiesVerified":false,"selectionChanged":false,"networkContacted":false,
            "models":(0..8).map(|ordinal|json!({"id":format!("model-{ordinal}"),"displayName":null,"contextWindow":null,"maxOutputTokens":null,"advertisedCapabilities":["completion"]})).collect::<Vec<_>>()}),
    });
    view.apply(&app);
    let binding = app.get_model_choice_binding();
    app.invoke_local_configuration_requested(
        0,
        source.to_str().expect("source path").into(),
        "".into(),
        "".into(),
        -1,
    );
    assert!(app.get_local_configuration_busy());
    view.state.borrow_mut().apply_native(
        observed
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("actual inspection"),
    );
    view.apply(&app);
    assert!(!app.get_local_configuration_busy());
    assert!(app.get_local_configuration().contains("Source SHA256:"));
    app.invoke_local_configuration_requested(
        1,
        source.to_str().expect("source path").into(),
        destination.to_str().expect("candidate path").into(),
        binding.clone(),
        1,
    );
    assert!(app.get_local_configuration_busy());
    view.state.borrow_mut().apply_native(
        observed
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("actual candidate"),
    );
    view.apply(&app);
    assert!(
        app.get_local_configuration()
            .contains("Candidate created and read back")
    );
    assert!(app.get_local_configuration().contains("not applied"));
    assert!(!app.get_local_configuration().contains("SLINT_NOT_RESOLVED"));
    let candidate = claw_platform::configuration::inspect_provider(&destination)
        .expect("actual candidate file");
    assert_eq!(
        candidate
            .snapshot
            .core()
            .provider()
            .expect("provider")
            .model(),
        Some("model-1")
    );
    assert_eq!(
        std::fs::read_to_string(&source).expect("unchanged source"),
        original
    );
    view.state.borrow_mut().native_unavailable();
    view.apply(&app);
    let rejected = root.0.join("stale.json5");
    app.invoke_local_configuration_requested(
        1,
        source.to_str().expect("path").into(),
        rejected.to_str().expect("path").into(),
        binding,
        1,
    );
    assert!(!app.get_local_configuration_busy());
    assert!(!rejected.exists());
    assert!(observed.try_recv().is_err());
    assert!(app.get_local_configuration().contains("Candidate created"));
    controller.shutdown().expect("local work drained");
}

#[test]
fn native_model_catalogue_renders_cached_metadata_and_control_states_at_two_sizes() {
    use crate::controller::{ProductConnection, ProductUpdate};
    use serde_json::json;
    let software_window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(SoftwarePlatform {
        window: software_window.clone(),
        started: Instant::now(),
    }))
    .expect("model renderer");
    let app = AppWindow::new().expect("model component tree");
    let view = crate::ProductView::attach(&app, crate::product_state::ProductState::native())
        .expect("native view");
    let connection = ProductConnection {
        generation: 0,
        epoch: 1,
    };
    view.state
        .borrow_mut()
        .apply_native(ProductUpdate::Ready { connection });
    view.state
        .borrow_mut()
        .select_destination(crate::product_state::PrimaryDestination::Settings);
    view.state.borrow_mut().select_settings_section(1);
    app.set_workspace_ready(true);
    view.apply(&app);
    app.show().expect("headless models tree");
    let params = view
        .state
        .borrow()
        .native_model_catalogue(0)
        .expect("cache read");
    view.state
        .borrow_mut()
        .native_model_catalogue_enqueued(&params);
    view.apply(&app);
    assert!(
        !app.get_can_read_models() && !app.get_can_next_models() && !app.get_can_refresh_models()
    );
    let mut page = json!({"schemaVersion":1,"available":true,"offset":0,"endOffset":8,"nextOffset":8,"totalModels":9,"sha256":"a".repeat(64),
        "provider":"fixture","providerGeneration":1,"selectedModel":"fixture-model-0","selectionPinned":true,"observedAtMs":123,
        "source":"provider_sdk_catalogue","liveCapabilitiesVerified":false,"selectionChanged":false,"networkContacted":false,
        "models":(0..8).map(|ordinal|json!({"id":if ordinal == 7 {format!("{}MODEL-ID-END","x".repeat(240))} else {format!("fixture-model-{ordinal}")},"displayName":format!("{} model {ordinal}","\u{754c}".repeat(30)),
            "contextWindow":null,"maxOutputTokens":1024,"advertisedCapabilities":["completion"]})).collect::<Vec<_>>()});
    page["models"][0]["aliases"] = json!(["work", format!("{}ALIAS-END", "a".repeat(240))]);
    let cached_page = page.clone();
    view.state
        .borrow_mut()
        .apply_native(ProductUpdate::Response {
            connection,
            method: "models.list",
            params,
            payload: page,
        });
    let expected = view.state.borrow().model_catalogue_text();
    assert!(expected.contains("Selected: fixture-model-0 (pinned)"));
    assert!(expected.contains("Alias (config): work") && expected.contains("ALIAS-END"));
    assert!(
        expected.contains("Context: not reported")
            && expected.contains("Live capabilities: unverified")
    );
    for (width, height) in [(1080_u16, 720_u16), (720, 520)] {
        app.set_layout_width(f32::from(width));
        software_window.set_size(slint::PhysicalSize::new(
            u32::from(width),
            u32::from(height),
        ));
        app.set_model_catalogue("".into());
        let empty = render(&software_window, usize::from(width), usize::from(height));
        view.apply(&app);
        assert_eq!(app.get_model_catalogue().as_str(), expected);
        assert!(
            app.get_can_read_models() && app.get_can_next_models() && app.get_can_refresh_models()
        );
        let populated = render(&software_window, usize::from(width), usize::from(height));
        assert!(
            changed_pixel_count(&empty, &populated) > 1000,
            "{width}x{height}: actual metadata rendered"
        );
        app.set_can_read_models(false);
        app.set_can_next_models(false);
        app.set_can_refresh_models(false);
        let disabled = render(&software_window, usize::from(width), usize::from(height));
        assert!(
            changed_pixel_count(&populated, &disabled) > 8,
            "{width}x{height}: controls visibly change"
        );
        view.apply(&app);
        app.set_local_configuration_open(true);
        app.set_local_model_index(7);
        app.set_local_configuration(
            "Source verified\nSaved model: fixture-model-0\nCandidate not applied".into(),
        );
        let editor = render(&software_window, usize::from(width), usize::from(height));
        assert!(
            changed_pixel_count(&populated, &editor) > 1000,
            "{width}x{height}: local editor replaces catalogue"
        );
        assert_eq!(app.get_model_choices().row_count(), 8);
        assert_eq!(app.get_local_model_index(), 7);
        assert!(
            app.get_model_choices()
                .row_data(7)
                .expect("long exact ID")
                .ends_with("MODEL-ID-END")
        );
        assert!(!app.get_model_choice_binding().is_empty());
        app.set_local_configuration_busy(true);
        let busy = render(&software_window, usize::from(width), usize::from(height));
        assert!(
            changed_pixel_count(&editor, &busy) > 8,
            "{width}x{height}: local fields visibly disable"
        );
        app.set_local_configuration_open(false);
        app.set_model_choice_binding("replaced-while-editor-closed".into());
        render(&software_window, usize::from(width), usize::from(height));
        assert_eq!(
            app.get_local_model_index(),
            -1,
            "hidden editor must discard a stale choice"
        );
        view.apply(&app);
    }
    for (age, limit) in [
        (Some(1), Some(1000)),
        (Some(1000), Some(1000)),
        (None, Some(1000)),
        (Some(90_000), None),
    ] {
        let freshness = claw_protocol::native_models::CatalogueFreshness::new(age, limit)
            .expect("cache policy");
        let mut payload = cached_page.clone();
        payload["cacheFreshness"] = json!(freshness);
        let params = view
            .state
            .borrow()
            .native_model_catalogue(3)
            .expect("cache status query");
        view.state
            .borrow_mut()
            .native_model_catalogue_enqueued(&params);
        view.state
            .borrow_mut()
            .apply_native(ProductUpdate::Response {
                connection,
                method: "models.list",
                params,
                payload,
            });
        for (width, height) in [(1080_u16, 720_u16), (720, 520)] {
            app.set_layout_width(f32::from(width));
            software_window.set_size(slint::PhysicalSize::new(
                u32::from(width),
                u32::from(height),
            ));
            app.set_model_catalogue("".into());
            let empty = render(&software_window, usize::from(width), usize::from(height));
            view.apply(&app);
            assert!(
                app.get_model_catalogue()
                    .contains(freshness.to_string().as_str())
            );
            assert!(app.get_can_read_models() && app.get_can_refresh_models());
            assert_eq!(app.get_model_choices().row_count(), 8);
            let populated = render(&software_window, usize::from(width), usize::from(height));
            assert!(
                changed_pixel_count(&empty, &populated) > 1000,
                "{width}x{height}: cache state is visible"
            );
        }
    }
    for reason in [
        claw_protocol::native_models::CatalogueUnavailableReason::Disabled,
        claw_protocol::native_models::CatalogueUnavailableReason::AuthenticationPending,
        claw_protocol::native_models::CatalogueUnavailableReason::NotInitialized,
        claw_protocol::native_models::CatalogueUnavailableReason::Retired,
    ] {
        let params = view
            .state
            .borrow()
            .native_model_catalogue(3)
            .expect("status query");
        view.state
            .borrow_mut()
            .native_model_catalogue_enqueued(&params);
        view.state.borrow_mut().apply_native(ProductUpdate::Response {
            connection, method: "models.list", params,
            payload: json!({"schemaVersion":1,"available":false,"selectionChanged":false,"networkContacted":false,"unavailableReason":reason}),
        });
        for (width, height) in [(1080_u16, 720_u16), (720, 520)] {
            app.set_layout_width(f32::from(width));
            software_window.set_size(slint::PhysicalSize::new(
                u32::from(width),
                u32::from(height),
            ));
            app.set_model_catalogue("".into());
            let empty = render(&software_window, usize::from(width), usize::from(height));
            view.apply(&app);
            assert_eq!(app.get_model_catalogue().as_str(), reason.to_string());
            assert!(
                app.get_can_read_models()
                    && !app.get_can_next_models()
                    && !app.get_can_refresh_models()
            );
            assert!(app.get_model_choice_binding().is_empty());
            assert_eq!(app.get_model_choices().row_count(), 0);
            let populated = render(&software_window, usize::from(width), usize::from(height));
            assert!(
                changed_pixel_count(&empty, &populated) > 100,
                "{width}x{height}: {reason}"
            );
        }
    }
    view.state.borrow_mut().native_unavailable();
    view.apply(&app);
    assert_eq!(app.get_model_catalogue(), "Gateway disconnected");
    assert!(
        !app.get_can_read_models() && !app.get_can_next_models() && !app.get_can_refresh_models()
    );
    app.hide().expect("hide models tree");
}

#[test]
fn native_accounting_renders_from_bound_state_at_narrow_and_wide_sizes() {
    let software_window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(SoftwarePlatform {
        window: software_window.clone(),
        started: Instant::now(),
    }))
    .expect("isolated accounting renderer");
    let app = AppWindow::new().expect("native accounting component tree");
    let view = crate::ProductView::attach(&app, crate::product_state::ProductState::native())
        .expect("native view");
    let connection = crate::controller::ProductConnection {
        generation: 0,
        epoch: 1,
    };
    view.state
        .borrow_mut()
        .apply_native(crate::controller::ProductUpdate::Ready { connection });
    app.set_workspace_ready(true);
    app.set_selected_screen(7);
    app.show().expect("headless accounting tree");
    for (index, scenario) in ["missing", "zero", "journal"].into_iter().enumerate() {
        let mut accounting = serde_json::json!({
            "available":true,"recordedRounds":1,"completeCounterRounds":1,
            "partialCounterRounds":0,"unreportedRounds":0,"allPrimaryCountersReported":true,
            "observedTokens":{"inputTokens":0,"outputTokens":0,"totalTokens":0,"cachedInputTokens":0,"reasoningTokens":0},
            "aggregationOverflow":false,"costCalculated":false,"billingReconciled":false,
            "recordSource":"terminal_turn","attemptsMayBeUnsent":true,
        });
        if scenario == "missing" {
            accounting = serde_json::Value::Null;
        } else if scenario == "journal" {
            accounting["recordedRounds"] = serde_json::json!(17);
            accounting["unreportedRounds"] = serde_json::json!(16);
            accounting["recordSource"] = serde_json::json!("provider_journal");
            accounting["journalRevision"] = serde_json::json!(2);
            accounting["journalClosed"] = serde_json::json!(false);
            accounting["completeCounterRounds"] = serde_json::json!(0);
            accounting["partialCounterRounds"] = serde_json::json!(1);
            accounting["allPrimaryCountersReported"] = serde_json::json!(false);
        }
        let run = format!("{index:064x}");
        view.state.borrow_mut().apply_native(crate::controller::ProductUpdate::Response {
            connection, method: "agent.wait", params: serde_json::json!({"runId":run}),
            payload: serde_json::json!({"runId":run,"sessionId":"native-session","phase":"outcome_unknown","status":"outcome_unknown","turn":index+1,"revision":4,"durable":true,"result":{"status":"outcome_unknown","text":"Retained run status"},"providerAccounting":accounting}),
        });
        if scenario == "journal" {
            let params = view
                .state
                .borrow()
                .native_accounting(false)
                .expect("readable accounting");
            view.state.borrow_mut().native_accounting_enqueued(&params);
            view.apply(&app);
            assert!(!app.get_can_read_accounting() && !app.get_can_next_accounting());
            let rounds = (0..16).map(|round| serde_json::json!({"round":round,"response":if round == 0 {
                serde_json::json!({"provider":"renderer-provider","model":"renderer-model","responseId":"renderer-response",
                    "usageReporting":"partial","finishReason":"length","observedTokens":{"inputTokens":0,"outputTokens":0,"totalTokens":0,"cachedInputTokens":0,"reasoningTokens":0}})
            } else {serde_json::Value::Null}})).collect::<Vec<_>>();
            view.state.borrow_mut().apply_native(crate::controller::ProductUpdate::Response {
                connection,method:"agent.wait",params,
                payload:serde_json::json!({"runId":run,"sessionId":"native-session","revision":4,"turn":index+1,"status":"outcome_unknown",
                    "durable":true,"acknowledged":false,"automaticReplay":false,"accounting":{"available":true,"offset":0,"endOffset":16,"nextOffset":16,
                        "totalRounds":17,"sha256":"b".repeat(64),"summary":accounting,"rounds":rounds}}),
            });
        }
        let expected = view.state.borrow().accounting_summary();
        assert!(expected.contains("Billing: unreconciled"));
        if scenario == "missing" {
            assert!(expected.contains("Tokens: unknown"));
        } else if scenario == "zero" {
            assert!(expected.contains("Tokens (complete): 0"));
        } else {
            assert!(expected.contains("Tokens (partial): 0"));
            assert!(expected.contains("journal r2 (open)"));
            assert!(expected.contains("renderer-response"));
            assert!(expected.contains("Round 1: report unavailable; delivery unknown"));
        }
        for (width, height) in [(1080_u16, 720_u16), (720, 520)] {
            app.set_layout_width(f32::from(width));
            software_window.set_size(slint::PhysicalSize::new(
                u32::from(width),
                u32::from(height),
            ));
            app.set_provider_accounting("".into());
            let empty = render(&software_window, usize::from(width), usize::from(height));
            view.apply(&app);
            assert_eq!(app.get_provider_accounting().as_str(), expected);
            assert!(app.get_can_read_accounting());
            assert_eq!(app.get_can_next_accounting(), scenario == "journal");
            let populated = render(&software_window, usize::from(width), usize::from(height));
            assert!(
                changed_pixel_count(&empty, &populated) > 1_000,
                "{scenario} {width}x{height}"
            );
            assert!(
                populated
                    .iter()
                    .filter(|pixel| **pixel != RgbPixel::default())
                    .count()
                    > 10_000
            );
            app.set_can_read_accounting(false);
            app.set_can_next_accounting(false);
            let disabled = render(&software_window, usize::from(width), usize::from(height));
            assert!(
                changed_pixel_count(&populated, &disabled) > 8,
                "accounting controls are visible at {width}x{height}"
            );
            view.apply(&app);
        }
    }
    view.state.borrow_mut().native_unavailable();
    view.apply(&app);
    assert!(app.get_provider_accounting().is_empty());
    assert!(!app.get_can_read_accounting() && !app.get_can_next_accounting());
    app.hide().expect("hide software accounting tree");
}

#[test]
fn native_memory_form_renders_at_narrow_and_wide_sizes_and_closes_on_binding_change() {
    let software_window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(SoftwarePlatform {
        window: software_window.clone(),
        started: Instant::now(),
    }))
    .expect("isolated memory software renderer");
    let app = AppWindow::new().expect("native memory component tree");
    let view = crate::ProductView::attach(&app, crate::product_state::ProductState::native())
        .expect("native view");
    view.state
        .borrow_mut()
        .apply_native(crate::controller::ProductUpdate::Ready {
            connection: crate::controller::ProductConnection {
                generation: 0,
                epoch: 1,
            },
        });
    view.apply(&app);
    app.set_workspace_ready(true);
    app.set_selected_screen(7);
    app.show().expect("headless memory tree");
    for (width, height) in [(1080_u16, 720_u16), (720, 520)] {
        app.set_layout_width(f32::from(width));
        software_window.set_size(slint::PhysicalSize::new(
            u32::from(width),
            u32::from(height),
        ));
        app.set_memory_open(false);
        let closed = render(&software_window, width as usize, height as usize);
        app.set_memory_open(true);
        let opened = render(&software_window, width as usize, height as usize);
        assert!(app.get_memory_open());
        assert!(changed_pixel_count(&closed, &opened) > 1_000);
        assert!(
            opened
                .iter()
                .filter(|pixel| **pixel != RgbPixel::default())
                .count()
                > 10_000
        );
        let text = format!(
            "{{\"content\":\"{}\",\"revision\":9}}",
            "\u{4e2d}\u{6587} ".repeat(500)
        );
        app.set_memory_result(text.as_str().into());
        let _ = render(&software_window, width as usize, height as usize);
        assert_eq!(app.get_memory_result().as_str(), text);
    }
    app.set_memory_binding("0:2:another-session".into());
    let _ = render(&software_window, 720, 520);
    assert!(!app.get_memory_open());
    app.hide().expect("hide software memory tree");
}

#[test]
fn native_product_empty_history_and_complete_approval_render_without_demo_data() {
    let software_window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(SoftwarePlatform {
        window: software_window.clone(),
        started: Instant::now(),
    }))
    .expect("isolated native software renderer");
    let app = AppWindow::new().expect("native component tree");
    let view = crate::ProductView::attach(&app, crate::product_state::ProductState::native())
        .expect("native product view");
    view.apply(&app);
    assert_eq!(app.get_transcript().row_count(), 0);
    assert_eq!(app.get_workspaces().row_count(), 0);
    assert_eq!(app.get_deliverables().row_count(), 0);
    assert!(!app.get_can_approve());
    app.set_workspace_ready(true);
    app.set_layout_width(1080.0);
    software_window.set_size(slint::PhysicalSize::new(1080, 720));
    app.show().expect("headless native view");
    let empty = render(&software_window, 1080, 720);
    assert!(
        empty
            .iter()
            .filter(|pixel| **pixel != RgbPixel::default())
            .count()
            > 10_000
    );
    let connection = crate::controller::ProductConnection {
        generation: 0,
        epoch: 1,
    };
    view.state
        .borrow_mut()
        .apply_native(crate::controller::ProductUpdate::Ready { connection });
    view.state.borrow_mut().apply_native(crate::controller::ProductUpdate::Response {
        connection,
        method: "exec.approval.get",
        params: serde_json::json!({"id": "approval-1"}),
        payload: serde_json::json!({"id": "approval-1", "sessionId": "native-session", "previewComplete": true, "redacted": true, "prompt": "write-file\n{\"path\":\"example.txt\",\"apiKey\":\"[REDACTED]\"}"}),
    });
    view.apply(&app);
    assert!(app.get_can_approve());
    assert!(app.get_approval_prompt().contains("example.txt"));
    let approval = render(&software_window, 1080, 720);
    assert!(changed_pixel_count(&empty, &approval) > 100);
    app.set_layout_width(720.0);
    software_window.set_size(slint::PhysicalSize::new(720, 520));
    let narrow = render(&software_window, 720, 520);
    assert!(
        narrow
            .iter()
            .filter(|pixel| **pixel != RgbPixel::default())
            .count()
            > 10_000
    );
    app.hide().expect("hide headless native view");
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
        location: "No trusted path loaded".into(),
        kind: "Preview workspace".into(),
        branch: "Workspace trust is not composed".into(),
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
    app.set_status_text("Connected".into());
    app.set_status_label("Gateway status".into());
    app.set_status_icon("OK".into());
    app.set_status_kind(StatusKind::Success);
    app.set_server_summary("Gateway test fixture".into());
    app.set_role_summary("operator".into());
    app.set_scopes_summary("operator.read".into());
    app.set_health_summary("Health RPC returned ok=true".into());
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
    app.set_workspace_ready(false);
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

//! Native Gateway onboarding with Slint retaining ownership of the main thread.

#[cfg(any(target_os = "windows", target_os = "macos"))]
mod command_palette;
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod controller;
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod onboarding;
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod product_state;
#[cfg(all(test, any(target_os = "windows", target_os = "macos")))]
mod software_renderer_smoke;
#[cfg(all(test, any(target_os = "windows", target_os = "macos")))]
mod test_gateway;
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod ui_adapter;
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod ui_models;

#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::cell::RefCell;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::error::Error;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::fmt::{self, Display, Formatter};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::rc::Rc;

#[cfg(any(target_os = "windows", target_os = "macos"))]
use command_palette::{CommandPaletteState, PaletteAction, PaletteCatalogError};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use controller::{
    CommandRejection, ControllerSender, ControllerShutdownError, ControllerStartError,
    DesktopController,
};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use onboarding::{ConnectRequest, UiStatusKind, UserError, ViewSnapshot};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use product_state::{
    ChangeKind, DiffMode, OnboardingStage, PrimaryDestination, ProductState, RunState,
    SemanticTone, TranscriptRole, render_side_by_side, render_unified,
};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use slint::{CloseRequestResponse, ComponentHandle, Model};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use ui_adapter::{PreferenceLifetime, UiTheme, VisualPreferencesState};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use ui_models::{ProductModels, reconcile};

#[cfg(any(target_os = "windows", target_os = "macos"))]
#[expect(
    unreachable_pub,
    reason = "slint::include_modules! emits `pub` items that stay crate-private behind this module"
)]
mod generated_ui {
    slint::include_modules!();
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
use generated_ui::{
    ActivityItem, AppWindow, DeliverableItem, DiffItem, ExtensionItem, FileItem, RunItem,
    ScheduleItem, StatusKind, ThemeMode, TranscriptItem, VisualPreferences, WorkspaceItem,
};

#[cfg(any(target_os = "windows", target_os = "macos"))]
const fn retain_explicit_preview(currently_open: bool, diagnostic_ready: bool) -> bool {
    currently_open && diagnostic_ready
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn apply_snapshot(window: &AppWindow, snapshot: &ViewSnapshot) {
    window.set_state_title(snapshot.title().into());
    window.set_state_detail(snapshot.detail().into());
    window.set_status_text(snapshot.status_text().into());
    window.set_status_label(snapshot.status_label().into());
    window.set_status_icon(snapshot.status_icon().into());
    window.set_status_kind(status_kind(snapshot.status_kind()));
    window.set_endpoint_summary(snapshot.endpoint().into());
    window.set_server_summary(snapshot.server().into());
    window.set_protocol_summary(snapshot.protocol().into());
    window.set_role_summary(snapshot.role().into());
    window.set_scopes_summary(snapshot.scopes().into());
    window.set_health_summary(snapshot.health().into());
    window.set_identity_summary(snapshot.identity().into());
    window.set_busy(snapshot.busy());
    window.set_can_connect(snapshot.can_connect());
    window.set_can_cancel(snapshot.can_cancel());
    window.set_can_disconnect(snapshot.can_disconnect());
    window.set_can_retry(snapshot.can_retry());
    window.set_product_preview_open(retain_explicit_preview(
        window.get_product_preview_open(),
        snapshot.can_disconnect(),
    ));
    if !snapshot.can_disconnect() {
        window.set_palette_open(false);
    }
    if snapshot.reset_consent() {
        window.set_consent_checked(false);
    }
    if let Some(error) = snapshot.error() {
        apply_error(window, error);
    } else {
        clear_error(window);
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
const fn tone_index(tone: SemanticTone) -> i32 {
    match tone {
        SemanticTone::Neutral => 0,
        SemanticTone::Info => 1,
        SemanticTone::Warning => 2,
        SemanticTone::Danger => 3,
        SemanticTone::Success => 4,
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
const fn change_kind_index(kind: ChangeKind) -> i32 {
    match kind {
        ChangeKind::Context => 0,
        ChangeKind::Added => 1,
        ChangeKind::Removed => 2,
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn line_number(number: Option<u32>) -> slint::SharedString {
    number.map_or_else(slint::SharedString::default, |value| {
        value.to_string().into()
    })
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn apply_product_state(window: &AppWindow, models: &ProductModels, state: &ProductState) {
    debug_assert_eq!(ProductState::keyboard_order().len(), 10);
    debug_assert_eq!(ProductState::accessibility_nodes().len(), 4);
    window.set_onboarding_stage(state.onboarding_stage().index());
    window.set_selected_screen(state.surface().screen_index());
    window.set_selected_settings_section(
        i32::try_from(state.selected_settings_section()).unwrap_or(i32::MAX),
    );
    window.set_palette_open(state.palette_open());
    window.set_product_interactions_enabled(state.interactions_enabled());
    window.set_diff_mode(match state.diff_mode() {
        DiffMode::Unified => 0,
        DiffMode::SideBySide => 1,
    });
    let selected_run = state.selected_run();
    window.set_session_title(selected_run.title.as_str().into());
    window.set_session_state(selected_run.state.label().into());
    window
        .set_session_detail(format!("{} · {}", selected_run.workspace, selected_run.detail).into());
    window.set_session_tone(tone_index(selected_run.state.tone()));
    window.set_can_approve(selected_run.state == RunState::WaitingForApproval);
    window.set_can_answer(selected_run.state == RunState::WaitingForAnswer);
    window.set_approval_prompt(state.approval_prompt().into());
    window.set_approval_scope(state.approval_scope().into());
    window.set_question(state.question().into());
    let dashboard = state.dashboard_counts();
    window.set_dashboard_awaiting_review(
        i32::try_from(dashboard.awaiting_review).unwrap_or(i32::MAX),
    );
    window.set_dashboard_running(i32::try_from(dashboard.running).unwrap_or(i32::MAX));
    window.set_dashboard_blocked(i32::try_from(dashboard.blocked).unwrap_or(i32::MAX));
    window.set_dashboard_workspaces(i32::try_from(dashboard.workspaces).unwrap_or(i32::MAX));

    reconcile(
        models.runs(),
        state.runs().visible().iter().map(|run| RunItem {
            id: run.id.as_str().into(),
            title: run.title.as_str().into(),
            workspace: run.workspace.as_str().into(),
            state: run.state.label().into(),
            detail: run.detail.as_str().into(),
            updated: run.updated.as_str().into(),
            tone: tone_index(run.state.tone()),
        }),
    );

    reconcile(
        models.workspaces(),
        state.workspaces().iter().map(|workspace| WorkspaceItem {
            name: workspace.name.as_str().into(),
            location: workspace.location.as_str().into(),
            kind: workspace.kind.as_str().into(),
            branch: workspace.branch.as_str().into(),
            active_runs: i32::try_from(state.workspace_active_runs(&workspace.name))
                .unwrap_or(i32::MAX),
        }),
    );

    reconcile(
        models.schedules(),
        state.schedules().iter().map(|schedule| ScheduleItem {
            name: schedule.name.as_str().into(),
            cadence: schedule.cadence.as_str().into(),
            next_run: schedule.next_run.as_str().into(),
            enabled: schedule.enabled,
            configured: schedule.is_configured(),
            state: schedule.state_label().into(),
            can_toggle: state.interactions_enabled() && schedule.is_configured(),
            workspace: schedule.workspace.as_str().into(),
        }),
    );

    reconcile(
        models.deliverables(),
        state
            .deliverables()
            .iter()
            .map(|deliverable| DeliverableItem {
                name: deliverable.name.as_str().into(),
                kind: deliverable.kind.as_str().into(),
                source: deliverable.source.as_str().into(),
                size: deliverable.size.as_str().into(),
                pinned: deliverable.pinned,
            }),
    );
    let selected_deliverable = state.selected_deliverable();
    window.set_selected_deliverable_index(
        i32::try_from(state.selected_deliverable_index()).unwrap_or(i32::MAX),
    );
    window.set_selected_deliverable_name(selected_deliverable.name.as_str().into());
    window.set_selected_deliverable_kind(selected_deliverable.kind.as_str().into());
    window.set_selected_deliverable_source(selected_deliverable.source.as_str().into());
    window.set_selected_deliverable_size(selected_deliverable.size.as_str().into());
    window.set_selected_deliverable_content(state.selected_deliverable_content().into());
    window.set_selected_deliverable_pinned(selected_deliverable.pinned);

    reconcile(
        models.extensions(),
        state.extensions().iter().map(|extension| ExtensionItem {
            name: extension.name.as_str().into(),
            category: extension.category.as_str().into(),
            detail: extension.detail.as_str().into(),
            permission: extension.permission.as_str().into(),
            enabled: extension.enabled,
        }),
    );

    reconcile(
        models.transcript(),
        state.transcript().iter().map(|entry| TranscriptItem {
            role: entry.role.label().into(),
            text: entry.text.as_str().into(),
            detail: entry.detail.as_str().into(),
            timestamp: entry.timestamp.as_str().into(),
            tone: match entry.role {
                TranscriptRole::User | TranscriptRole::Activity => 0,
                TranscriptRole::Assistant => 1,
                TranscriptRole::System => 2,
            },
        }),
    );

    reconcile(
        models.activity(),
        state.activity().iter().map(|entry| ActivityItem {
            title: entry.title.as_str().into(),
            detail: entry.detail.as_str().into(),
            state: entry.state.label().into(),
            duration: entry.duration.as_str().into(),
            tone: tone_index(entry.state.tone()),
        }),
    );

    reconcile(
        models.session_files(),
        state.session_files().iter().map(|file| FileItem {
            name: file.name.as_str().into(),
            status: file.status.as_str().into(),
        }),
    );
    window.set_selected_file_index(i32::try_from(state.selected_file_index()).unwrap_or(i32::MAX));
    window.set_selected_file_name(state.selected_file_name().into());

    match state.diff_mode() {
        DiffMode::Unified => reconcile(
            models.diff_lines(),
            state
                .diff()
                .iter()
                .zip(render_unified(state.diff()))
                .map(|(line, text)| {
                    let text_column: slint::SharedString = line.text.as_str().into();
                    DiffItem {
                        old_line: line_number(line.old_line),
                        new_line: line_number(line.new_line),
                        text: text.into(),
                        old_text: text_column.clone(),
                        new_text: text_column,
                        kind: change_kind_index(line.kind),
                    }
                }),
        ),
        DiffMode::SideBySide => reconcile(
            models.diff_lines(),
            render_side_by_side(state.diff())
                .into_iter()
                .map(|line| DiffItem {
                    old_line: line_number(line.old_line),
                    new_line: line_number(line.new_line),
                    text: slint::SharedString::default(),
                    old_text: line.old_text.into(),
                    new_text: line.new_text.into(),
                    kind: change_kind_index(line.kind),
                }),
        ),
    }

    let page_count = state.runs().page_count();
    window.set_run_page_label(
        format!(
            "Page {} of {} · {} runs per page",
            state.runs().page() + 1,
            page_count,
            state.runs().page_size()
        )
        .into(),
    );
    window.set_can_previous_run_page(state.runs().page() > 0);
    window.set_can_next_run_page(state.runs().page() + 1 < page_count);
}

/// The product screens and the Rust state they render, bound together so a
/// callback only has to carry one handle.
#[cfg(any(target_os = "windows", target_os = "macos"))]
struct ProductView {
    models: ProductModels,
    state: RefCell<ProductState>,
    palette: RefCell<CommandPaletteState>,
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
impl ProductView {
    fn attach(window: &AppWindow, state: ProductState) -> Result<Self, PaletteCatalogError> {
        let palette = CommandPaletteState::new(window.get_command_catalog().iter())?;
        Ok(Self {
            models: ProductModels::attach(window),
            state: RefCell::new(state),
            palette: RefCell::new(palette),
        })
    }

    fn apply(&self, window: &AppWindow) {
        apply_product_state(window, &self.models, &self.state.borrow());
        self.apply_palette(window);
    }

    fn apply_palette(&self, window: &AppWindow) {
        let palette = self.palette.borrow();
        let visible = palette.visible_items().collect::<Vec<_>>();
        let selected = visible.get(palette.selected_index());
        let selected_action_id = selected.map_or(-1, |command| command.action_id);
        let selected_label = selected
            .map(|command| command.title.clone())
            .unwrap_or_default();
        let command_count = i32::try_from(visible.len()).unwrap_or(i32::MAX);
        reconcile(self.models.palette_commands(), visible);
        window.set_palette_selected_index(
            i32::try_from(palette.selected_index()).unwrap_or(i32::MAX),
        );
        window.set_palette_command_count(command_count);
        window.set_palette_selected_action_id(selected_action_id);
        window.set_palette_selected_label(selected_label);
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn mutate_product(
    weak_window: &slint::Weak<AppWindow>,
    view: &ProductView,
    update: impl FnOnce(&mut ProductState),
) {
    if view.state.borrow().palette_open() {
        return;
    }
    update(&mut view.state.borrow_mut());
    if let Some(window) = weak_window.upgrade() {
        view.apply(&window);
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn apply_palette_action(state: &mut ProductState, action: PaletteAction) {
    match action {
        PaletteAction::Focus => state.select_destination(PrimaryDestination::Focus),
        PaletteAction::Workspaces => state.select_destination(PrimaryDestination::Workspaces),
        PaletteAction::Runs => state.select_destination(PrimaryDestination::Runs),
        PaletteAction::Schedules => state.select_destination(PrimaryDestination::Schedules),
        PaletteAction::Deliverables => {
            state.select_destination(PrimaryDestination::Deliverables);
        }
        PaletteAction::Extensions => state.select_destination(PrimaryDestination::Extensions),
        PaletteAction::Settings => state.select_destination(PrimaryDestination::Settings),
        PaletteAction::KeyboardShortcuts => {
            state.select_settings_section(5);
            state.select_destination(PrimaryDestination::Settings);
        }
        PaletteAction::Update => state.open_update(),
        PaletteAction::Diagnostics => state.open_diagnostics(),
    }
    state.close_palette();
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn apply_error(window: &AppWindow, error: &UserError) {
    window.set_error_message(error.message().into());
    window.set_error_action(error.action().into());
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn clear_error(window: &AppWindow) {
    window.set_error_message("".into());
    window.set_error_action("".into());
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
const fn status_kind(kind: UiStatusKind) -> StatusKind {
    match kind {
        UiStatusKind::Neutral => StatusKind::Neutral,
        UiStatusKind::Success => StatusKind::Success,
        UiStatusKind::Warning => StatusKind::Warning,
        UiStatusKind::Danger => StatusKind::Danger,
        UiStatusKind::Info => StatusKind::Info,
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn apply_preferences(window: &AppWindow, preferences: VisualPreferencesState) {
    debug_assert_eq!(preferences.lifetime(), PreferenceLifetime::SessionOnly);
    window
        .global::<VisualPreferences>()
        .set_theme_override_active(preferences.theme_override_active());
    window.set_theme_mode(match preferences.theme() {
        UiTheme::Light => ThemeMode::Light,
        UiTheme::Dark => ThemeMode::Dark,
    });
    window.set_high_contrast(preferences.high_contrast());
    window.set_reduced_motion(preferences.reduced_motion());
    window.set_density_scale(preferences.density_scale());
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn enqueue_submission(
    weak_window: &slint::Weak<AppWindow>,
    sender: &ControllerSender,
    endpoint: &slint::SharedString,
    token: &slint::SharedString,
    consent: bool,
) {
    let submission = ConnectRequest::prepare(endpoint, token.to_string(), consent);
    let Some(window) = weak_window.upgrade() else {
        return;
    };

    // Destroying the editor also removes its private undo, selection, and preedit state.
    window.invoke_purge_token_input();
    let safe_endpoint = match &submission {
        Ok(request) => request.endpoint_input(),
        Err(rejection) => rejection.endpoint_input.as_deref().unwrap_or(""),
    };
    window.invoke_replace_endpoint_input(safe_endpoint.into());
    let result = match submission {
        Ok(request) => sender.connect(request),
        Err(rejection) => sender.reject_submission(rejection),
    };
    if let Err(rejection) = result {
        apply_error(&window, &rejection.user_error());
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn apply_command_result(window: &slint::Weak<AppWindow>, result: Result<(), CommandRejection>) {
    if let Err(rejection) = result
        && let Some(window) = window.upgrade()
    {
        apply_error(&window, &rejection.user_error());
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn handle_close_request(
    weak_window: &slint::Weak<AppWindow>,
    sender: &ControllerSender,
) -> CloseRequestResponse {
    if let Some(window) = weak_window.upgrade() {
        window.invoke_purge_token_input();
    }
    sender.close();
    CloseRequestResponse::HideWindow
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn wire_callbacks(
    window: &AppWindow,
    sender: ControllerSender,
    preferences: Rc<RefCell<VisualPreferencesState>>,
    product_view: &Rc<ProductView>,
) {
    let weak_window = window.as_weak();
    let callback_sender = sender.clone();
    window.on_connect_requested(move |endpoint, token, consent| {
        enqueue_submission(&weak_window, &callback_sender, &endpoint, &token, consent);
    });

    let weak_window = window.as_weak();
    let callback_sender = sender.clone();
    window.on_retry_requested(move |endpoint, token, consent| {
        enqueue_submission(&weak_window, &callback_sender, &endpoint, &token, consent);
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_preview_requested(move || {
        if let Some(window) = weak_window.upgrade() {
            if !window.get_can_disconnect() {
                apply_error(
                    &window,
                    &UserError::input(
                        "preview.diagnostic-required",
                        "The read-only product preview requires a completed Gateway diagnostic.",
                        "Finish the diagnostic, then choose Preview explicitly.",
                    ),
                );
                return;
            }
            view.state.borrow_mut().close_palette();
            view.palette.borrow_mut().reset();
            window.set_palette_query(slint::SharedString::default());
            window.set_palette_focused_command_index(-1);
            window.set_product_preview_open(true);
            view.apply(&window);
        }
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_preview_dismiss_requested(move || {
        if let Some(window) = weak_window.upgrade() {
            view.state.borrow_mut().close_palette();
            view.palette.borrow_mut().reset();
            window.set_palette_open(false);
            window.set_palette_query(slint::SharedString::default());
            window.set_palette_focused_command_index(-1);
            window.set_product_preview_open(false);
        }
    });

    let weak_window = window.as_weak();
    let callback_sender = sender.clone();
    window.on_cancel_requested(move || {
        apply_command_result(&weak_window, callback_sender.cancel());
    });

    let weak_window = window.as_weak();
    let callback_sender = sender.clone();
    window.on_disconnect_requested(move || {
        let result = callback_sender.disconnect();
        if result.is_ok()
            && let Some(window) = weak_window.upgrade()
        {
            window.set_palette_open(false);
            window.set_product_preview_open(false);
        }
        apply_command_result(&weak_window, result);
    });

    let weak_window = window.as_weak();
    window.on_error_dismiss_requested(move || {
        if let Some(window) = weak_window.upgrade() {
            clear_error(&window);
        }
    });

    let visual_preferences = window.global::<VisualPreferences>();
    let weak_window = window.as_weak();
    let callback_preferences = Rc::clone(&preferences);
    visual_preferences.on_theme_mode_requested(move |theme| {
        callback_preferences.borrow_mut().set_theme_override(match theme {
            ThemeMode::Light => UiTheme::Light,
            ThemeMode::Dark => UiTheme::Dark,
        });
        if let Some(window) = weak_window.upgrade() {
            apply_preferences(&window, *callback_preferences.borrow());
        }
    });

    let visual_preferences = window.global::<VisualPreferences>();
    let weak_window = window.as_weak();
    let callback_preferences = Rc::clone(&preferences);
    visual_preferences.on_follow_system_theme_requested(move |theme| {
        callback_preferences.borrow_mut().follow_system_theme(match theme {
            ThemeMode::Light => UiTheme::Light,
            ThemeMode::Dark => UiTheme::Dark,
        });
        if let Some(window) = weak_window.upgrade() {
            apply_preferences(&window, *callback_preferences.borrow());
        }
    });

    let weak_window = window.as_weak();
    let callback_preferences = Rc::clone(&preferences);
    visual_preferences.on_high_contrast_requested(move |enabled| {
        callback_preferences.borrow_mut().set_high_contrast(enabled);
        if let Some(window) = weak_window.upgrade() {
            apply_preferences(&window, *callback_preferences.borrow());
        }
    });

    let weak_window = window.as_weak();
    let callback_preferences = Rc::clone(&preferences);
    visual_preferences.on_reduced_motion_requested(move |enabled| {
        callback_preferences
            .borrow_mut()
            .set_reduced_motion(enabled);
        if let Some(window) = weak_window.upgrade() {
            apply_preferences(&window, *callback_preferences.borrow());
        }
    });

    let weak_window = window.as_weak();
    visual_preferences.on_density_scale_requested(move |scale| {
        preferences.borrow_mut().set_density_scale(scale);
        if let Some(window) = weak_window.upgrade() {
            apply_preferences(&window, *preferences.borrow());
        }
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_onboarding_stage_requested(move |index| {
        let stage = OnboardingStage::from_index(index)
            .expect("Slint onboarding stages must use a known index");
        mutate_product(&weak_window, &view, |product| {
            product.select_onboarding_stage(stage);
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_navigate_requested(move |index| {
        let destination = PrimaryDestination::from_index(index)
            .expect("Slint navigation must use a known destination index");
        mutate_product(&weak_window, &view, |product| {
            product.select_destination(destination);
            product.close_palette();
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_palette_toggle_requested(move || {
        let opening = !view.state.borrow().palette_open();
        if opening {
            view.palette.borrow_mut().reset();
        }
        view.state.borrow_mut().toggle_palette();
        if let Some(window) = weak_window.upgrade() {
            if opening {
                window.set_palette_query(slint::SharedString::default());
            }
            window.set_palette_focused_command_index(-1);
            view.apply(&window);
        }
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_palette_dismiss_requested(move || {
        if let Some(window) = weak_window.upgrade() {
            view.state.borrow_mut().close_palette();
            window.set_palette_focused_command_index(-1);
            view.apply(&window);
        }
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_palette_query_changed(move |query| {
        let changed = view.palette.borrow_mut().update_query(query.as_str());
        if changed && let Some(window) = weak_window.upgrade() {
            view.apply_palette(&window);
        }
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_palette_selection_step_requested(move |step| {
        view.palette.borrow_mut().move_selection(step);
        if let Some(window) = weak_window.upgrade() {
            view.apply_palette(&window);
        }
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_palette_selection_index_requested(move |index| {
        let changed = view.palette.borrow_mut().select_ui_focus_index(index);
        if changed && let Some(window) = weak_window.upgrade() {
            view.apply_palette(&window);
        }
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_palette_command_requested(move |action_id| {
        let action = PaletteAction::from_id(action_id)
            .expect("Slint palette commands must use a catalog action");
        view.palette.borrow_mut().reset();
        apply_palette_action(&mut view.state.borrow_mut(), action);
        if let Some(window) = weak_window.upgrade() {
            window.set_palette_query(slint::SharedString::default());
            window.set_palette_focused_command_index(-1);
            view.apply(&window);
        }
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_open_session_requested(move |index| {
        let index = usize::try_from(index).expect("Slint run indexes must be non-negative");
        mutate_product(&weak_window, &view, |product| {
            product.open_session(index);
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_open_workspace_requested(move |index| {
        let index = usize::try_from(index).expect("Slint workspace indexes must be non-negative");
        mutate_product(&weak_window, &view, |product| {
            if !product.open_workspace(index) {
                product.record_message(
                    TranscriptRole::System,
                    "Workspace could not be opened",
                    "The selected workspace has no associated run.",
                );
            }
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_settings_section_requested(move |index| {
        let index = usize::try_from(index).expect("Slint settings indexes must be non-negative");
        mutate_product(&weak_window, &view, |product| {
            product.select_settings_section(index);
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_update_requested(move || {
        mutate_product(&weak_window, &view, ProductState::open_update);
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_diagnostics_requested(move || {
        mutate_product(&weak_window, &view, ProductState::open_diagnostics);
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_back_requested(move || {
        mutate_product(&weak_window, &view, ProductState::return_from_auxiliary);
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_diff_mode_requested(move |mode| {
        let mode = match mode {
            0 => DiffMode::Unified,
            1 => DiffMode::SideBySide,
            _ => panic!("Slint diff modes must use a known index"),
        };
        mutate_product(&weak_window, &view, |product| {
            product.set_diff_mode(mode);
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_previous_run_page_requested(move || {
        mutate_product(&weak_window, &view, |product| {
            product.previous_run_page();
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_next_run_page_requested(move || {
        mutate_product(&weak_window, &view, |product| {
            product.next_run_page();
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_approval_requested(move |approved| {
        mutate_product(&weak_window, &view, |product| {
            match product.resolve_approval(approved) {
                Ok(run_state) => product.record_message(
                    TranscriptRole::System,
                    if approved {
                        "Approval granted"
                    } else {
                        "Approval denied"
                    },
                    format!("The run moved to {run_state}."),
                ),
                Err(error) => product.record_message(
                    TranscriptRole::System,
                    "Approval decision rejected",
                    error.to_string(),
                ),
            };
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_answer_requested(move |answer| {
        mutate_product(&weak_window, &view, |product| {
            match product.answer_question(answer.as_str()) {
                Ok(run_state) => {
                    product.record_message(
                        TranscriptRole::User,
                        answer.to_string(),
                        "Answer to the agent question",
                    );
                    product.record_message(
                        TranscriptRole::System,
                        "Answer recorded",
                        format!("The run moved to {run_state}."),
                    );
                }
                Err(error) => {
                    product.record_message(
                        TranscriptRole::System,
                        "Answer rejected",
                        error.to_string(),
                    );
                }
            };
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_message_submitted(move |message| {
        mutate_product(&weak_window, &view, |product| {
            product.record_message(
                TranscriptRole::User,
                message.to_string(),
                "Submitted from the session composer",
            );
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_file_selected(move |index| {
        let index = usize::try_from(index).expect("Slint file indexes must be non-negative");
        mutate_product(&weak_window, &view, |product| {
            product.select_session_file(index);
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_schedule_create_requested(move || {
        mutate_product(&weak_window, &view, |product| {
            product.create_schedule();
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_schedule_toggled(move |index| {
        let index = usize::try_from(index).expect("Slint schedule indexes must be non-negative");
        mutate_product(&weak_window, &view, |product| {
            product.toggle_schedule(index);
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_extension_toggled(move |index| {
        let index = usize::try_from(index).expect("Slint extension indexes must be non-negative");
        mutate_product(&weak_window, &view, |product| {
            product.toggle_extension(index);
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_deliverable_selected(move |index| {
        let index = usize::try_from(index).expect("Slint deliverable indexes must be non-negative");
        mutate_product(&weak_window, &view, |product| {
            product.select_deliverable(index);
        });
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_deliverable_pin_toggle_requested(move || {
        mutate_product(&weak_window, &view, |product| {
            product.toggle_selected_deliverable_pin();
        });
    });

    let weak_window = window.as_weak();
    let close_sender = sender;
    window
        .window()
        .on_close_requested(move || handle_close_request(&weak_window, &close_sender));
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn main() -> Result<(), DesktopError> {
    let window = AppWindow::new().map_err(DesktopError::Platform)?;
    let preferences = Rc::new(RefCell::new(VisualPreferencesState::default()));
    let product_view = Rc::new(
        ProductView::attach(&window, ProductState::default())
            .map_err(DesktopError::PaletteCatalog)?,
    );
    apply_preferences(&window, *preferences.borrow());
    product_view.apply(&window);
    let weak_window = window.as_weak();
    let controller = DesktopController::spawn(move |snapshot| {
        let _ = weak_window.upgrade_in_event_loop(move |window| apply_snapshot(&window, &snapshot));
    })
    .map_err(DesktopError::ControllerStart)?;
    wire_callbacks(&window, controller.sender(), preferences, &product_view);
    window.run().map_err(DesktopError::Platform)?;
    controller
        .shutdown()
        .map_err(DesktopError::ControllerShutdown)
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
#[derive(Debug)]
enum DesktopError {
    Platform(slint::PlatformError),
    ControllerStart(ControllerStartError),
    ControllerShutdown(ControllerShutdownError),
    PaletteCatalog(PaletteCatalogError),
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
impl Display for DesktopError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Platform(_) => "the desktop window could not complete its lifecycle",
            Self::ControllerStart(_) => "the desktop Gateway controller could not start",
            Self::ControllerShutdown(_) => {
                "the desktop Gateway controller could not stop within bounds"
            }
            Self::PaletteCatalog(_) => "the desktop command catalog is invalid",
        })
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
impl Error for DesktopError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            Self::ControllerStart(error) => Some(error),
            Self::ControllerShutdown(error) => Some(error),
            Self::PaletteCatalog(error) => Some(error),
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn main() {
    compile_error!("gta-claw-desktop supports only Windows and macOS");
}

#[cfg(all(test, any(target_os = "windows", target_os = "macos")))]
mod tests {
    #[cfg(target_os = "windows")]
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::onboarding::{AttemptUpdate, OnboardingModel};
    #[cfg(target_os = "windows")]
    use crate::onboarding::OnboardingPhase;

    #[cfg(target_os = "macos")]
    type GeneratedContract = fn(&AppWindow, ControllerSender, Rc<RefCell<VisualPreferencesState>>);

    fn exercise_generated_contracts(
        window: &AppWindow,
        sender: ControllerSender,
        preferences: Rc<RefCell<VisualPreferencesState>>,
    ) {
        apply_snapshot(window, &OnboardingModel::default().snapshot());
        let mut initial_product = ProductState::default();
        initial_product.select_onboarding_stage(OnboardingStage::GatewayConnection);
        let product_view =
            Rc::new(ProductView::attach(window, initial_product).expect("valid command catalog"));
        product_view.apply(window);
        assert!(!window.get_product_preview_open());
        assert!(!window.get_product_interactions_enabled());
        assert_eq!(window.get_dashboard_awaiting_review(), 10);
        assert_eq!(window.get_dashboard_running(), 10);
        assert_eq!(window.get_dashboard_blocked(), 10);
        assert_eq!(window.get_dashboard_workspaces(), 3);
        let paused_schedule = window
            .get_schedules()
            .row_data(2)
            .expect("preview includes configured paused schedule");
        assert!(!paused_schedule.enabled);
        assert!(paused_schedule.configured);
        assert_eq!(paused_schedule.state, "Paused");
        assert!(
            !paused_schedule.can_toggle,
            "preview action lock disables mutation without changing paused semantics"
        );

        let mut retained_identity = OnboardingModel::default();
        let retained_generation =
            retained_identity.begin("ws://localhost:18789/".to_owned());
        assert!(retained_identity.apply(
            retained_generation,
            AttemptUpdate::IdentityCreated("session-device".to_owned())
        ));
        assert!(retained_identity.apply(
            retained_generation,
            AttemptUpdate::Failed(UserError::input(
                "test.retry",
                "Retry remains available.",
                "Retry with the same identity.",
            ))
        ));
        window.set_consent_checked(true);
        apply_snapshot(window, &retained_identity.take_snapshot());
        assert!(window.get_consent_checked());

        let discarded_generation = retained_identity.start_disconnect();
        assert!(retained_identity.finish_disconnect(discarded_generation));
        apply_snapshot(window, &retained_identity.take_snapshot());
        assert!(!window.get_consent_checked());
        window.set_consent_checked(true);
        retained_identity.reject_submission(
            None,
            UserError::input(
                "test.invalid-endpoint",
                "The rechecked submission is invalid.",
                "Correct the address and retry.",
            ),
        );
        apply_snapshot(window, &retained_identity.take_snapshot());
        assert!(
            window.get_consent_checked(),
            "a later invalid submission must not replay a consumed consent reset"
        );

        wire_callbacks(window, sender, preferences, &product_view);
        window
            .global::<VisualPreferences>()
            .invoke_density_scale_requested(f32::NAN);
        assert!(window.get_density_scale().is_finite());
        assert_eq!(window.get_density_scale().to_bits(), 1.0_f32.to_bits());
        window
            .global::<VisualPreferences>()
            .invoke_density_scale_requested(f32::INFINITY);
        assert_eq!(window.get_density_scale().to_bits(), 2.0_f32.to_bits());
        window
            .global::<VisualPreferences>()
            .invoke_density_scale_requested(1.0);
        let selected_palette_index = window.get_palette_selected_index();
        for invalid_index in [-1, i32::MIN, 10, 999, i32::MAX] {
            window.invoke_palette_selection_index_requested(invalid_index);
            assert_eq!(
                window.get_palette_selected_index(),
                selected_palette_index,
                "invalid or stale palette focus input must be ignored"
            );
        }
        window.invoke_palette_toggle_requested();
        assert!(window.get_palette_open());
        let modal_state = product_view.state.borrow().clone();
        window.invoke_navigate_requested(1);
        window.invoke_open_session_requested(0);
        window.invoke_open_workspace_requested(0);
        window.invoke_settings_section_requested(3);
        window.invoke_update_requested();
        window.invoke_diagnostics_requested();
        window.invoke_back_requested();
        window.invoke_diff_mode_requested(1);
        window.invoke_next_run_page_requested();
        window.invoke_previous_run_page_requested();
        window.invoke_approval_requested(true);
        window.invoke_answer_requested("Pause run".into());
        window.invoke_message_submitted("blocked modal message".into());
        window.invoke_file_selected(1);
        window.invoke_schedule_create_requested();
        window.invoke_schedule_toggled(0);
        window.invoke_extension_toggled(0);
        window.invoke_deliverable_selected(1);
        window.invoke_deliverable_pin_toggle_requested();
        assert_eq!(
            &*product_view.state.borrow(),
            &modal_state,
            "modal palette must reject background accessibility actions"
        );
        window.invoke_palette_dismiss_requested();
        assert!(!window.get_palette_open());
        let preview_before_actions = product_view.state.borrow().clone();
        window.invoke_approval_requested(true);
        window.invoke_answer_requested("Continue".into());
        window.invoke_message_submitted("must not be recorded".into());
        window.invoke_schedule_create_requested();
        window.invoke_schedule_toggled(0);
        window.invoke_extension_toggled(0);
        window.invoke_deliverable_pin_toggle_requested();
        assert_eq!(
            &*product_view.state.borrow(),
            &preview_before_actions,
            "backend-shaped callbacks must not mutate read-only preview data"
        );

        window.set_can_disconnect(true);
        window.invoke_preview_requested();
        assert!(window.get_product_preview_open());
        window.invoke_preview_dismiss_requested();
        assert!(!window.get_product_preview_open());
        window.set_can_disconnect(false);

        window.set_layout_width(1080.0);
        assert!(!window.get_narrow_layout());
        window.set_layout_width(720.0);
        assert!(window.get_narrow_layout());

        window.set_token_input("do-not-mirror".into());
        let token_reset_selector = window.get_token_reset_selector();
        let endpoint_reset_selector = window.get_endpoint_reset_selector();
        window.invoke_connect_requested("not-a-gateway".into(), "do-not-mirror".into(), true);
        assert_eq!(window.get_token_input(), "");
        assert_ne!(window.get_token_reset_selector(), token_reset_selector);
        assert_eq!(window.get_endpoint_input(), "");
        assert_ne!(
            window.get_endpoint_reset_selector(),
            endpoint_reset_selector
        );
        assert!(!window.get_error_message().contains("do-not-mirror"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn component_callbacks_clear_the_secure_field_synchronously() {
        fn dispatch_key(window: &AppWindow, text: slint::SharedString) {
            window
                .window()
                .dispatch_event(slint::platform::WindowEvent::KeyPressed { text: text.clone() });
            window
                .window()
                .dispatch_event(slint::platform::WindowEvent::KeyReleased { text });
        }

        fn focus_secure_field(window: &AppWindow) {
            for _ in 0..12 {
                dispatch_key(window, slint::platform::Key::Tab.into());
                dispatch_key(window, "x".into());
                if window.get_token_input() == "x" {
                    return;
                }
                window.set_endpoint_input("ws://localhost:18789".into());
            }
            panic!("secure field must remain keyboard reachable");
        }

        fn focus_endpoint_field(window: &AppWindow) {
            for _ in 0..32 {
                dispatch_key(window, slint::platform::Key::Tab.into());
                let prior = window.get_endpoint_input();
                dispatch_key(window, "x".into());
                let current = window.get_endpoint_input();
                if current.len() == prior.len() + 1 && current.contains(prior.as_str()) {
                    return;
                }
                if !window.get_token_input().is_empty() {
                    window.invoke_purge_token_input();
                }
            }
            panic!("endpoint field must remain keyboard reachable");
        }

        fn undo(window: &AppWindow) {
            window
                .window()
                .dispatch_event(slint::platform::WindowEvent::KeyPressed {
                    text: slint::platform::Key::Control.into(),
                });
            dispatch_key(window, "z".into());
            window
                .window()
                .dispatch_event(slint::platform::WindowEvent::KeyReleased {
                    text: slint::platform::Key::Control.into(),
                });
        }

        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&snapshots);
        let controller = DesktopController::spawn(move |snapshot| {
            sink.lock().expect("snapshots").push(snapshot);
        })
        .expect("controller");
        let window = AppWindow::new().expect("component construction");
        window.show().expect("window visibility");
        exercise_generated_contracts(
            &window,
            controller.sender(),
            Rc::new(RefCell::new(VisualPreferencesState::default())),
        );
        let weak_window = window.as_weak();
        window.set_endpoint_input("".into());
        focus_endpoint_field(&window);
        window.set_endpoint_input("".into());
        for character in
            "wss://endpoint-user:endpoint-secret@gateway.example/path?token=hidden#private".chars()
        {
            dispatch_key(&window, character.into());
        }
        let endpoint_reset_selector = window.get_endpoint_reset_selector();
        window.invoke_connect_requested(
            window.get_endpoint_input(),
            slint::SharedString::default(),
            true,
        );
        assert_eq!(window.get_endpoint_input(), "wss://gateway.example/path");
        assert_ne!(
            window.get_endpoint_reset_selector(),
            endpoint_reset_selector
        );
        assert!(window.get_endpoint_preserve_focus());
        dispatch_key(&window, "y".into());
        let edited_endpoint = window.get_endpoint_input();
        assert_eq!(
            edited_endpoint.len(),
            "wss://gateway.example/path".len() + 1
        );
        assert!(edited_endpoint.contains("wss://gateway.example/path"));
        undo(&window);
        undo(&window);
        assert_eq!(window.get_endpoint_input(), "wss://gateway.example/path");

        let endpoint_reset_selector = window.get_endpoint_reset_selector();
        window.set_endpoint_input("not-a-gateway token=must-not-survive ".into());
        window.invoke_connect_requested(
            window.get_endpoint_input(),
            slint::SharedString::default(),
            true,
        );
        assert_eq!(window.get_endpoint_input(), "");
        assert_ne!(
            window.get_endpoint_reset_selector(),
            endpoint_reset_selector
        );

        focus_secure_field(&window);
        window.set_token_input("".into());
        for character in "undo-secret".chars() {
            dispatch_key(&window, character.into());
        }
        assert_eq!(window.get_token_input(), "undo-secret");
        window.set_layout_width(720.0);
        dispatch_key(&window, "r".into());
        assert_eq!(window.get_token_input(), "undo-secretr");
        window.set_layout_width(1080.0);
        let reset_selector = window.get_token_reset_selector();
        window.invoke_connect_requested(
            "ws://localhost:18789".into(),
            window.get_token_input(),
            true,
        );
        assert_eq!(window.get_token_input(), "");
        assert_ne!(window.get_token_reset_selector(), reset_selector);
        assert!(window.get_token_preserve_focus());
        dispatch_key(&window, "x".into());
        assert_eq!(window.get_token_input(), "x");
        undo(&window);
        undo(&window);
        assert_eq!(window.get_token_input(), "");

        window.set_token_input("pending-close-secret".into());
        let reset_selector = window.get_token_reset_selector();
        assert!(window.invoke_request_close());
        assert_eq!(window.get_token_input(), "");
        assert_ne!(window.get_token_reset_selector(), reset_selector);
        drop(window);
        assert!(matches!(
            handle_close_request(&weak_window, &controller.sender()),
            CloseRequestResponse::HideWindow
        ));
        controller.shutdown().expect("controller shutdown");
        assert!(snapshots.lock().expect("snapshots").iter().any(|snapshot| {
            matches!(
                snapshot.phase(),
                OnboardingPhase::Disconnected | OnboardingPhase::Failed
            )
        }));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_contracts_compile_without_worker_thread_window_creation() {
        let contract: GeneratedContract = exercise_generated_contracts;
        assert_eq!(
            std::mem::size_of_val(&contract),
            std::mem::size_of::<GeneratedContract>()
        );
    }

    #[test]
    fn secure_accessibility_keyboard_and_modal_contracts_are_explicit() {
        let app = include_str!("../ui/app-window.slint");
        let onboarding = include_str!("../ui/modules/gateway-onboarding.slint");
        let first_run = include_str!("../ui/modules/first-run.slint");
        let primitives = include_str!("../ui/modules/primitives.slint");
        let product_shell = include_str!("../ui/modules/product-shell.slint");
        let product_state = include_str!("product_state.rs");
        let main = include_str!("main.rs");
        let tokens = include_str!("../ui/modules/tokens.slint");
        let build = include_str!("../build.rs");
        let generated = include_str!(concat!(env!("OUT_DIR"), "/app-window.rs"));

        assert!(app.contains("min-width: 720px"));
        assert!(app.contains("min-height: 520px"));
        assert!(onboarding.contains("narrow-layout: root.available-width < 900px"));
        assert!(primitives.contains("export component SecureTextField"));
        assert!(primitives.contains("export component ResettableTextField"));
        assert_eq!(
            primitives.matches("input-type: InputType.password").count(),
            1
        );
        assert_eq!(primitives.matches("accessible-value: \"\"").count(), 1);
        assert!(primitives.contains("field := TextInput"));
        assert!(primitives.contains("accessible-role: none"));
        assert!(
            primitives
                .contains("if (!root.reset-selector) : even-instance := SecureEditorInstance")
        );
        assert!(
            primitives.contains("if (root.reset-selector) : odd-instance := SecureEditorInstance")
        );
        assert!(app.contains("root.token-reset-selector = !root.token-reset-selector"));
        assert!(app.contains("root.endpoint-reset-selector = !root.endpoint-reset-selector"));
        assert!(onboarding.contains("accessible-name: \"Session-only Gateway token\""));
        assert!(onboarding.contains("token-field := SecureTextField"));
        assert!(onboarding.contains("endpoint-field := ResettableTextField"));
        assert_eq!(
            onboarding
                .matches("connection-form := ConnectionForm")
                .count(),
            1
        );
        assert!(!onboarding.contains("if (!root.narrow-layout)"));
        assert!(primitives.contains("message-text := Text"));
        assert!(primitives.contains("wrap: word-wrap"));
        let secure_start = generated
            .find("struct InnerSecureEditorInstance")
            .expect("generated secure editor");
        let secure_end = generated[secure_start..]
            .find("struct InnerSecureTextField")
            .map(|offset| secure_start + offset)
            .expect("generated secure field follows editor");
        let secure_generated = &generated[secure_start..secure_end];
        assert!(secure_generated.contains(
            "AccessibleStringProperty :: r#Value) => sp :: Some (sp :: SharedString :: from (\"\"))"
        ));
        assert!(!secure_generated.contains(
            "AccessibleStringProperty :: r#Value) => sp :: Some ((InnerSecureEditorInstance"
        ));
        assert!(!onboarding.contains("accessible-label: root.token-input"));
        assert!(!onboarding.contains("text: root.token-input"));
        assert!(onboarding.contains("event.text == Key.Escape"));
        assert!(onboarding.contains("accepted => { root.submit-form(); }"));
        assert!(onboarding.contains("accessible-role: form"));
        assert!(onboarding.contains("ToastBanner"));
        assert!(primitives.contains("before-focus-boundary := FocusScope"));
        assert!(primitives.contains("after-focus-boundary := FocusScope"));
        assert!(primitives.contains("sheet-pointer-guard := TouchArea"));
        assert!(app.contains("out property <[CommandItem]> command-catalog"));
        assert!(app.contains("title: @tr(\"Go to Preview Focus\")"));
        assert!(product_shell.contains("accessible-name: @tr(\"Search commands\")"));
        assert!(product_shell.contains("accessible-role: list-item"));
        assert!(product_shell.contains("accessible-role: search"));
        assert!(product_shell.contains("event.text == Key.UpArrow"));
        assert!(app.contains("application-focus := FocusScope"));
        assert!(app.contains("event.modifiers.meta"));
        assert!(app.contains("if (root.palette-open)"));
        assert!(app.contains("FocusHistory.capture-current()"));
        assert!(app.contains("changed observed-selected-screen => { self.focus(); }"));
        assert!(product_shell.contains("changed palette-open"));
        assert!(product_shell.contains("visible: !root.palette-open"));
        assert!(product_shell.contains("enabled: !root.palette-open"));
        assert!(product_shell.contains("scroll-event(event) => { return accept; }"));
        assert!(product_shell.contains(
            "accessible-role: root.palette-open ? AccessibleRole.none : AccessibleRole.region"
        ));
        assert!(primitives.contains("accessible-role: groupbox"));
        assert!(primitives.contains("Modal dialog. Background content is unavailable"));
        assert!(primitives.contains("export global FocusHistory"));
        assert!(primitives.contains("public function restore-captured()"));
        assert!(primitives.contains("public function capture-control(control: string)"));
        assert!(primitives.contains("in property <string> focus-id: \"\""));
        assert!(primitives.contains("private property <string> stable-focus-id: \"\""));
        assert!(primitives.contains(
            "root.stable-focus-id = root.focus-id == \"\" ? root.accessible-name : root.focus-id"
        ));
        assert!(primitives.contains("FocusHistory.remember(root.stable-focus-id)"));
        assert!(primitives.contains("out property <bool> content-bounds-fit"));
        assert!(primitives.contains("min-height: max(Metrics.control-medium, content.min-height)"));
        assert!(product_shell.contains("selection-index-requested(index)"));
        assert!(product_shell.contains("focus-when-selected"));
        assert!(product_shell.contains(
            "FocusHistory.capture-control(palette-button.focus-id)"
        ));
        assert!(product_shell.contains("focus-id: \"settings.appearance.contrast\""));
        assert!(product_shell.contains("FocusHistory.restore-captured()"));
        assert!(product_shell.contains("width: max(0px, min(680px"));
        assert!(product_shell.contains("focus-received =>"));
        assert!(product_shell.contains("viewport-y"));
        assert!(primitives.contains("in property <bool> focus-on-init"));
        assert!(primitives.contains("intercept-vertical-navigation"));
        assert!(tokens.contains("private property <float> geometry-density"));
        assert!(tokens.contains("min(Metrics.density, 1.4)"));
        assert!(first_run.contains("private property <length> content-width"));
        assert!(first_run.contains("width: min(900px, root.content-width)"));
        assert!(!first_run.contains("width: min(900px, parent.width)"));
        assert!(first_run.contains("heading-text.preferred-height"));
        assert!(onboarding.contains("summary-grid := GridLayout"));
        assert!(onboarding.contains("row: root.stacked ? 1 : 0"));
        assert!(onboarding.contains("out property <bool> text-bounds-fit"));
        assert!(onboarding.contains("label-text.preferred-height"));
        assert!(onboarding.contains("value-text.preferred-height"));
        assert!(onboarding.contains("summary-geometry-changed(bool, bool)"));
        assert!(!onboarding.contains("width: 112px"));
        assert!(product_shell.contains("component ApprovalPrompt"));
        assert!(product_shell.contains(
            "callback geometry-changed(bool, bool, bool, bool)"
        ));
        assert!(product_shell.contains("out property <bool> controls-no-overlap"));
        assert!(product_shell.contains("deny-button.content-bounds-fit"));
        assert!(product_shell.contains("approve-button.content-bounds-fit"));
        assert!(product_shell.contains("row: root.stacked ? 2 : 0"));
        assert!(!product_shell.contains("HorizontalLayout {\n                        spacing: Metrics.space-3;\n                        VerticalLayout {\n                            spacing: Metrics.space-1;\n                            Text { text: \"Sample approval prompt\""));
        assert!(product_shell.contains("component QuestionPrompt"));
        assert!(product_shell.contains("question-text := Text"));
        assert!(product_shell.contains("wrap: word-wrap"));
        assert!(product_shell.contains("focus-id: \"session.question.continue\""));
        assert!(product_shell.contains("focus-id: \"session.question.pause\""));
        assert!(product_shell.contains("root.question-geometry-changed("));
        assert!(!product_shell.contains("Text { text: root.question; color: DesignTokens.text-primary; font-size: Metrics.type-small; accessible-role: text; }"));
        assert!(product_shell.contains("configured: bool"));
        assert!(product_shell.contains("state: string"));
        assert!(product_shell.contains("badge: schedule.state"));
        assert!(product_state.contains("pub(crate) configured: bool"));
        assert!(!product_state.contains("next_run != \"Not scheduled\""));
        assert!(!product_state.contains("next_run == \"Not scheduled\""));
        assert!(!product_state.contains("pub(crate) active_runs"));
        assert!(main.contains("state.workspace_active_runs(&workspace.name)"));
        assert!(main.contains("select_ui_focus_index(index)"));
        assert!(main.contains("if view.state.borrow().palette_open()"));
        assert!(!main.contains("Slint palette selection indexes must be non-negative"));
        assert!(!product_shell.contains(
            "text: schedule.enabled ? \"Enabled\" : (schedule.can-toggle ? \"Paused\" : \"Draft\")"
        ));
        assert!(product_shell.contains("component PreviewCard"));
        assert!(product_shell.contains("out property <bool> icon-bounds-fit"));
        assert!(product_shell.contains("out property <bool> button-bounds-fit"));
        assert!(product_shell.contains("card-action.content-bounds-fit"));
        assert!(product_shell.contains("for workspace[index] in root.workspaces : PreviewCard"));
        assert!(product_shell.contains("for schedule[index] in root.schedules : PreviewCard"));
        assert!(product_shell.contains("for extension[index] in root.extensions : PreviewCard"));
        assert!(product_shell.contains("workspace-card-geometry-changed("));
        assert!(product_shell.contains("schedule-card-geometry-changed("));
        assert!(product_shell.contains("extension-card-geometry-changed("));
        assert!(product_shell.contains("badge-bounds-fit"));
        assert!(product_shell.contains("workspace-card-geometry-changed(int,"));
        assert!(product_shell.contains("application-title-min-width"));
        assert!(product_shell.contains("application-title.preferred-width"));
        assert!(product_shell.contains("if (!root.compact-navigation) : ToolbarIconButton"));
        assert!(product_shell.contains("compact-rail-width"));
        assert!(product_shell.contains("settings-rail.width >= root.compact-rail-width"));
        assert!(product_shell.contains("in property <bool> session-narrow-layout"));
        assert!(product_shell.contains("narrow: root.session-narrow-layout"));
        assert!(product_shell.contains("focus-reveal-requested(length, length)"));
        assert!(product_shell.contains("root.reveal-focused-control(item-y, item-height)"));
        assert!(product_shell.contains("focused-run-visibility-changed(bool)"));
        assert!(product_shell.contains("preferred-height"));
        assert!(!product_shell.contains(".width >= title-text.min-width"));
        assert!(product_shell.contains("component SessionHeader"));
        assert!(product_shell.contains("callback session-header-geometry-changed("));
        assert!(product_shell.contains("state-badge.content-bounds-fit"));
        assert!(product_shell.contains("header-copy.absolute-position"));
        assert!(
            primitives.contains("if (root.enabled) {\n                    touch-area.clicked();")
        );
        assert!(!onboarding.contains("if (root.can-connect && !root.can-retry)"));
        assert!(!onboarding.contains("if (root.can-retry) : PrimaryButton"));
        assert!(!onboarding.contains("if (root.can-cancel) : SecondaryButton"));
        assert!(!onboarding.contains("if (root.can-disconnect) : DangerButton"));
        assert!(build.contains("\"windows\" => \"fluent\""));
        assert!(build.contains("\"macos\" => \"cupertino\""));
    }

    #[test]
    fn desktop_surfaces_do_not_claim_unwired_backends() {
        let app = include_str!("../ui/app-window.slint");
        let first_run = include_str!("../ui/modules/first-run.slint");
        let onboarding = include_str!("../ui/modules/gateway-onboarding.slint");
        let product_shell = include_str!("../ui/modules/product-shell.slint");
        let product_state = include_str!("product_state.rs");
        let main = include_str!("main.rs");
        let progress = include_str!("../../../../docs/PROGRESS.md");

        for invented_claim in [
            "GTAC-7K2M",
            r"C:\work\GTA-Claw",
            r"D:\labs\gateway-double",
            "ssh://builder/release",
            "Gateway healthy",
            "GTA Claw 0.2.0 is ready",
            "Signature verified",
            "A signed native update is available for review.",
            "4 worker threads",
            "\"gateway\": \"healthy\"",
            "software-fallback-ready",
            "\"accessibility\": \"active\"",
        ] {
            assert!(!first_run.contains(invented_claim));
            assert!(!product_shell.contains(invented_claim));
            assert!(!product_state.contains(invented_claim));
        }

        assert!(first_run.contains("@tr(\"Account authorization isn't available\")"));
        assert!(first_run.contains("@tr(\"Workspace trust isn't available\")"));
        assert!(first_run.contains("component ResponsiveHeading"));
        assert!(first_run.contains("wrap: word-wrap"));
        assert!(first_run.contains("callback heading-geometry-changed(bool, bool)"));
        assert!(onboarding.contains("@tr(\"Desktop device authorization is not composed."));
        assert!(product_state.contains("\"No trusted path loaded\""));
        assert!(app.contains("product-preview-open"));
        assert!(!app.contains("workspace-ready"));
        assert!(onboarding.contains("optional product preview is read-only sample data"));
        assert!(product_shell.contains("GTA Claw read-only product preview"));
        assert!(product_shell.contains("No live or historical runs are loaded."));
        assert!(product_shell.contains("Creation unavailable"));
        assert!(product_shell.contains("enabled: root.interactions-enabled"));
        assert!(product_shell.contains("Appearance preferences reset when this application closes"));
        assert!(!product_shell.contains("Native workspace"));
        assert!(!product_shell.contains("MetricCard { value: \"3\""));
        assert!(!product_shell.contains("MetricCard { value: \"7\""));
        assert!(!main.contains("set_product_preview_open(snapshot.can_disconnect())"));
        assert!(app.contains("gateway-status-text: root.status-text"));
        assert!(product_shell.contains("@tr(\"In-app updates are not available\")"));
        assert!(product_shell.contains("@tr(\"Diagnostic coverage\")"));
        assert!(app.contains("@tr(\"View update availability\")"));
        assert!(app.contains("@tr(\"View diagnostic availability\")"));
        assert!(progress.contains("device authorization and workspace trust are not composed"));
        assert!(progress.contains("diagnostics expose only the live Gateway summary"));
    }

    #[test]
    fn palette_actions_reach_primary_and_auxiliary_surfaces() {
        for (action, screen) in [
            (PaletteAction::Focus, 0),
            (PaletteAction::Workspaces, 1),
            (PaletteAction::Runs, 2),
            (PaletteAction::Schedules, 3),
            (PaletteAction::Deliverables, 4),
            (PaletteAction::Extensions, 5),
            (PaletteAction::Settings, 6),
            (PaletteAction::Update, 8),
            (PaletteAction::Diagnostics, 9),
        ] {
            let mut state = ProductState::default();
            state.toggle_palette();

            apply_palette_action(&mut state, action);

            assert_eq!(state.surface().screen_index(), screen);
            assert!(!state.palette_open());
        }

        let mut state = ProductState::default();
        state.toggle_palette();
        apply_palette_action(&mut state, PaletteAction::KeyboardShortcuts);
        assert_eq!(state.surface().screen_index(), 6);
        assert_eq!(state.selected_settings_section(), 5);
        assert!(!state.palette_open());
    }

    #[test]
    fn diagnostic_readiness_retains_only_an_explicit_preview() {
        assert!(!retain_explicit_preview(false, false));
        assert!(!retain_explicit_preview(false, true));
        assert!(!retain_explicit_preview(true, false));
        assert!(retain_explicit_preview(true, true));
    }

    #[test]
    fn controller_to_slint_handoff_and_callbacks_keep_weak_ui_handles() {
        let source = include_str!("main.rs");
        assert!(source.contains("weak_window.upgrade_in_event_loop"));
        assert!(source.matches("let weak_window = window.as_weak();").count() >= 20);
        assert!(!source.contains("Rc<AppWindow>"));
        assert!(!source.contains("Arc<AppWindow>"));
    }
}

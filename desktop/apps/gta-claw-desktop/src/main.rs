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
use ui_adapter::{UiTheme, VisualPreferencesState};
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
    window.set_workspace_ready(snapshot.can_disconnect());
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
            active_runs: i32::try_from(workspace.active_runs).unwrap_or(i32::MAX),
        }),
    );

    reconcile(
        models.schedules(),
        state.schedules().iter().map(|schedule| ScheduleItem {
            name: schedule.name.as_str().into(),
            cadence: schedule.cadence.as_str().into(),
            next_run: schedule.next_run.as_str().into(),
            enabled: schedule.enabled,
            can_toggle: schedule.enabled || schedule.next_run != "Not scheduled",
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
    let callback_sender = sender.clone();
    window.on_cancel_requested(move || {
        apply_command_result(&weak_window, callback_sender.cancel());
    });

    let weak_window = window.as_weak();
    let callback_sender = sender.clone();
    window.on_disconnect_requested(move || {
        apply_command_result(&weak_window, callback_sender.disconnect());
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
        callback_preferences.borrow_mut().set_theme(match theme {
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
            view.apply(&window);
        }
    });

    let weak_window = window.as_weak();
    let view = Rc::clone(product_view);
    window.on_palette_dismiss_requested(move || {
        mutate_product(&weak_window, &view, ProductState::close_palette);
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
    window.on_palette_command_requested(move |action_id| {
        let action = PaletteAction::from_id(action_id)
            .expect("Slint palette commands must use a catalog action");
        view.palette.borrow_mut().reset();
        apply_palette_action(&mut view.state.borrow_mut(), action);
        if let Some(window) = weak_window.upgrade() {
            window.set_palette_query(slint::SharedString::default());
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
            }
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
                Err(error) => product.record_message(
                    TranscriptRole::System,
                    "Answer rejected",
                    error.to_string(),
                ),
            }
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
        mutate_product(&weak_window, &view, ProductState::create_schedule);
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
    use crate::onboarding::OnboardingModel;
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
        wire_callbacks(window, sender, preferences, &product_view);

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
        let primitives = include_str!("../ui/modules/primitives.slint");
        let product_shell = include_str!("../ui/modules/product-shell.slint");
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
        assert!(app.contains("title: @tr(\"Go to Focus\")"));
        assert!(product_shell.contains("accessible-name: @tr(\"Search commands\")"));
        assert!(product_shell.contains("accessible-role: list-item"));
        assert!(product_shell.contains("accessible-role: search"));
        assert!(product_shell.contains("event.text == Key.UpArrow"));
        assert!(product_shell.contains("event.modifiers.meta"));
        assert!(product_shell.contains("changed palette-open"));
        assert!(primitives.contains("in property <bool> focus-on-init"));
        assert!(primitives.contains("intercept-vertical-navigation"));
        assert!(build.contains("\"windows\" => \"fluent\""));
        assert!(build.contains("\"macos\" => \"cupertino\""));
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
}

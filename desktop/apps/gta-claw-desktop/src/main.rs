//! Native Gateway onboarding with Slint retaining ownership of the main thread.

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
use std::cell::RefCell;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::error::Error;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::fmt::{self, Display, Formatter};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::rc::Rc;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::time::Duration;

#[cfg(any(target_os = "windows", target_os = "macos"))]
use claw_application::SystemProbe as _;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use claw_platform::NativeSystemProbe;
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
use slint::{CloseRequestResponse, ComponentHandle};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use ui_adapter::{UiTheme, VisualPreferencesState};

#[cfg(any(target_os = "windows", target_os = "macos"))]
#[allow(missing_docs, unreachable_pub)]
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
fn model<T: Clone + 'static>(rows: Vec<T>) -> slint::ModelRc<T> {
    Rc::new(slint::VecModel::from(rows)).into()
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
fn apply_product_state(window: &AppWindow, state: &ProductState) {
    debug_assert_eq!(state.keyboard_order().len(), 10);
    debug_assert_eq!(state.accessibility_nodes().len(), 4);
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
    window.set_session_title(selected_run.title.clone().into());
    window.set_session_state(selected_run.state.label().into());
    window
        .set_session_detail(format!("{} · {}", selected_run.workspace, selected_run.detail).into());
    window.set_session_tone(tone_index(selected_run.state.tone()));
    window.set_can_approve(selected_run.state == RunState::WaitingForApproval);
    window.set_can_answer(selected_run.state == RunState::WaitingForAnswer);
    window.set_approval_prompt(state.approval_prompt().into());
    window.set_approval_scope(state.approval_scope().into());
    window.set_question(state.question().into());

    let runs = state
        .runs()
        .visible()
        .iter()
        .map(|run| RunItem {
            id: run.id.clone().into(),
            title: run.title.clone().into(),
            workspace: run.workspace.clone().into(),
            state: run.state.label().into(),
            detail: run.detail.clone().into(),
            updated: run.updated.clone().into(),
            tone: tone_index(run.state.tone()),
        })
        .collect();
    window.set_runs(model(runs));

    let workspaces = state
        .workspaces()
        .iter()
        .map(|workspace| WorkspaceItem {
            name: workspace.name.clone().into(),
            location: workspace.location.clone().into(),
            kind: workspace.kind.clone().into(),
            branch: workspace.branch.clone().into(),
            active_runs: i32::try_from(workspace.active_runs).unwrap_or(i32::MAX),
        })
        .collect();
    window.set_workspaces(model(workspaces));

    let schedules = state
        .schedules()
        .iter()
        .map(|schedule| ScheduleItem {
            name: schedule.name.clone().into(),
            cadence: schedule.cadence.clone().into(),
            next_run: schedule.next_run.clone().into(),
            enabled: schedule.enabled,
            can_toggle: schedule.enabled || schedule.next_run != "Not scheduled",
            workspace: schedule.workspace.clone().into(),
        })
        .collect();
    window.set_schedules(model(schedules));

    let deliverables = state
        .deliverables()
        .iter()
        .map(|deliverable| DeliverableItem {
            name: deliverable.name.clone().into(),
            kind: deliverable.kind.clone().into(),
            source: deliverable.source.clone().into(),
            size: deliverable.size.clone().into(),
            pinned: deliverable.pinned,
        })
        .collect();
    window.set_deliverables(model(deliverables));
    let selected_deliverable = state.selected_deliverable();
    window.set_selected_deliverable_index(
        i32::try_from(state.selected_deliverable_index()).unwrap_or(i32::MAX),
    );
    window.set_selected_deliverable_name(selected_deliverable.name.clone().into());
    window.set_selected_deliverable_kind(selected_deliverable.kind.clone().into());
    window.set_selected_deliverable_source(selected_deliverable.source.clone().into());
    window.set_selected_deliverable_size(selected_deliverable.size.clone().into());
    window.set_selected_deliverable_content(state.selected_deliverable_content().into());
    window.set_selected_deliverable_pinned(selected_deliverable.pinned);

    let extensions = state
        .extensions()
        .iter()
        .map(|extension| ExtensionItem {
            name: extension.name.clone().into(),
            category: extension.category.clone().into(),
            detail: extension.detail.clone().into(),
            permission: extension.permission.clone().into(),
            enabled: extension.enabled,
        })
        .collect();
    window.set_extensions(model(extensions));

    let transcript = state
        .transcript()
        .iter()
        .map(|entry| TranscriptItem {
            role: entry.role.label().into(),
            text: entry.text.clone().into(),
            detail: entry.detail.clone().into(),
            timestamp: entry.timestamp.clone().into(),
            tone: match entry.role {
                TranscriptRole::User | TranscriptRole::Activity => 0,
                TranscriptRole::Assistant => 1,
                TranscriptRole::System => 2,
            },
        })
        .collect();
    window.set_transcript(model(transcript));

    let activity = state
        .activity()
        .iter()
        .map(|entry| ActivityItem {
            title: entry.title.clone().into(),
            detail: entry.detail.clone().into(),
            state: entry.state.label().into(),
            duration: entry.duration.clone().into(),
            tone: tone_index(entry.state.tone()),
        })
        .collect();
    window.set_activity(model(activity));

    let session_files = state
        .session_files()
        .iter()
        .map(|file| FileItem {
            name: file.name.clone().into(),
            status: file.status.clone().into(),
        })
        .collect();
    window.set_session_files(model(session_files));
    window.set_selected_file_index(i32::try_from(state.selected_file_index()).unwrap_or(i32::MAX));
    window.set_selected_file_name(state.selected_file_name().into());

    let diff = match state.diff_mode() {
        DiffMode::Unified => state
            .diff()
            .iter()
            .zip(render_unified(state.diff()))
            .map(|(line, text)| DiffItem {
                old_line: line_number(line.old_line),
                new_line: line_number(line.new_line),
                text: text.into(),
                old_text: line.text.clone().into(),
                new_text: line.text.clone().into(),
                kind: change_kind_index(line.kind),
            })
            .collect(),
        DiffMode::SideBySide => render_side_by_side(state.diff())
            .into_iter()
            .map(|line| DiffItem {
                old_line: line_number(line.old_line),
                new_line: line_number(line.new_line),
                text: slint::SharedString::default(),
                old_text: line.old_text.into(),
                new_text: line.new_text.into(),
                kind: change_kind_index(line.kind),
            })
            .collect(),
    };
    window.set_diff_lines(model(diff));

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

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn mutate_product(
    weak_window: &slint::Weak<AppWindow>,
    state: &Rc<RefCell<ProductState>>,
    update: impl FnOnce(&mut ProductState),
) {
    update(&mut state.borrow_mut());
    if let Some(window) = weak_window.upgrade() {
        apply_product_state(&window, &state.borrow());
    }
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
    endpoint: slint::SharedString,
    token: slint::SharedString,
    consent: bool,
) {
    let submission = ConnectRequest::prepare(endpoint.to_string(), token.to_string(), consent);
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
    product_state: Rc<RefCell<ProductState>>,
) {
    let weak_window = window.as_weak();
    let callback_sender = sender.clone();
    window.on_connect_requested(move |endpoint, token, consent| {
        enqueue_submission(&weak_window, &callback_sender, endpoint, token, consent);
    });

    let weak_window = window.as_weak();
    let callback_sender = sender.clone();
    window.on_retry_requested(move |endpoint, token, consent| {
        enqueue_submission(&weak_window, &callback_sender, endpoint, token, consent);
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
    let state = Rc::clone(&product_state);
    window.on_onboarding_stage_requested(move |index| {
        let stage = OnboardingStage::from_index(index)
            .expect("Slint onboarding stages must use a known index");
        mutate_product(&weak_window, &state, |product| {
            product.select_onboarding_stage(stage);
        });
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_navigate_requested(move |index| {
        let destination = PrimaryDestination::from_index(index)
            .expect("Slint navigation must use a known destination index");
        mutate_product(&weak_window, &state, |product| {
            product.select_destination(destination);
            product.close_palette();
        });
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_palette_toggle_requested(move || {
        mutate_product(&weak_window, &state, ProductState::toggle_palette);
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_palette_dismiss_requested(move || {
        mutate_product(&weak_window, &state, ProductState::close_palette);
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_open_session_requested(move |index| {
        let index = usize::try_from(index).expect("Slint run indexes must be non-negative");
        mutate_product(&weak_window, &state, |product| {
            product.open_session(index);
        });
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_open_workspace_requested(move |index| {
        let index = usize::try_from(index).expect("Slint workspace indexes must be non-negative");
        mutate_product(&weak_window, &state, |product| {
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
    let state = Rc::clone(&product_state);
    window.on_settings_section_requested(move |index| {
        let index = usize::try_from(index).expect("Slint settings indexes must be non-negative");
        mutate_product(&weak_window, &state, |product| {
            product.select_settings_section(index);
        });
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_update_requested(move || {
        mutate_product(&weak_window, &state, ProductState::open_update);
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_diagnostics_requested(move || {
        mutate_product(&weak_window, &state, ProductState::open_diagnostics);
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_back_requested(move || {
        mutate_product(&weak_window, &state, ProductState::return_from_auxiliary);
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_diff_mode_requested(move |mode| {
        let mode = match mode {
            0 => DiffMode::Unified,
            1 => DiffMode::SideBySide,
            _ => panic!("Slint diff modes must use a known index"),
        };
        mutate_product(&weak_window, &state, |product| {
            product.set_diff_mode(mode);
        });
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_previous_run_page_requested(move || {
        mutate_product(&weak_window, &state, |product| {
            product.previous_run_page();
        });
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_next_run_page_requested(move || {
        mutate_product(&weak_window, &state, |product| {
            product.next_run_page();
        });
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_approval_requested(move |approved| {
        mutate_product(&weak_window, &state, |product| {
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
    let state = Rc::clone(&product_state);
    window.on_answer_requested(move |answer| {
        mutate_product(&weak_window, &state, |product| {
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
    let state = Rc::clone(&product_state);
    window.on_message_submitted(move |message| {
        mutate_product(&weak_window, &state, |product| {
            product.record_message(
                TranscriptRole::User,
                message.to_string(),
                "Submitted from the session composer",
            );
        });
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_file_selected(move |index| {
        let index = usize::try_from(index).expect("Slint file indexes must be non-negative");
        mutate_product(&weak_window, &state, |product| {
            product.select_session_file(index);
        });
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_schedule_create_requested(move || {
        mutate_product(&weak_window, &state, ProductState::create_schedule);
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_schedule_toggled(move |index| {
        let index = usize::try_from(index).expect("Slint schedule indexes must be non-negative");
        mutate_product(&weak_window, &state, |product| {
            product.toggle_schedule(index);
        });
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_extension_toggled(move |index| {
        let index = usize::try_from(index).expect("Slint extension indexes must be non-negative");
        mutate_product(&weak_window, &state, |product| {
            product.toggle_extension(index);
        });
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_deliverable_selected(move |index| {
        let index = usize::try_from(index).expect("Slint deliverable indexes must be non-negative");
        mutate_product(&weak_window, &state, |product| {
            product.select_deliverable(index);
        });
    });

    let weak_window = window.as_weak();
    let state = Rc::clone(&product_state);
    window.on_deliverable_pin_toggle_requested(move || {
        mutate_product(&weak_window, &state, |product| {
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
    let self_check = packaging_self_check_requested();
    let window = AppWindow::new().map_err(DesktopError::Platform)?;
    let weak_window = window.as_weak();
    let controller = DesktopController::spawn(move |snapshot| {
        let weak_window = weak_window.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = weak_window.upgrade() {
                apply_snapshot(&window, &snapshot);
            }
        });
    })
    .map_err(DesktopError::ControllerStart)?;
    let preferences = Rc::new(RefCell::new(VisualPreferencesState::default()));
    let product_state = Rc::new(RefCell::new(ProductState::default()));
    apply_preferences(&window, *preferences.borrow());
    apply_product_state(&window, &product_state.borrow());
    wire_callbacks(&window, controller.sender(), preferences, product_state);
    // Dropping a Slint timer cancels it, so the self-check timer has to outlive
    // the event loop it is going to stop.
    let _self_check_timer = self_check.then(arm_packaging_self_check);
    window.run().map_err(DesktopError::Platform)?;
    controller
        .shutdown()
        .map_err(DesktopError::ControllerShutdown)?;
    if self_check {
        report_packaging_self_check();
    }
    Ok(())
}

/// Sole argument that makes this binary complete one full startup and shut
/// itself down again instead of waiting for a person.
///
/// The packaging scripts pass it so that the bytes they are about to archive,
/// sign and publish have been run at least once. Every other check in
/// `packaging/macos` only reads those bytes.
#[cfg(any(target_os = "windows", target_os = "macos"))]
const PACKAGING_SELF_CHECK_FLAG: &str = "--packaging-self-check";

/// Delay before a self-check run asks the Slint event loop to stop.
#[cfg(any(target_os = "windows", target_os = "macos"))]
const PACKAGING_SELF_CHECK_QUIT_DELAY: Duration = Duration::from_millis(250);

/// Deadline after which a self-check that never reached its quit timer aborts,
/// so a window that never opens fails the packaging run instead of hanging it.
#[cfg(any(target_os = "windows", target_os = "macos"))]
const PACKAGING_SELF_CHECK_DEADLINE: Duration = Duration::from_secs(120);

/// Reports whether this process was started for a packaging self-check.
///
/// The flag has to be the only argument, and it is read from the argument
/// vector rather than the environment on purpose: an environment variable is
/// inherited by every descendant of whatever set it, so one exported name could
/// make ordinary launches exit on their own. An argument cannot be inherited,
/// and a launch through Finder or `open` supplies none. Arguments are read as
/// `OsString` because `env::args` panics on a non-Unicode argument, which a
/// launcher must not be able to cause.
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn packaging_self_check_requested() -> bool {
    let mut arguments = std::env::args_os().skip(1);
    arguments
        .next()
        .is_some_and(|first| first == PACKAGING_SELF_CHECK_FLAG)
        && arguments.next().is_none()
}

/// Arms the watchdog and the single-shot timer that ends a self-check run.
///
/// The returned timer is the whole difference between a self-check run and an
/// ordinary one: the window, the controller, the callbacks and the shutdown
/// path are the production ones.
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn arm_packaging_self_check() -> slint::Timer {
    std::thread::spawn(|| {
        std::thread::sleep(PACKAGING_SELF_CHECK_DEADLINE);
        eprintln!("packaging self-check exceeded its deadline without reaching the event loop");
        std::process::abort();
    });
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::SingleShot,
        PACKAGING_SELF_CHECK_QUIT_DELAY,
        || slint::quit_event_loop().expect("quit the Slint event loop"),
    );
    timer
}

/// Prints what actually ran, once the real shutdown path has completed.
///
/// A zero exit status only says that something ran. The package version ties
/// the run to this build, and the runtime descriptor is resolved from
/// `std::env::consts` at compile time, so a binary built for another target
/// fails this even on a host that could execute it.
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn report_packaging_self_check() {
    println!(
        "gta-claw-desktop packaging self-check ok version={} runtime={}",
        env!("CARGO_PKG_VERSION"),
        NativeSystemProbe.runtime()
    );
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
#[derive(Debug)]
enum DesktopError {
    Platform(slint::PlatformError),
    ControllerStart(ControllerStartError),
    ControllerShutdown(ControllerShutdownError),
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
        let product_state = Rc::new(RefCell::new(initial_product));
        apply_product_state(window, &product_state.borrow());
        wire_callbacks(window, sender, preferences, product_state);

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
        assert!(build.contains("\"windows\" => \"fluent\""));
        assert!(build.contains("\"macos\" => \"cupertino\""));
    }
}

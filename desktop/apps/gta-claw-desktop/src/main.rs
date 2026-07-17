//! Native Gateway onboarding with Slint retaining ownership of the main thread.

#[cfg(any(target_os = "windows", target_os = "macos"))]
mod controller;
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod onboarding;
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
use controller::{
    CommandRejection, ControllerSender, ControllerShutdownError, ControllerStartError,
    DesktopController,
};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use onboarding::{ConnectRequest, UiStatusKind, UserError, ViewSnapshot};
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
use generated_ui::{AppWindow, StatusKind, ThemeMode, VisualPreferences};

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
    if let Some(error) = snapshot.error() {
        apply_error(window, error);
    } else {
        clear_error(window);
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
    let close_sender = sender;
    window
        .window()
        .on_close_requested(move || handle_close_request(&weak_window, &close_sender));
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn main() -> Result<(), DesktopError> {
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
    apply_preferences(&window, *preferences.borrow());
    wire_callbacks(&window, controller.sender(), preferences);
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
        wire_callbacks(window, sender, preferences);

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

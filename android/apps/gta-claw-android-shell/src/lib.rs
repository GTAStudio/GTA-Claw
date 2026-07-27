//! Native Slint Android shell over the UI-independent client core.

#[cfg(target_os = "android")]
use std::error::Error;
#[cfg(target_os = "android")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "android")]
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

#[cfg(target_os = "android")]
use gta_claw_android::controller::{
    AndroidController, core_protocol_summary, native_runtime_summary,
};
#[cfg(target_os = "android")]
use gta_claw_android::controller::{CommandRejection, ControllerHandle, SnapshotSink};
#[cfg(any(target_os = "android", test))]
use gta_claw_android::onboarding::StatusKind;
#[cfg(target_os = "android")]
use gta_claw_android::onboarding::{ConnectRequest, ViewSnapshot};
#[cfg(target_os = "android")]
use slint::ComponentHandle;

#[expect(
    unreachable_pub,
    reason = "slint::include_modules! emits public generated items kept private by this module"
)]
mod generated_ui {
    slint::include_modules!();
}

#[cfg(target_os = "android")]
use generated_ui::AppWindow;
#[cfg(any(target_os = "android", test))]
use generated_ui::StatusTone;

#[cfg(any(target_os = "android", test))]
const fn status_tone(status: StatusKind) -> StatusTone {
    match status {
        StatusKind::Neutral => StatusTone::Neutral,
        StatusKind::Info => StatusTone::Progress,
        StatusKind::Success => StatusTone::Success,
        StatusKind::Warning => StatusTone::Warning,
        StatusKind::Danger => StatusTone::Danger,
    }
}

#[cfg(target_os = "android")]
fn apply_snapshot(window: &AppWindow, snapshot: &ViewSnapshot) {
    window.set_state_title(snapshot.title().into());
    window.set_state_detail(snapshot.detail().into());
    window.set_status_label(snapshot.status_label().into());
    window.set_status_tone(status_tone(snapshot.status_kind()));
    window.set_endpoint_summary(snapshot.endpoint_summary().into());
    window.set_server_summary(snapshot.server_summary().into());
    window.set_protocol_summary(snapshot.protocol_summary().into());
    window.set_role_summary(snapshot.role_summary().into());
    window.set_scopes_summary(snapshot.scopes_summary().into());
    window.set_identity_summary(snapshot.identity_summary().into());
    window.set_credential_notice(snapshot.credential_notice().into());
    window.set_transport_notice(snapshot.transport_notice().into());
    window.set_token_offered(snapshot.token_offered());
    window.set_busy(snapshot.busy());
    window.set_can_connect(snapshot.can_connect());
    window.set_can_disconnect(snapshot.can_disconnect());
    if let Some(error) = snapshot.error() {
        window.set_error_message(error.message().into());
        window.set_error_action(error.action().into());
        window.set_has_error(true);
    } else {
        window.set_error_message("".into());
        window.set_error_action("".into());
        window.set_has_error(false);
    }
}

#[cfg(target_os = "android")]
fn snapshot_sink(window: &AppWindow) -> SnapshotSink {
    let weak_window = window.as_weak();
    let latest = Arc::new(Mutex::new(None::<ViewSnapshot>));
    Arc::new(move |snapshot| {
        let changed = {
            let mut latest = latest.lock().unwrap_or_else(PoisonError::into_inner);
            if latest.as_ref() == Some(&snapshot) {
                false
            } else {
                *latest = Some(snapshot.clone());
                true
            }
        };
        if !changed {
            return;
        }

        let weak_window = weak_window.clone();
        if let Err(error) = slint::invoke_from_event_loop(move || {
            if let Some(window) = weak_window.upgrade() {
                apply_snapshot(&window, &snapshot);
            }
        }) {
            eprintln!("failed to queue Android UI snapshot: {error}");
        }
    })
}

#[cfg(target_os = "android")]
fn show_form_error(weak_window: &slint::Weak<AppWindow>, message: &str) {
    if let Some(window) = weak_window.upgrade() {
        window.set_form_error(message.into());
    }
}

#[cfg(target_os = "android")]
fn show_command_error(weak_window: &slint::Weak<AppWindow>, error: CommandRejection) {
    let error = error.user_error();
    show_form_error(
        weak_window,
        &format!("{} {}", error.message(), error.action()),
    );
}

#[cfg(target_os = "android")]
fn install_callbacks(window: &AppWindow, handle: &ControllerHandle) {
    let connect_handle = handle.clone();
    let weak_window = window.as_weak();
    window.on_connect_requested(move |endpoint, token, allow_insecure| {
        let request = ConnectRequest::prepare(endpoint.as_str(), token.as_str(), allow_insecure);
        match request {
            Ok(request) => match connect_handle.connect(request) {
                Ok(()) => {
                    if let Some(window) = weak_window.upgrade() {
                        window.set_form_error("".into());
                        window.set_token_input("".into());
                    }
                }
                Err(error) => show_command_error(&weak_window, error),
            },
            Err(rejection) => {
                if let Err(error) = connect_handle.reject(rejection) {
                    show_command_error(&weak_window, error);
                }
            }
        }
    });

    let disconnect_handle = handle.clone();
    let weak_window = window.as_weak();
    window.on_disconnect_requested(move || {
        if let Err(error) = disconnect_handle.disconnect() {
            show_command_error(&weak_window, error);
        }
    });
}

#[cfg(target_os = "android")]
fn run_android(app: slint::android::AndroidApp) -> Result<(), Box<dyn Error>> {
    use slint::android::android_activity::{MainEvent, PollEvent};

    let lifecycle_handle = Arc::new(OnceLock::<ControllerHandle>::new());
    let lifecycle_paused = Arc::new(AtomicBool::new(false));
    let event_handle = Arc::clone(&lifecycle_handle);
    let event_paused = Arc::clone(&lifecycle_paused);
    slint::android::init_with_event_listener(app, move |event| match event {
        PollEvent::Main(MainEvent::Resume { .. }) => {
            event_paused.store(false, Ordering::Release);
        }
        PollEvent::Main(MainEvent::Pause | MainEvent::Destroy)
            if !event_paused.swap(true, Ordering::AcqRel) =>
        {
            if let Some(handle) = event_handle.get()
                && let Err(error) = handle.disconnect()
            {
                eprintln!("failed to queue lifecycle disconnect: {error}");
            }
        }
        _ => {}
    })?;

    let window = AppWindow::new()?;
    window.set_runtime_summary(native_runtime_summary().into());
    window.set_core_protocol(core_protocol_summary(claw_platform::NativeSystemProbe).into());

    let controller = AndroidController::start(snapshot_sink(&window))?;
    let handle = controller.handle();
    lifecycle_handle
        .set(handle.clone())
        .map_err(|_| "Android lifecycle handle was initialized twice")?;
    install_callbacks(&window, &handle);
    window.run()?;
    drop(controller);
    Ok(())
}

/// Android NativeActivity entry point.
#[cfg(target_os = "android")]
#[allow(
    unsafe_code,
    reason = "Android's dynamic loader requires this one unmangled entry-point symbol"
)]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    if let Err(error) = run_android(app) {
        eprintln!("GTA Claw Android shell stopped: {error}");
    }
}

#[cfg(test)]
mod tests {
    use gta_claw_android::onboarding::{ConnectRequest, ViewModel};

    use super::status_tone;
    use crate::generated_ui::StatusTone;

    #[test]
    fn every_core_status_has_a_visual_tone() {
        use gta_claw_android::onboarding::StatusKind;

        assert_eq!(status_tone(StatusKind::Neutral), StatusTone::Neutral);
        assert_eq!(status_tone(StatusKind::Info), StatusTone::Progress);
        assert_eq!(status_tone(StatusKind::Success), StatusTone::Success);
        assert_eq!(status_tone(StatusKind::Warning), StatusTone::Warning);
        assert_eq!(status_tone(StatusKind::Danger), StatusTone::Danger);
    }

    #[test]
    fn initial_and_connecting_snapshots_drive_opposite_controls() {
        let mut model = ViewModel::new();
        let initial = model.snapshot();
        assert!(initial.can_connect());
        assert!(!initial.can_disconnect());

        let request = ConnectRequest::prepare("gateway.example:8443", "", false)
            .expect("secure bare host is valid");
        model.begin(&request);
        let connecting = model.snapshot();
        assert!(!connecting.can_connect());
        assert!(connecting.can_disconnect());
        assert!(connecting.busy());
    }
}

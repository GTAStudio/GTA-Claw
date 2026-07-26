//! Slint event-loop side of the Android shell.
//!
//! Everything here runs on the Android UI thread. It owns no Gateway state: it
//! renders [`ViewSnapshot`] values produced by the controller and forwards
//! validated input back.

use std::sync::Arc;

use claw_platform::NativeSystemProbe;
use slint::ComponentHandle;

use crate::controller::{
    AndroidController, ControllerHandle, core_protocol_summary, native_runtime_summary,
};
use crate::generated_ui::{AppWindow, StatusKind as UiStatusKind};
use crate::onboarding::{ConnectRequest, StatusKind, UserError, ViewSnapshot};

/// Runs the Android shell until the activity is destroyed.
pub(crate) fn run(app: slint::android::AndroidApp) {
    slint::android::init(app).expect("the Slint Android backend must initialise");

    let window = AppWindow::new().expect("the Slint window must be created");

    // Values that come from the application core rather than from this shell.
    window.set_runtime_summary(native_runtime_summary().into());
    window.set_core_protocol_summary(core_protocol_summary(NativeSystemProbe).into());

    let weak = window.as_weak();
    let sink = Arc::new(move |snapshot: ViewSnapshot| {
        let weak = weak.clone();
        // The controller runs on Tokio worker threads; only the Slint event loop
        // may touch component properties.
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = weak.upgrade() {
                apply_snapshot(&window, &snapshot);
            }
        });
    });

    let controller =
        AndroidController::start(sink).expect("the Gateway runtime must start on Android");
    let handle = controller.handle();

    wire_callbacks(&window, handle);

    window.run().expect("the Slint event loop must run");

    // Keeping the controller alive until the loop exits means the Gateway task
    // is cancelled and joined on the way out rather than leaked.
    drop(controller);
}

fn wire_callbacks(window: &AppWindow, handle: ControllerHandle) {
    let weak = window.as_weak();
    let connect_handle = handle.clone();
    window.on_connect_requested(move |endpoint, token, allow_plaintext| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        let prepared = ConnectRequest::prepare(endpoint.as_str(), token.as_str(), allow_plaintext);
        // Drop the visible token as soon as it has been captured, whether or not
        // validation succeeded.
        window.invoke_clear_token_input();
        let outcome = match prepared {
            Ok(request) => connect_handle.connect(request),
            Err(rejection) => connect_handle.reject(rejection),
        };
        if let Err(rejection) = outcome {
            apply_error(&window, Some(&rejection.user_error()));
        }
    });

    let weak = window.as_weak();
    window.on_disconnect_requested(move || {
        let Some(window) = weak.upgrade() else {
            return;
        };
        if let Err(rejection) = handle.disconnect() {
            apply_error(&window, Some(&rejection.user_error()));
        }
    });
}

fn apply_snapshot(window: &AppWindow, snapshot: &ViewSnapshot) {
    window.set_title_text(snapshot.title().into());
    window.set_detail_text(snapshot.detail().into());
    window.set_status_label(snapshot.status_label().into());
    window.set_status_kind(status_kind(snapshot.status_kind()));
    window.set_endpoint_summary(snapshot.endpoint_summary().into());
    window.set_server_summary(snapshot.server_summary().into());
    window.set_protocol_summary(snapshot.protocol_summary().into());
    window.set_role_summary(snapshot.role_summary().into());
    window.set_scopes_summary(snapshot.scopes_summary().into());
    window.set_identity_summary(snapshot.identity_summary().into());
    window.set_credential_notice(snapshot.credential_notice().into());
    window.set_transport_notice(snapshot.transport_notice().into());
    window.set_busy(snapshot.busy());
    window.set_can_connect(snapshot.can_connect());
    window.set_can_disconnect(snapshot.can_disconnect());
    apply_error(window, snapshot.error());
}

fn apply_error(window: &AppWindow, error: Option<&UserError>) {
    match error {
        Some(error) => {
            window.set_error_message(error.message().into());
            window.set_error_action(error.action().into());
        }
        None => {
            window.set_error_message("".into());
            window.set_error_action("".into());
        }
    }
}

const fn status_kind(kind: StatusKind) -> UiStatusKind {
    match kind {
        StatusKind::Neutral => UiStatusKind::Neutral,
        StatusKind::Info => UiStatusKind::Info,
        StatusKind::Success => UiStatusKind::Success,
        StatusKind::Warning => UiStatusKind::Warning,
        StatusKind::Danger => UiStatusKind::Danger,
    }
}

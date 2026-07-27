//! Slint event-loop adapter for redaction-safe iOS snapshots.

use std::sync::{Arc, Mutex, PoisonError};

use slint::ComponentHandle;

use crate::controller::{ControllerHandle, SnapshotSink, Tone, UiSnapshot};
use crate::generated_ui::{AppWindow, StatusTone};

const fn status_tone(tone: Tone) -> StatusTone {
    match tone {
        Tone::Neutral => StatusTone::Neutral,
        Tone::Progress => StatusTone::Progress,
        Tone::Success => StatusTone::Success,
        Tone::Warning => StatusTone::Warning,
        Tone::Danger => StatusTone::Danger,
    }
}

fn apply_snapshot(window: &AppWindow, snapshot: &UiSnapshot) {
    window.set_state_title(snapshot.title.as_str().into());
    window.set_state_detail(snapshot.detail.as_str().into());
    window.set_status_label(snapshot.status_label.as_str().into());
    window.set_status_tone(status_tone(snapshot.tone));
    window.set_endpoint_summary(snapshot.endpoint.as_str().into());
    window.set_server_summary(snapshot.server.as_str().into());
    window.set_protocol_summary(snapshot.protocol.as_str().into());
    window.set_authorization_summary(snapshot.authorization.as_str().into());
    window.set_actions_summary(snapshot.available_actions.as_str().into());
    window.set_busy(snapshot.busy);
    window.set_can_connect(snapshot.can_connect);
    window.set_can_cancel(snapshot.can_cancel);
    window.set_can_disconnect(snapshot.can_disconnect);
    window.set_has_error(snapshot.has_error);
    window.set_error_action(snapshot.error_action.as_str().into());
}

pub(crate) fn snapshot_sink(window: &AppWindow) -> SnapshotSink {
    let weak_window = window.as_weak();
    let latest = Arc::new(Mutex::new(None::<UiSnapshot>));
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
            eprintln!("failed to queue iOS UI snapshot: {error}");
        }
    })
}

fn show_form_error(weak_window: &slint::Weak<AppWindow>, message: &str) {
    if let Some(window) = weak_window.upgrade() {
        window.set_form_error(message.into());
    }
}

pub(crate) fn install_callbacks(window: &AppWindow, handle: &ControllerHandle) {
    let connect_handle = handle.clone();
    let weak_window = window.as_weak();
    window.on_connect_requested(move |endpoint, token| {
        match connect_handle.connect(endpoint.to_string(), token.to_string()) {
            Ok(()) => {
                if let Some(window) = weak_window.upgrade() {
                    window.set_form_error("".into());
                    window.set_token_input("".into());
                }
            }
            Err(error) => show_form_error(&weak_window, &error.to_string()),
        }
    });

    let disconnect_handle = handle.clone();
    let weak_window = window.as_weak();
    window.on_disconnect_requested(move || {
        if let Err(error) = disconnect_handle.disconnect() {
            show_form_error(&weak_window, &error.to_string());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::status_tone;
    use crate::controller::Tone;
    use crate::generated_ui::StatusTone;

    #[test]
    fn every_controller_tone_maps_to_the_ui_enum() {
        assert_eq!(status_tone(Tone::Neutral), StatusTone::Neutral);
        assert_eq!(status_tone(Tone::Progress), StatusTone::Progress);
        assert_eq!(status_tone(Tone::Success), StatusTone::Success);
        assert_eq!(status_tone(Tone::Warning), StatusTone::Warning);
        assert_eq!(status_tone(Tone::Danger), StatusTone::Danger);
    }
}

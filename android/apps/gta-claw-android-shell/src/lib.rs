//! Native Slint Android shell over the UI-independent client core.

#[cfg(target_os = "android")]
use std::error::Error;
#[cfg(target_os = "android")]
use std::sync::{Arc, OnceLock};

#[cfg(any(target_os = "android", test))]
use gta_claw_android::controller::ActivityLifecycleEvent;
#[cfg(target_os = "android")]
use gta_claw_android::controller::{
    AndroidController, core_protocol_summary, native_runtime_summary,
};
#[cfg(target_os = "android")]
use gta_claw_android::controller::{CommandRejection, ControllerHandle, SnapshotSink};
#[cfg(target_os = "android")]
use gta_claw_android::onboarding::{ConnectRequest, ViewSnapshot};
#[cfg(any(target_os = "android", test))]
use gta_claw_android::onboarding::{ConnectionPhase, StatusKind};
#[cfg(any(target_os = "android", test))]
use gta_claw_android::platform::AppLifecycle;
#[cfg(target_os = "android")]
use gta_claw_android::platform::{
    DiscoveryReadiness, NetworkStatus, PlatformFacilities, PortablePlatformFacilities,
};
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

#[cfg(any(target_os = "android", test))]
const fn phase_label(phase: ConnectionPhase) -> &'static str {
    match phase {
        ConnectionPhase::Idle => "Idle",
        ConnectionPhase::Suspended => "Suspended",
        ConnectionPhase::WaitingForNetwork => "Waiting for network",
        ConnectionPhase::Connecting => "Connecting",
        ConnectionPhase::Authenticating => "Authenticating",
        ConnectionPhase::Ready => "Ready",
        ConnectionPhase::Reconnecting => "Reconnecting",
        ConnectionPhase::Failed => "Failed",
        ConnectionPhase::Disconnected => "Disconnected",
    }
}

#[cfg(any(target_os = "android", test))]
const fn lifecycle_label(lifecycle: AppLifecycle) -> &'static str {
    match lifecycle {
        AppLifecycle::Foreground => "Foreground",
        AppLifecycle::Background => "Background",
    }
}

#[cfg(any(target_os = "android", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShellLifecycleEvent {
    Start,
    Resume,
    Pause,
    Stop,
    Destroy,
}

#[cfg(any(target_os = "android", test))]
const fn lifecycle_transition(event: ShellLifecycleEvent) -> ActivityLifecycleEvent {
    match event {
        ShellLifecycleEvent::Start | ShellLifecycleEvent::Resume => {
            ActivityLifecycleEvent::Foreground
        }
        ShellLifecycleEvent::Pause => ActivityLifecycleEvent::Paused,
        ShellLifecycleEvent::Stop => ActivityLifecycleEvent::Stopped,
        ShellLifecycleEvent::Destroy => ActivityLifecycleEvent::Destroyed,
    }
}

#[cfg(target_os = "android")]
fn apply_snapshot(window: &AppWindow, snapshot: &ViewSnapshot) {
    window.set_snapshot_revision(snapshot.revision().to_string().into());
    window.set_phase_label(phase_label(snapshot.phase()).into());
    window.set_state_title(snapshot.title().into());
    window.set_state_detail(snapshot.detail().into());
    window.set_status_label(snapshot.status_label().into());
    window.set_status_tone(status_tone(snapshot.status_kind()));
    window.set_lifecycle_label(lifecycle_label(snapshot.lifecycle()).into());
    window.set_network_summary(snapshot.network_summary().into());
    window.set_platform_notice(snapshot.platform_notice().into());
    window.set_endpoint_summary(snapshot.endpoint_summary().into());
    window.set_server_summary(snapshot.server_summary().into());
    window.set_protocol_summary(snapshot.protocol_summary().into());
    window.set_role_summary(snapshot.role_summary().into());
    window.set_scopes_summary(snapshot.scopes_summary().into());
    window.set_connection_epoch(
        snapshot
            .connection_epoch()
            .map_or_else(|| "-".to_owned(), |epoch| epoch.to_string())
            .into(),
    );
    window.set_identity_summary(snapshot.identity_summary().into());
    window.set_credential_notice(snapshot.credential_notice().into());
    window.set_transport_notice(snapshot.transport_notice().into());
    window.set_pending_connection(snapshot.pending_connection());
    window.set_token_offered(snapshot.token_offered());
    window.set_busy(snapshot.busy());
    window.set_can_connect(snapshot.can_connect());
    window.set_can_disconnect(snapshot.can_disconnect());
    window.set_can_retry(snapshot.can_retry());
    if let Some(retry) = snapshot.retry() {
        window.set_retry_summary(
            format!(
                "Attempt {} starts in {} ms.",
                retry.attempt(),
                retry.delay_millis()
            )
            .into(),
        );
        window.set_has_retry(true);
    } else {
        window.set_retry_summary("".into());
        window.set_has_retry(false);
    }
    if let Some(remedy) = snapshot.remedy() {
        window.set_diagnostic_code(format!("{:?}", remedy.diagnostic_code()).into());
        window.set_remedy_kind(format!("{:?}", remedy.kind()).into());
        window.set_error_action(remedy.action().into());
        window.set_has_remedy(true);
    } else {
        window.set_diagnostic_code("".into());
        window.set_remedy_kind("".into());
        window.set_error_action("".into());
        window.set_has_remedy(false);
    }
    if let Some(error) = snapshot.error() {
        window.set_error_message(error.message().into());
        window.set_has_error(true);
    } else {
        window.set_error_message("".into());
        window.set_has_error(false);
    }
}

#[cfg(target_os = "android")]
fn snapshot_sink(window: &AppWindow) -> SnapshotSink {
    let weak_window = window.as_weak();
    Arc::new(move |snapshot| {
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

    let retry_handle = handle.clone();
    let weak_window = window.as_weak();
    window.on_retry_requested(move || {
        if let Err(error) = retry_handle.retry() {
            show_command_error(&weak_window, error);
        }
    });
}

#[cfg(target_os = "android")]
fn report_platform_command(result: Result<(), CommandRejection>, action: &str) {
    if let Err(error) = result {
        eprintln!("failed to report Android {action}: {error}");
    }
}

#[cfg(target_os = "android")]
fn run_android(app: slint::android::AndroidApp) -> Result<(), Box<dyn Error>> {
    use slint::android::android_activity::{MainEvent, PollEvent};

    let lifecycle_handle = Arc::new(OnceLock::<ControllerHandle>::new());
    let event_handle = Arc::clone(&lifecycle_handle);
    slint::android::init_with_event_listener(app, move |event| {
        let lifecycle = match event {
            PollEvent::Main(MainEvent::Start) => Some((ShellLifecycleEvent::Start, "start state")),
            PollEvent::Main(MainEvent::Resume { .. }) => {
                Some((ShellLifecycleEvent::Resume, "resume state"))
            }
            PollEvent::Main(MainEvent::Pause) => Some((ShellLifecycleEvent::Pause, "paused state")),
            PollEvent::Main(MainEvent::Stop) => Some((ShellLifecycleEvent::Stop, "stopped state")),
            PollEvent::Main(MainEvent::Destroy) => {
                Some((ShellLifecycleEvent::Destroy, "destroyed state"))
            }
            _ => None,
        };
        if let Some((event, action)) = lifecycle
            && let Some(handle) = event_handle.get()
        {
            report_platform_command(
                handle.lifecycle_changed(lifecycle_transition(event)),
                action,
            );
        }
    })?;

    let window = AppWindow::new()?;
    window.set_runtime_summary(native_runtime_summary().into());
    window.set_core_protocol(core_protocol_summary(claw_platform::NativeSystemProbe).into());

    let platform: Arc<dyn PlatformFacilities> = Arc::new(PortablePlatformFacilities);
    let controller = AndroidController::start_with_platform(snapshot_sink(&window), platform)?;
    let handle = controller.handle();
    lifecycle_handle
        .set(handle.clone())
        .map_err(|_| "Android lifecycle handle was initialized twice")?;
    report_platform_command(handle.app_foregrounded(), "initial foreground state");
    report_platform_command(
        handle.network_changed(NetworkStatus::Unknown),
        "initial network state",
    );
    report_platform_command(
        handle.discovery_readiness_changed(DiscoveryReadiness::ManualAddressOnly),
        "discovery readiness",
    );
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
    use gta_claw_android::onboarding::{ConnectRequest, ConnectionPhase, ViewModel};
    use gta_claw_android::platform::AppLifecycle;

    use super::{
        ShellLifecycleEvent, lifecycle_label, lifecycle_transition, phase_label, status_tone,
    };
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
        assert_eq!(initial.revision(), 0);
        assert_eq!(initial.phase(), ConnectionPhase::Idle);
        assert!(initial.can_connect());
        assert!(!initial.can_disconnect());

        let request = ConnectRequest::prepare("gateway.example:8443", "", false)
            .expect("secure bare host is valid");
        model.begin(&request);
        let connecting = model.snapshot();
        assert_eq!(connecting.revision(), 1);
        assert_eq!(connecting.phase(), ConnectionPhase::Connecting);
        assert!(!connecting.can_connect());
        assert!(connecting.can_disconnect());
        assert!(connecting.busy());
    }

    #[test]
    fn structured_core_state_has_stable_shell_labels() {
        assert_eq!(phase_label(ConnectionPhase::Suspended), "Suspended");
        assert_eq!(
            phase_label(ConnectionPhase::WaitingForNetwork),
            "Waiting for network"
        );
        assert_eq!(phase_label(ConnectionPhase::Reconnecting), "Reconnecting");
        assert_eq!(lifecycle_label(AppLifecycle::Foreground), "Foreground");
        assert_eq!(lifecycle_label(AppLifecycle::Background), "Background");
    }

    #[test]
    fn native_activity_events_map_to_exact_controller_transitions() {
        use gta_claw_android::controller::ActivityLifecycleEvent;

        assert_eq!(
            lifecycle_transition(ShellLifecycleEvent::Start),
            ActivityLifecycleEvent::Foreground
        );
        assert_eq!(
            lifecycle_transition(ShellLifecycleEvent::Resume),
            ActivityLifecycleEvent::Foreground
        );
        assert_eq!(
            lifecycle_transition(ShellLifecycleEvent::Pause),
            ActivityLifecycleEvent::Paused
        );
        assert_eq!(
            lifecycle_transition(ShellLifecycleEvent::Stop),
            ActivityLifecycleEvent::Stopped
        );
        assert_eq!(
            lifecycle_transition(ShellLifecycleEvent::Destroy),
            ActivityLifecycleEvent::Destroyed
        );
    }
}

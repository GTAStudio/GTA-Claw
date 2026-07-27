//! Native Slint iOS shell over the UI-independent client core.

mod controller;
mod host;
mod ui;

#[expect(
    unreachable_pub,
    reason = "slint::include_modules! emits public generated items kept private by this module"
)]
mod generated_ui {
    slint::include_modules!();
}

fn run_shell() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use controller::IosController;
    use generated_ui::AppWindow;
    use gta_claw_ios::{AppRunState, IosNetworkInterface, IosNetworkPath, IosNetworkRoute};
    use slint::ComponentHandle;

    let host = Arc::new(host::HostBoundaries::new());
    let window = AppWindow::new()?;
    window
        .set_runtime_summary(format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH).into());
    let discovery = host.discovery_diagnostic();
    window.set_discovery_title(discovery.title().into());
    window.set_discovery_explanation(discovery.explanation().into());
    window.set_discovery_action(discovery.remediation().action_label().into());
    window.set_credential_store_notice(host::HostBoundaries::credential_notice().into());
    let controller = IosController::start(ui::snapshot_sink(&window), Arc::clone(&host))?;
    let handle = controller.handle();
    handle.set_run_state(AppRunState::Foreground)?;
    handle.set_network_path(IosNetworkPath::Satisfied(
        IosNetworkRoute::new(1, IosNetworkInterface::Other).with_local_network_available(false),
    ))?;
    ui::install_callbacks(&window, &handle);
    window.run()?;
    drop(controller);
    Ok(())
}

#[cfg(target_os = "ios")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_shell()
}

#[cfg(not(target_os = "ios"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("GTA_CLAW_IOS_HOST_PREVIEW").is_some() {
        return run_shell();
    }
    eprintln!(
        "gta-claw-ios-shell is an iOS application target; use the iOS workspace checks on this host"
    );
    Ok(())
}

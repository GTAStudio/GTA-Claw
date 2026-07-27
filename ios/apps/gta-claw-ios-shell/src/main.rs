//! Native Slint iOS shell over the UI-independent client core.

mod controller;
mod ui;

#[expect(
    unreachable_pub,
    reason = "slint::include_modules! emits public generated items kept private by this module"
)]
mod generated_ui {
    slint::include_modules!();
}

fn run_shell() -> Result<(), Box<dyn std::error::Error>> {
    use controller::IosController;
    use generated_ui::AppWindow;
    use slint::ComponentHandle;

    let window = AppWindow::new()?;
    window
        .set_runtime_summary(format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH).into());
    let controller = IosController::start(ui::snapshot_sink(&window))?;
    ui::install_callbacks(&window, &controller.handle());
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

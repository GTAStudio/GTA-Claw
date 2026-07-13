//! Minimal native desktop shell with Slint retaining ownership of the main thread.

#[cfg(any(target_os = "windows", target_os = "macos"))]
mod ui_adapter;

#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::rc::Rc;

#[cfg(any(target_os = "windows", target_os = "macos"))]
use slint::ComponentHandle;

#[cfg(any(target_os = "windows", target_os = "macos"))]
use ui_adapter::{UiAdapter, UiSnapshot};

#[cfg(any(target_os = "windows", target_os = "macos"))]
#[allow(missing_docs, unreachable_pub)]
mod generated_ui {
    slint::include_modules!();
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
use generated_ui::AppWindow;

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn apply_snapshot(window: &AppWindow, snapshot: &UiSnapshot) {
    window.set_status_text(snapshot.status_text().into());
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn main() -> Result<(), slint::PlatformError> {
    let adapter = Rc::new(UiAdapter::native());
    let window = AppWindow::new()?;

    apply_snapshot(&window, &adapter.snapshot());

    let weak_window = window.as_weak();
    window.on_refresh_requested(move || {
        if let Some(window) = weak_window.upgrade() {
            apply_snapshot(&window, &adapter.snapshot());
        }
    });

    window.run()
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn main() {
    compile_error!("gta-claw-desktop supports only Windows and macOS");
}

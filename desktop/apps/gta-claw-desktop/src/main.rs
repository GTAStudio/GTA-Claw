//! Minimal native desktop shell with Slint retaining ownership of the main thread.

mod ui_adapter;

use std::rc::Rc;

use slint::ComponentHandle;

use ui_adapter::{UiAdapter, UiSnapshot};

#[allow(missing_docs, unreachable_pub)]
mod generated_ui {
    slint::include_modules!();
}

use generated_ui::AppWindow;

fn apply_snapshot(window: &AppWindow, snapshot: &UiSnapshot) {
    window.set_status_text(snapshot.status_text().into());
}

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

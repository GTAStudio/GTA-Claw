//! Minimal native desktop shell with Slint retaining ownership of the main thread.

#[cfg(any(target_os = "windows", target_os = "macos"))]
mod ui_adapter;

#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::{cell::RefCell, rc::Rc};

#[cfg(any(target_os = "windows", target_os = "macos"))]
use slint::ComponentHandle;

#[cfg(any(target_os = "windows", target_os = "macos"))]
use ui_adapter::{
    UiAdapter, UiPaneMode, UiRequest, UiSnapshot, UiStatusKind, UiTheme, VisualPreferencesState,
};

#[cfg(any(target_os = "windows", target_os = "macos"))]
#[allow(missing_docs, unreachable_pub)]
mod generated_ui {
    slint::include_modules!();
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
use generated_ui::{AppWindow, PaneMode, StatusKind, ThemeMode, VisualPreferences};

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn apply_snapshot(window: &AppWindow, snapshot: &UiSnapshot) {
    window.set_status_text(snapshot.status_text().into());
    window.set_status_label(snapshot.status().label().into());
    window.set_status_icon(snapshot.status().icon().into());
    window.set_status_kind(match snapshot.status().kind() {
        UiStatusKind::Neutral => StatusKind::Neutral,
        UiStatusKind::Success => StatusKind::Success,
        UiStatusKind::Warning => StatusKind::Warning,
        UiStatusKind::Danger => StatusKind::Danger,
        UiStatusKind::Info => StatusKind::Info,
    });
    window.set_pane_mode(match snapshot.pane_mode() {
        UiPaneMode::ThreePane => PaneMode::ThreePane,
        UiPaneMode::OverlayInspector => PaneMode::OverlayInspector,
        UiPaneMode::SinglePane => PaneMode::SinglePane,
    });
    apply_visual_preferences(window, snapshot.preferences());
    window.set_navigation_drawer_open(snapshot.navigation_drawer_open());
    window.set_inspector_open(snapshot.inspector_open());
    window.set_inspector_backdrop_active(snapshot.inspector_backdrop_active());
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn apply_visual_preferences(window: &AppWindow, preferences: VisualPreferencesState) {
    window.set_theme_mode(match preferences.theme() {
        UiTheme::Light => ThemeMode::Light,
        UiTheme::Dark => ThemeMode::Dark,
    });
    window.set_high_contrast(preferences.high_contrast());
    window.set_reduced_motion(preferences.reduced_motion());
    window.set_density_scale(preferences.density_scale());
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn update_from_request(
    weak_window: &slint::Weak<AppWindow>,
    adapter: &Rc<RefCell<UiAdapter>>,
    request: UiRequest,
) {
    adapter.borrow_mut().handle_request(request);
    if let Some(window) = weak_window.upgrade() {
        apply_snapshot(&window, &adapter.borrow().snapshot());
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn wire_callbacks(window: &AppWindow, adapter: Rc<RefCell<UiAdapter>>) {
    let weak_window = window.as_weak();
    let callback_adapter = Rc::clone(&adapter);
    window.on_refresh_requested(move || {
        update_from_request(&weak_window, &callback_adapter, UiRequest::Refresh);
    });

    let weak_window = window.as_weak();
    let callback_adapter = Rc::clone(&adapter);
    window.on_navigation_toggle_requested(move || {
        update_from_request(&weak_window, &callback_adapter, UiRequest::ToggleNavigation);
    });

    let weak_window = window.as_weak();
    let callback_adapter = Rc::clone(&adapter);
    window.on_inspector_toggle_requested(move || {
        update_from_request(&weak_window, &callback_adapter, UiRequest::ToggleInspector);
    });

    let weak_window = window.as_weak();
    let callback_adapter = Rc::clone(&adapter);
    window.on_viewport_width_changed(move |width| {
        update_from_request(
            &weak_window,
            &callback_adapter,
            UiRequest::SetViewportWidth(width.max(0.0) as u32),
        );
    });

    let visual_preferences = window.global::<VisualPreferences>();

    let weak_window = window.as_weak();
    let callback_adapter = Rc::clone(&adapter);
    visual_preferences.on_theme_mode_requested(move |theme| {
        let theme = match theme {
            ThemeMode::Light => UiTheme::Light,
            ThemeMode::Dark => UiTheme::Dark,
        };
        update_from_request(&weak_window, &callback_adapter, UiRequest::SetTheme(theme));
    });

    let weak_window = window.as_weak();
    let callback_adapter = Rc::clone(&adapter);
    visual_preferences.on_high_contrast_requested(move |enabled| {
        update_from_request(
            &weak_window,
            &callback_adapter,
            UiRequest::SetHighContrast(enabled),
        );
    });

    let weak_window = window.as_weak();
    let callback_adapter = Rc::clone(&adapter);
    visual_preferences.on_reduced_motion_requested(move |enabled| {
        update_from_request(
            &weak_window,
            &callback_adapter,
            UiRequest::SetReducedMotion(enabled),
        );
    });

    let weak_window = window.as_weak();
    visual_preferences.on_density_scale_requested(move |scale| {
        update_from_request(&weak_window, &adapter, UiRequest::SetDensityScale(scale));
    });
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn sync_viewport(window: &AppWindow) {
    window.invoke_viewport_width_changed(window.get_layout_width());
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn main() -> Result<(), slint::PlatformError> {
    let adapter = Rc::new(RefCell::new(UiAdapter::native()));
    let window = AppWindow::new()?;

    apply_snapshot(&window, &adapter.borrow().snapshot());
    wire_callbacks(&window, adapter);
    sync_viewport(&window);

    window.run()
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn main() {
    compile_error!("gta-claw-desktop supports only Windows and macOS");
}

#[cfg(all(test, any(target_os = "windows", target_os = "macos")))]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use slint::ComponentHandle;

    use super::{
        generated_ui::{AppWindow, DesignTokens, PaneMode, ThemeMode, VisualPreferences},
        ui_adapter::UiAdapter,
        wire_callbacks,
    };

    #[cfg(target_os = "macos")]
    type GeneratedContract = fn(&AppWindow, Rc<RefCell<UiAdapter>>);

    fn exercise_generated_contracts(window: &AppWindow, adapter: Rc<RefCell<UiAdapter>>) {
        super::apply_snapshot(window, &adapter.borrow().snapshot());
        wire_callbacks(window, Rc::clone(&adapter));

        window.set_layout_width(1_180.0);
        super::sync_viewport(window);
        assert_eq!(window.get_pane_mode(), PaneMode::ThreePane);
        window.set_layout_width(1_179.0);
        super::sync_viewport(window);
        assert_eq!(window.get_pane_mode(), PaneMode::OverlayInspector);
        window.set_layout_width(839.0);
        super::sync_viewport(window);
        assert_eq!(window.get_pane_mode(), PaneMode::SinglePane);
        window.invoke_inspector_toggle_requested();
        assert!(window.get_inspector_backdrop_active());
        window.invoke_inspector_toggle_requested();
        assert!(!window.get_inspector_backdrop_active());

        window.set_layout_width(1_179.0);
        super::sync_viewport(window);
        window.invoke_inspector_toggle_requested();
        assert!(window.get_inspector_backdrop_active());
        window.invoke_inspector_toggle_requested();
        assert!(!window.get_inspector_backdrop_active());

        window.set_layout_width(1_180.0);
        super::sync_viewport(window);
        window.invoke_inspector_toggle_requested();
        assert!(!window.get_inspector_backdrop_active());

        let regular_success = window.global::<DesignTokens>().get_success();
        window
            .global::<VisualPreferences>()
            .invoke_theme_mode_requested(ThemeMode::Dark);
        window
            .global::<VisualPreferences>()
            .invoke_high_contrast_requested(true);
        window
            .global::<VisualPreferences>()
            .invoke_reduced_motion_requested(true);
        window
            .global::<VisualPreferences>()
            .invoke_density_scale_requested(2.0);

        assert_eq!(window.get_theme_mode(), ThemeMode::Dark);
        assert!(window.get_high_contrast());
        assert!(window.get_reduced_motion());
        assert_eq!(window.get_density_scale(), 1.35);
        assert_ne!(
            regular_success,
            window.global::<DesignTokens>().get_success()
        );

        window.set_layout_width(839.0);
        super::sync_viewport(window);
        window.invoke_navigation_toggle_requested();
        assert!(window.get_navigation_drawer_open());
        window.invoke_inspector_toggle_requested();
        assert!(!window.get_navigation_drawer_open());
        assert!(window.get_inspector_open());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn component_contracts_and_callbacks_use_stable_generated_apis() {
        let adapter = Rc::new(RefCell::new(UiAdapter::native()));
        let window = AppWindow::new().expect("component construction must succeed");
        exercise_generated_contracts(&window, Rc::clone(&adapter));

        drop(window);
        assert_eq!(Rc::strong_count(&adapter), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_component_contracts_compile_without_worker_thread_window_creation() {
        let contract: GeneratedContract = exercise_generated_contracts;
        assert_eq!(
            std::mem::size_of_val(&contract),
            std::mem::size_of::<GeneratedContract>()
        );
    }

    #[test]
    fn modal_sheet_contract_keeps_pointer_and_focus_guards() {
        let primitives = include_str!("../ui/modules/primitives.slint");
        let shell = include_str!("../ui/modules/shell.slint");

        assert!(primitives.contains("sheet-pointer-guard := TouchArea"));
        assert!(primitives.contains("before-focus-boundary := FocusScope"));
        assert!(primitives.contains("after-focus-boundary := FocusScope"));
        assert!(primitives.contains("footer-close-button := SecondaryButton"));
        assert!(shell.contains("enabled: !root.navigation-drawer-open && !root.inspector-open"));
        assert!(shell.contains("navigation-toggle-button.restore-focus()"));
        assert!(shell.contains("inspector-toggle-button.restore-focus()"));
        assert!(shell.contains("if (root.inspector-backdrop-active) : Rectangle"));
    }
}

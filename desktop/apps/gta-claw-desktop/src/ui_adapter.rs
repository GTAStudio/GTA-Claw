use claw_application::Application;
use claw_platform::NativeSystemProbe;

const MINIMUM_DENSITY_SCALE: f32 = 0.85;
const MAXIMUM_DENSITY_SCALE: f32 = 1.35;

/// The only boundary between generated Slint UI code and the application core.
#[derive(Debug)]
pub(crate) struct UiAdapter {
    application: Application<NativeSystemProbe>,
    preferences: VisualPreferencesState,
    pane_mode: UiPaneMode,
    navigation_drawer_open: bool,
    inspector_open: bool,
}

impl UiAdapter {
    pub(crate) fn native() -> Self {
        Self {
            application: Application::new(NativeSystemProbe),
            preferences: VisualPreferencesState::default(),
            pane_mode: UiPaneMode::ThreePane,
            navigation_drawer_open: false,
            inspector_open: false,
        }
    }

    pub(crate) fn snapshot(&self) -> UiSnapshot {
        let status_text = self.application.health().to_string();

        UiSnapshot {
            status: StatusPresentation::from_runtime_text(&status_text),
            status_text,
            preferences: self.preferences,
            pane_mode: self.pane_mode,
            navigation_drawer_open: self.navigation_drawer_open,
            inspector_open: self.inspector_open,
        }
    }

    pub(crate) fn handle_request(&mut self, request: UiRequest) {
        match request {
            UiRequest::Refresh => {}
            UiRequest::ToggleNavigation => {
                self.navigation_drawer_open = !self.navigation_drawer_open;
                if self.navigation_drawer_open {
                    self.inspector_open = false;
                }
            }
            UiRequest::ToggleInspector => {
                self.inspector_open = !self.inspector_open;
                if self.inspector_open {
                    self.navigation_drawer_open = false;
                }
            }
            UiRequest::SetTheme(theme) => {
                self.preferences.theme = theme;
            }
            UiRequest::SetHighContrast(enabled) => {
                self.preferences.high_contrast = enabled;
            }
            UiRequest::SetReducedMotion(enabled) => {
                self.preferences.reduced_motion = enabled;
            }
            UiRequest::SetDensityScale(scale) => {
                self.preferences.density_scale =
                    scale.clamp(MINIMUM_DENSITY_SCALE, MAXIMUM_DENSITY_SCALE);
            }
            UiRequest::SetViewportWidth(width) => {
                let pane_mode = UiPaneMode::for_width(width);
                if pane_mode != self.pane_mode {
                    self.pane_mode = pane_mode;
                    self.navigation_drawer_open = false;
                    self.inspector_open = false;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UiTheme {
    Light,
    Dark,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct VisualPreferencesState {
    theme: UiTheme,
    high_contrast: bool,
    reduced_motion: bool,
    density_scale: f32,
}

impl Default for VisualPreferencesState {
    fn default() -> Self {
        Self {
            theme: UiTheme::Light,
            high_contrast: false,
            reduced_motion: false,
            density_scale: 1.0,
        }
    }
}

impl VisualPreferencesState {
    pub(crate) fn theme(self) -> UiTheme {
        self.theme
    }

    pub(crate) fn high_contrast(self) -> bool {
        self.high_contrast
    }

    pub(crate) fn reduced_motion(self) -> bool {
        self.reduced_motion
    }

    pub(crate) fn density_scale(self) -> f32 {
        self.density_scale
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UiStatusKind {
    Neutral,
    Success,
    Warning,
    Danger,
    Info,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StatusPresentation {
    kind: UiStatusKind,
    label: &'static str,
    icon: &'static str,
}

impl StatusPresentation {
    fn from_runtime_text(status_text: &str) -> Self {
        if status_text.starts_with("healthy runtime=") {
            Self {
                kind: UiStatusKind::Success,
                label: "Success",
                icon: "OK",
            }
        } else if status_text.is_empty() {
            Self {
                kind: UiStatusKind::Neutral,
                label: "Status",
                icon: "-",
            }
        } else if status_text.contains("error")
            || status_text.contains("unavailable")
            || status_text.contains("unhealthy")
        {
            Self {
                kind: UiStatusKind::Danger,
                label: "Danger",
                icon: "X",
            }
        } else if status_text.starts_with("info") {
            Self {
                kind: UiStatusKind::Info,
                label: "Information",
                icon: "i",
            }
        } else {
            Self {
                kind: UiStatusKind::Warning,
                label: "Warning",
                icon: "!",
            }
        }
    }

    pub(crate) fn kind(self) -> UiStatusKind {
        self.kind
    }

    pub(crate) fn label(self) -> &'static str {
        self.label
    }

    pub(crate) fn icon(self) -> &'static str {
        self.icon
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UiPaneMode {
    ThreePane,
    OverlayInspector,
    SinglePane,
}

impl UiPaneMode {
    pub(crate) fn for_width(width: u32) -> Self {
        if width >= 1_180 {
            Self::ThreePane
        } else if width >= 840 {
            Self::OverlayInspector
        } else {
            Self::SinglePane
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum UiRequest {
    Refresh,
    ToggleNavigation,
    ToggleInspector,
    SetTheme(UiTheme),
    SetHighContrast(bool),
    SetReducedMotion(bool),
    SetDensityScale(f32),
    SetViewportWidth(u32),
}

#[derive(Debug, PartialEq)]
pub(crate) struct UiSnapshot {
    status_text: String,
    status: StatusPresentation,
    preferences: VisualPreferencesState,
    pane_mode: UiPaneMode,
    navigation_drawer_open: bool,
    inspector_open: bool,
}

impl UiSnapshot {
    pub(crate) fn status_text(&self) -> &str {
        &self.status_text
    }

    pub(crate) fn status(&self) -> StatusPresentation {
        self.status
    }

    pub(crate) fn preferences(&self) -> VisualPreferencesState {
        self.preferences
    }

    pub(crate) fn pane_mode(&self) -> UiPaneMode {
        self.pane_mode
    }

    pub(crate) fn navigation_drawer_open(&self) -> bool {
        self.navigation_drawer_open
    }

    pub(crate) fn inspector_open(&self) -> bool {
        self.inspector_open
    }
}

#[cfg(test)]
mod tests {
    use super::{UiAdapter, UiPaneMode, UiRequest, UiStatusKind, UiTheme};

    #[test]
    fn snapshot_exposes_headless_runtime_health() {
        let snapshot = UiAdapter::native().snapshot();

        assert!(snapshot.status_text().starts_with("healthy runtime="));
        assert_eq!(snapshot.status().kind(), UiStatusKind::Success);
        assert_eq!(snapshot.status().label(), "Success");
        assert_eq!(snapshot.status().icon(), "OK");
    }

    #[test]
    fn visual_requests_update_the_rust_source_of_truth() {
        let mut adapter = UiAdapter::native();

        adapter.handle_request(UiRequest::SetTheme(UiTheme::Dark));
        adapter.handle_request(UiRequest::SetHighContrast(true));
        adapter.handle_request(UiRequest::SetReducedMotion(true));
        adapter.handle_request(UiRequest::SetDensityScale(2.0));

        let preferences = adapter.snapshot().preferences();
        assert_eq!(preferences.theme(), UiTheme::Dark);
        assert!(preferences.high_contrast());
        assert!(preferences.reduced_motion());
        assert_eq!(preferences.density_scale(), 1.35);
    }

    #[test]
    fn high_contrast_keeps_status_text_and_icon_semantics() {
        let mut adapter = UiAdapter::native();
        adapter.handle_request(UiRequest::SetHighContrast(true));

        let snapshot = adapter.snapshot();
        assert!(snapshot.preferences().high_contrast());
        assert_eq!(snapshot.status().label(), "Success");
        assert_eq!(snapshot.status().icon(), "OK");
        assert!(!snapshot.status_text().is_empty());
    }

    #[test]
    fn status_classification_covers_non_color_semantics() {
        let neutral = super::StatusPresentation::from_runtime_text("");
        assert_eq!(neutral.kind(), UiStatusKind::Neutral);
        assert_eq!(neutral.icon(), "-");

        let danger = super::StatusPresentation::from_runtime_text("runtime unavailable");
        assert_eq!(danger.kind(), UiStatusKind::Danger);
        assert_eq!(danger.label(), "Danger");

        let info = super::StatusPresentation::from_runtime_text("info: reconnecting");
        assert_eq!(info.kind(), UiStatusKind::Info);
        assert_eq!(info.icon(), "i");
    }

    #[test]
    fn breakpoints_select_the_planned_pane_modes() {
        assert_eq!(UiPaneMode::for_width(1_180), UiPaneMode::ThreePane);
        assert_eq!(UiPaneMode::for_width(1_179), UiPaneMode::OverlayInspector);
        assert_eq!(UiPaneMode::for_width(840), UiPaneMode::OverlayInspector);
        assert_eq!(UiPaneMode::for_width(839), UiPaneMode::SinglePane);
        assert_eq!(UiPaneMode::for_width(720), UiPaneMode::SinglePane);
    }

    #[test]
    fn viewport_requests_drive_pane_state_and_close_stale_overlays() {
        let mut adapter = UiAdapter::native();
        adapter.handle_request(UiRequest::SetViewportWidth(900));
        adapter.handle_request(UiRequest::ToggleInspector);
        assert!(adapter.snapshot().inspector_open());

        adapter.handle_request(UiRequest::SetViewportWidth(720));
        let snapshot = adapter.snapshot();
        assert_eq!(snapshot.pane_mode(), UiPaneMode::SinglePane);
        assert!(!snapshot.inspector_open());
        assert!(!snapshot.navigation_drawer_open());
    }

    #[test]
    fn drawer_requests_keep_overlays_mutually_exclusive() {
        let mut adapter = UiAdapter::native();

        adapter.handle_request(UiRequest::ToggleNavigation);
        assert!(adapter.snapshot().navigation_drawer_open());

        adapter.handle_request(UiRequest::ToggleInspector);
        let snapshot = adapter.snapshot();
        assert!(!snapshot.navigation_drawer_open());
        assert!(snapshot.inspector_open());
    }
}

const MINIMUM_DENSITY_SCALE: f32 = 0.85;
const MAXIMUM_DENSITY_SCALE: f32 = 1.35;

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
    pub(crate) const fn theme(self) -> UiTheme {
        self.theme
    }

    pub(crate) const fn high_contrast(self) -> bool {
        self.high_contrast
    }

    pub(crate) const fn reduced_motion(self) -> bool {
        self.reduced_motion
    }

    pub(crate) const fn density_scale(self) -> f32 {
        self.density_scale
    }

    pub(crate) fn set_theme(&mut self, theme: UiTheme) {
        self.theme = theme;
    }

    pub(crate) fn set_high_contrast(&mut self, enabled: bool) {
        self.high_contrast = enabled;
    }

    pub(crate) fn set_reduced_motion(&mut self, enabled: bool) {
        self.reduced_motion = enabled;
    }

    pub(crate) fn set_density_scale(&mut self, scale: f32) {
        self.density_scale = scale.clamp(MINIMUM_DENSITY_SCALE, MAXIMUM_DENSITY_SCALE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visual_preferences_remain_rust_owned_and_bounded() {
        let mut state = VisualPreferencesState::default();
        state.set_theme(UiTheme::Dark);
        state.set_high_contrast(true);
        state.set_reduced_motion(true);
        state.set_density_scale(2.0);

        assert_eq!(state.theme(), UiTheme::Dark);
        assert!(state.high_contrast());
        assert!(state.reduced_motion());
        assert_eq!(state.density_scale(), MAXIMUM_DENSITY_SCALE);
    }
}

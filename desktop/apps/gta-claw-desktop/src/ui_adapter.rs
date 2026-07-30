const MINIMUM_DENSITY_SCALE: f32 = 0.8;
const MAXIMUM_DENSITY_SCALE: f32 = 2.0;
const DEFAULT_DENSITY_SCALE: f32 = 1.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UiTheme {
    Light,
    Dark,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreferenceLifetime {
    SessionOnly,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct VisualPreferencesState {
    theme: UiTheme,
    theme_override_active: bool,
    high_contrast: bool,
    reduced_motion: bool,
    density_scale: f32,
}

impl Default for VisualPreferencesState {
    fn default() -> Self {
        Self {
            theme: UiTheme::Light,
            theme_override_active: false,
            high_contrast: false,
            reduced_motion: false,
            density_scale: DEFAULT_DENSITY_SCALE,
        }
    }
}

impl VisualPreferencesState {
    pub(crate) const fn theme(self) -> UiTheme {
        self.theme
    }

    pub(crate) const fn theme_override_active(self) -> bool {
        self.theme_override_active
    }

    pub(crate) const fn lifetime(self) -> PreferenceLifetime {
        PreferenceLifetime::SessionOnly
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

    pub(crate) const fn set_theme_override(&mut self, theme: UiTheme) {
        self.theme = theme;
        self.theme_override_active = true;
    }

    pub(crate) const fn follow_system_theme(&mut self, theme: UiTheme) {
        self.theme = theme;
        self.theme_override_active = false;
    }

    pub(crate) const fn set_high_contrast(&mut self, enabled: bool) {
        self.high_contrast = enabled;
    }

    pub(crate) const fn set_reduced_motion(&mut self, enabled: bool) {
        self.reduced_motion = enabled;
    }

    pub(crate) fn set_density_scale(&mut self, scale: f32) {
        self.density_scale = normalize_density_scale(scale);
    }
}

fn normalize_density_scale(scale: f32) -> f32 {
    if scale.is_nan() {
        DEFAULT_DENSITY_SCALE
    } else if !scale.is_finite() {
        if scale.is_sign_positive() {
            MAXIMUM_DENSITY_SCALE
        } else {
            MINIMUM_DENSITY_SCALE
        }
    } else {
        scale.clamp(MINIMUM_DENSITY_SCALE, MAXIMUM_DENSITY_SCALE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visual_preferences_are_session_only_rust_owned_and_bounded() {
        let mut state = VisualPreferencesState::default();
        assert_eq!(state.lifetime(), PreferenceLifetime::SessionOnly);
        assert!(!state.theme_override_active());

        state.set_theme_override(UiTheme::Dark);
        state.set_high_contrast(true);
        state.set_reduced_motion(true);
        state.set_density_scale(2.0);

        assert_eq!(state.theme(), UiTheme::Dark);
        assert!(state.theme_override_active());
        assert!(state.high_contrast());
        assert!(state.reduced_motion());
        assert_eq!(
            state.density_scale().to_bits(),
            MAXIMUM_DENSITY_SCALE.to_bits(),
            "clamping must reach the upper bound exactly"
        );

        state.set_density_scale(0.1);
        assert_eq!(
            state.density_scale().to_bits(),
            MINIMUM_DENSITY_SCALE.to_bits(),
            "clamping must reach the lower bound exactly"
        );

        state.follow_system_theme(UiTheme::Light);
        assert_eq!(state.theme(), UiTheme::Light);
        assert!(!state.theme_override_active());
    }

    #[test]
    fn density_normalization_is_always_finite_and_bounded() {
        let mut state = VisualPreferencesState::default();
        for input in [
            f32::NAN,
            f32::from_bits(0xffc0_0001),
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::MAX,
            f32::MIN,
            0.0,
            -0.0,
        ] {
            state.set_density_scale(input);
            assert!(state.density_scale().is_finite());
            assert!(
                (MINIMUM_DENSITY_SCALE..=MAXIMUM_DENSITY_SCALE)
                    .contains(&state.density_scale())
            );
        }
        state.set_density_scale(f32::NAN);
        assert_eq!(
            state.density_scale().to_bits(),
            DEFAULT_DENSITY_SCALE.to_bits()
        );
        state.set_density_scale(f32::INFINITY);
        assert_eq!(
            state.density_scale().to_bits(),
            MAXIMUM_DENSITY_SCALE.to_bits()
        );
        state.set_density_scale(f32::NEG_INFINITY);
        assert_eq!(
            state.density_scale().to_bits(),
            MINIMUM_DENSITY_SCALE.to_bits()
        );

        let mut bits = 0x1234_5678_u32;
        for _ in 0..16_384 {
            bits = bits.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state.set_density_scale(f32::from_bits(bits));
            assert!(state.density_scale().is_finite());
            assert!(
                (MINIMUM_DENSITY_SCALE..=MAXIMUM_DENSITY_SCALE)
                    .contains(&state.density_scale())
            );
        }
    }
}

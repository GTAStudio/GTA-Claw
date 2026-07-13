use claw_application::Application;
use claw_platform::NativeSystemProbe;

/// The only boundary between generated Slint UI code and the application core.
#[derive(Debug)]
pub(crate) struct UiAdapter {
    application: Application<NativeSystemProbe>,
}

impl UiAdapter {
    pub(crate) fn native() -> Self {
        Self {
            application: Application::new(NativeSystemProbe),
        }
    }

    pub(crate) fn snapshot(&self) -> UiSnapshot {
        UiSnapshot {
            status_text: self.application.health().to_string(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct UiSnapshot {
    status_text: String,
}

impl UiSnapshot {
    pub(crate) fn status_text(&self) -> &str {
        &self.status_text
    }
}

#[cfg(test)]
mod tests {
    use super::UiAdapter;

    #[test]
    fn snapshot_exposes_headless_runtime_health() {
        let snapshot = UiAdapter::native().snapshot();

        assert!(snapshot.status_text().starts_with("healthy runtime="));
    }
}

//! Supervised signed-update checks.

use std::sync::Arc;
use std::time::Duration;

use claw_provider_sdk::http::ProxyPolicy;
use gta_claw_updater::{UpdateDecision, Updater};
use semver::Version;
use tokio::task::JoinHandle;
use url::Url;

use super::http_api::Diagnostics;

const UPDATE_MANIFEST_ENV: &str = "GTA_CLAW_UPDATE_MANIFEST";
const UPDATE_TARGET_ENV: &str = "GTA_CLAW_UPDATE_TARGET";

/// One optional background signed-manifest check.
pub struct UpdateMonitor {
    task: Option<JoinHandle<()>>,
}

impl Drop for UpdateMonitor {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl UpdateMonitor {
    /// Starts the signed check when updates are enabled.
    ///
    /// # Errors
    ///
    /// Returns an actionable configuration error when enabled checks have no
    /// manifest URL/target triple or the updater trust client cannot start.
    pub fn start(
        enabled: bool,
        proxy: &ProxyPolicy,
        diagnostics: Arc<Diagnostics>,
    ) -> Result<Self, String> {
        if !enabled {
            return Ok(Self { task: None });
        }

        if !matches!(proxy, ProxyPolicy::FromEnvironment) {
            return Err(
                "the updater cannot honor the selected shared proxy policy; disable updates or use environment proxy policy"
                    .to_owned(),
            );
        }
        let manifest = std::env::var(UPDATE_MANIFEST_ENV)
            .map_err(|_| format!("{UPDATE_MANIFEST_ENV} is required when updates are enabled"))?;
        let target = std::env::var(UPDATE_TARGET_ENV)
            .map_err(|_| format!("{UPDATE_TARGET_ENV} is required when updates are enabled"))?;
        let manifest = Url::parse(&manifest)
            .map_err(|error| format!("{UPDATE_MANIFEST_ENV} is invalid: {error}"))?;
        let current = Version::parse(env!("CARGO_PKG_VERSION"))
            .map_err(|error| format!("daemon version is invalid: {error}"))?;
        let updater = Updater::production(target).map_err(|error| error.to_string())?;
        let task = tokio::spawn(async move {
            match updater.check(&manifest, &current).await {
                Ok(UpdateDecision::Current { version }) => {
                    diagnostics.record(format!("updater: current version {version}"));
                }
                Ok(UpdateDecision::Available { version, .. }) => {
                    diagnostics.record(format!("updater: signed version {version} is available"));
                }
                Err(error) => diagnostics.record(format!("updater check failed: {error}")),
            }
        });
        Ok(Self { task: Some(task) })
    }

    /// Joins the check within `budget`, aborting network work at the deadline.
    pub async fn shutdown(&mut self, budget: Duration) -> bool {
        let Some(mut task) = self.task.take() else {
            return true;
        };
        match tokio::time::timeout(budget, &mut task).await {
            Ok(Ok(())) => return true,
            Ok(Err(_)) => return false,
            Err(_) => {}
        }
        task.abort();
        if tokio::time::timeout(Duration::ZERO, &mut task)
            .await
            .is_err()
        {
            return false;
        }
        false
    }

    /// Reports whether a check task exists.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.task.is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::UpdateMonitor;

    #[tokio::test]
    async fn forced_abort_join_never_exceeds_the_shutdown_budget() {
        let task = tokio::spawn(std::future::pending::<()>());
        let mut monitor = UpdateMonitor { task: Some(task) };
        let started = Instant::now();

        assert!(!monitor.shutdown(Duration::from_millis(25)).await);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "post-abort updater join was unbounded"
        );
    }
}

//! Startup configuration for the headless daemon.
//!
//! The daemon owns no configuration format of its own. It hands the process
//! environment to [`claw_config`], whose frozen migration contract maps the
//! legacy environment surface onto a validated snapshot, and then derives only
//! the few process-level facts a listener needs.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use claw_config::{
    ConfigSnapshot, MigrationDiagnostic, MigrationError, migrate_legacy_environment,
};

/// Interface the headless daemon listens on.
///
/// The legacy Node server bound every interface so that a published container
/// port reached the process. That behavior is preserved exactly.
const LISTEN_INTERFACE: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Process-level settings derived from a validated configuration snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonSettings {
    listen_address: SocketAddr,
    public_domain: String,
    manual_migrations: Vec<ManualMigration>,
}

/// One legacy value that this runtime intentionally cannot apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManualMigration {
    legacy_env: &'static str,
    target: &'static str,
    reason: &'static str,
}

impl Display for ManualMigration {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} -> {}: {}",
            self.legacy_env, self.target, self.reason
        )
    }
}

impl DaemonSettings {
    /// Returns the address the HTTP listener must bind.
    pub(crate) const fn listen_address(&self) -> SocketAddr {
        self.listen_address
    }

    /// Returns the externally advertised domain.
    pub(crate) fn public_domain(&self) -> &str {
        &self.public_domain
    }

    /// Returns the legacy values that require operator action.
    pub(crate) fn manual_migrations(&self) -> &[ManualMigration] {
        &self.manual_migrations
    }

    fn from_snapshot(snapshot: &ConfigSnapshot, diagnostics: &[MigrationDiagnostic]) -> Self {
        let server = snapshot.core().server();
        Self {
            listen_address: SocketAddr::new(LISTEN_INTERFACE, server.port()),
            public_domain: server.public_domain().to_owned(),
            manual_migrations: diagnostics
                .iter()
                .map(|diagnostic| match diagnostic {
                    MigrationDiagnostic::ManualRequired(mapping) => ManualMigration {
                        legacy_env: mapping.legacy_env,
                        target: mapping.target,
                        reason: mapping.reason,
                    },
                })
                .collect(),
        }
    }
}

/// A startup configuration failure that must stop the process.
#[derive(Debug)]
pub(crate) enum SettingsError {
    /// The supplied environment could not be converted into valid configuration.
    Invalid(MigrationError),
}

impl Display for SettingsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => write!(
                formatter,
                "configuration is invalid, refusing to start half-configured: {error}"
            ),
        }
    }
}

impl Error for SettingsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invalid(error) => Some(error),
        }
    }
}

/// Converts supplied environment entries into process settings.
///
/// This function is pure so that startup failures are testable without
/// mutating the environment of a running test process.
pub(crate) fn load<'a>(
    variables: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<DaemonSettings, SettingsError> {
    let migration = migrate_legacy_environment(variables).map_err(SettingsError::Invalid)?;

    Ok(DaemonSettings::from_snapshot(
        &migration.config,
        &migration.diagnostics,
    ))
}

/// Reads the process environment, skipping entries that are not UTF-8.
///
/// Non-UTF-8 entries can never match the frozen ASCII mapping names, so they
/// are irrelevant rather than fatal.
pub(crate) fn process_environment() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{DaemonSettings, SettingsError, load};

    /// The smallest environment the frozen contract accepts, mirroring the
    /// legacy requirements that a role source is present and that a PAT is
    /// present unless device flow is enabled.
    const MINIMAL: &[(&str, &str)] = &[
        ("AGENT_ROLE_URL", "https://roles.example.com/role.json"),
        ("ENABLE_TEAMS", "false"),
        ("GITHUB_TOKEN", "test-token"),
    ];

    fn load_with(extra: &[(&str, &str)]) -> Result<DaemonSettings, SettingsError> {
        load(MINIMAL.iter().chain(extra.iter()).copied())
    }

    #[test]
    fn minimal_environment_yields_the_default_listener() {
        let settings = load_with(&[]).expect("default configuration is valid");

        assert_eq!(
            settings.listen_address().ip(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(settings.listen_address().port(), 3978);
        assert_eq!(settings.public_domain(), "localhost");
        assert!(settings.manual_migrations().is_empty());
    }

    #[test]
    fn legacy_port_selects_the_listening_port() {
        let settings = load_with(&[("PORT", "8123")]).expect("port configuration is valid");

        assert_eq!(settings.listen_address().port(), 8123);
    }

    #[test]
    fn missing_credentials_stop_startup() {
        let error = load(std::iter::empty()).expect_err("an empty environment must fail");

        assert!(
            error.to_string().contains("core.auth.github.pat"),
            "unexpected operator message: {error}"
        );
    }

    #[test]
    fn invalid_port_stops_startup_with_an_operator_message() {
        let error = load_with(&[("PORT", "not-a-port")]).expect_err("invalid port must fail");

        let SettingsError::Invalid(_) = &error;
        let message = error.to_string();
        assert!(
            message.starts_with("configuration is invalid, refusing to start half-configured:"),
            "unexpected operator message: {message}"
        );
        assert!(
            message.contains("PORT"),
            "operator message omitted the failing variable: {message}"
        );
    }

    #[test]
    fn out_of_range_port_is_rejected_rather_than_truncated() {
        let error = load_with(&[("PORT", "70000")]).expect_err("out of range port must fail");

        assert!(
            error.to_string().contains("must be from 1 through 65535"),
            "unexpected operator message: {error}"
        );
    }

    #[test]
    fn deploy_only_values_are_reported_as_manual_migrations() {
        let settings = load_with(&[("DOCKER_IMAGE", "example/image:1")])
            .expect("deploy-only values do not stop startup");

        let reported: Vec<String> = settings
            .manual_migrations()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(reported.len(), 1, "unexpected diagnostics: {reported:?}");
        assert!(
            reported[0].starts_with("DOCKER_IMAGE ->"),
            "unexpected diagnostic: {}",
            reported[0]
        );
    }
}

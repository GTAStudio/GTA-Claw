use std::sync::Arc;

use crate::{ConfigDomain, ConfigError, ConfigSnapshot, parse_json5};

/// Result of atomically publishing a validated reload candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadOutcome {
    /// Domains whose values changed.
    pub changed_domains: Vec<ConfigDomain>,
    /// Changed domains that require a process restart to take effect safely.
    pub restart_required_domains: Vec<ConfigDomain>,
    /// Newly published immutable snapshot.
    pub snapshot: Arc<ConfigSnapshot>,
}

/// Transactional owner of the last-known-good configuration snapshot.
#[derive(Clone, Debug)]
pub struct ReloadManager {
    current: Arc<ConfigSnapshot>,
}

impl ReloadManager {
    /// Creates a manager from an already validated snapshot.
    #[must_use]
    pub fn new(initial: ConfigSnapshot) -> Self {
        Self {
            current: Arc::new(initial),
        }
    }

    /// Returns the currently published last-known-good snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<ConfigSnapshot> {
        Arc::clone(&self.current)
    }

    /// Parses and validates a complete candidate before publishing it.
    ///
    /// Any error leaves the previous snapshot unchanged.
    pub fn reload_json5(
        &mut self,
        source: &str,
        source_name: &str,
    ) -> Result<ReloadOutcome, ConfigError> {
        let candidate = parse_json5(source, source_name)?;
        let changed_domains = changed_domains(&self.current, &candidate);
        let restart_required_domains = changed_domains
            .iter()
            .copied()
            .filter(|domain| restart_required(*domain))
            .collect();
        let snapshot = Arc::new(candidate);
        self.current = Arc::clone(&snapshot);
        Ok(ReloadOutcome {
            changed_domains,
            restart_required_domains,
            snapshot,
        })
    }
}

fn changed_domains(previous: &ConfigSnapshot, candidate: &ConfigSnapshot) -> Vec<ConfigDomain> {
    let previous = previous.core();
    let candidate = candidate.core();
    let comparisons = [
        (ConfigDomain::Auth, previous.auth != candidate.auth),
        (ConfigDomain::Role, previous.role != candidate.role),
        (
            ConfigDomain::Channels,
            previous.channels != candidate.channels,
        ),
        (ConfigDomain::Server, previous.server != candidate.server),
        (ConfigDomain::Logging, previous.logging != candidate.logging),
        (
            ConfigDomain::Sessions,
            previous.sessions != candidate.sessions,
        ),
        (ConfigDomain::Copilot, previous.copilot != candidate.copilot),
        (
            ConfigDomain::LegacySkills,
            previous.legacy_skills != candidate.legacy_skills,
        ),
        (ConfigDomain::Updates, previous.updates != candidate.updates),
        (ConfigDomain::Admin, previous.admin != candidate.admin),
        (ConfigDomain::Network, previous.network != candidate.network),
    ];
    comparisons
        .into_iter()
        .filter_map(|(domain, changed)| changed.then_some(domain))
        .collect()
}

const fn restart_required(domain: ConfigDomain) -> bool {
    matches!(
        domain,
        ConfigDomain::Auth
            | ConfigDomain::Channels
            | ConfigDomain::Server
            | ConfigDomain::Admin
            | ConfigDomain::Network
    )
}

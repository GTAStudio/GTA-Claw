//! Validated subsystem identifiers and the well-known set the daemon composes.

use std::fmt::{self, Display, Formatter};

use super::error::CompositionError;

const MAX_SUBSYSTEM_ID_BYTES: usize = 64;

/// The name a subsystem is known by inside one composition.
///
/// Identifiers are the vertices of the dependency graph, so they are validated
/// once on construction and then compared as opaque values. The grammar is
/// deliberately narrow — lowercase ASCII letters, digits and single interior
/// hyphens — so that an identifier is safe to embed in a log line, a metric name
/// or a file name without escaping.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SubsystemId(String);

impl SubsystemId {
    /// Creates an identifier, enforcing the grammar.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::InvalidSubsystemId`] when the value is
    /// empty, longer than 64 bytes, starts or ends with a hyphen, contains two
    /// consecutive hyphens, or contains anything other than lowercase ASCII
    /// alphanumerics and hyphens.
    pub fn new(value: impl Into<String>) -> Result<Self, CompositionError> {
        let value = value.into();

        let reject = |reason: &'static str| {
            Err(CompositionError::InvalidSubsystemId {
                value: value.clone(),
                reason,
            })
        };

        if value.is_empty() {
            return reject("must not be empty");
        }
        if value.len() > MAX_SUBSYSTEM_ID_BYTES {
            return reject("must not exceed 64 bytes");
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return reject("must use only lowercase ASCII alphanumerics and hyphens");
        }
        if value.starts_with('-') || value.ends_with('-') {
            return reject("must not start or end with a hyphen");
        }
        if value.contains("--") {
            return reject("must not contain consecutive hyphens");
        }

        Ok(Self(value))
    }

    /// Returns the identifier as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for SubsystemId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The subsystem identifiers the GTA Claw daemon composes.
///
/// Each constructor names the crate that owns the implementation. Nothing forces
/// a composition to use these names, but the daemon does, and the integration
/// contract is written against them.
pub mod well_known {
    use super::SubsystemId;

    macro_rules! well_known_ids {
        ($($function:ident => $literal:literal, $owner:literal;)+) => {
            $(
                #[doc = concat!("Returns the `", $literal, "` identifier, implemented by `", $owner, "`.")]
                ///
                /// # Panics
                ///
                /// Never: the literal is checked by `every_well_known_id_is_valid`.
                #[must_use]
                pub fn $function() -> SubsystemId {
                    SubsystemId::new($literal).expect("well-known identifiers satisfy the grammar")
                }
            )+

            /// Returns every well-known identifier in declaration order.
            #[must_use]
            pub fn all() -> Vec<SubsystemId> {
                vec![$($function()),+]
            }
        };
    }

    well_known_ids! {
        observability => "observability", "claw-observability";
        config => "config", "claw-config / claw-crestodian";
        persistence => "persistence", "claw-state";
        secrets => "secrets", "claw-provider-sdk";
        egress => "egress", "the daemon composition root";
        providers => "providers", "claw-providers";
        tools => "tools", "claw-tools";
        memory => "memory", "claw-memory";
        plugin_host => "plugin-host", "claw-plugin-host";
        engine => "engine", "claw-runtime";
        gateway => "gateway", "claw-gateway";
        http_api => "http-api", "claw-http-api";
        channels => "channels", "claw-channels / claw-skills";
        bridges => "bridges", "claw-mcp / claw-acp";
        automation => "automation", "claw-nodes / claw-automation";
    }
}

#[cfg(test)]
mod tests {
    use super::{SubsystemId, well_known};
    use crate::composition::error::CompositionError;

    fn rejection(value: &str) -> &'static str {
        match SubsystemId::new(value).expect_err("identifier must be rejected") {
            CompositionError::InvalidSubsystemId {
                value: seen,
                reason,
            } => {
                assert_eq!(seen, value);
                reason
            }
            other => panic!("expected an invalid identifier error, got {other}"),
        }
    }

    #[test]
    fn a_valid_identifier_keeps_its_exact_text() {
        let id = SubsystemId::new("plugin-host").expect("valid identifier");

        assert_eq!(id.as_str(), "plugin-host");
        assert_eq!(id.to_string(), "plugin-host");
    }

    #[test]
    fn each_grammar_violation_reports_its_own_reason() {
        assert_eq!(rejection(""), "must not be empty");
        assert_eq!(rejection(&"a".repeat(65)), "must not exceed 64 bytes");
        assert_eq!(
            rejection("Gateway"),
            "must use only lowercase ASCII alphanumerics and hyphens"
        );
        assert_eq!(
            rejection("http_api"),
            "must use only lowercase ASCII alphanumerics and hyphens"
        );
        assert_eq!(
            rejection("gate way"),
            "must use only lowercase ASCII alphanumerics and hyphens"
        );
        assert_eq!(rejection("-gateway"), "must not start or end with a hyphen");
        assert_eq!(rejection("gateway-"), "must not start or end with a hyphen");
        assert_eq!(
            rejection("http--api"),
            "must not contain consecutive hyphens"
        );
    }

    #[test]
    fn the_length_limit_is_inclusive_at_sixty_four_bytes() {
        let longest = "a".repeat(64);

        assert_eq!(
            SubsystemId::new(longest.clone())
                .expect("64 bytes is allowed")
                .as_str(),
            longest
        );
    }

    #[test]
    fn identifiers_are_not_trimmed_because_whitespace_is_not_in_the_grammar() {
        assert_eq!(
            rejection(" gateway"),
            "must use only lowercase ASCII alphanumerics and hyphens"
        );
    }

    #[test]
    fn every_well_known_id_is_valid_and_unique() {
        let all = well_known::all();
        let mut sorted: Vec<&str> = all.iter().map(SubsystemId::as_str).collect();

        for id in &all {
            assert_eq!(
                SubsystemId::new(id.as_str()).expect("well-known id round-trips"),
                *id
            );
        }

        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len());
        assert_eq!(all.len(), 15);
    }

    #[test]
    fn well_known_names_are_pinned() {
        let names: Vec<String> = well_known::all()
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect();

        assert_eq!(
            names,
            vec![
                "observability",
                "config",
                "persistence",
                "secrets",
                "egress",
                "providers",
                "tools",
                "memory",
                "plugin-host",
                "engine",
                "gateway",
                "http-api",
                "channels",
                "bridges",
                "automation",
            ]
        );
    }
}

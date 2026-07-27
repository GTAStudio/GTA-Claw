//! Operator configuration for one provider.
//!
//! A `ProviderConfig` is the shape GTA-Claw reads from disk. Deserialisation is
//! strict — `deny_unknown_fields` everywhere, no defaulted credential — because
//! a typo in a provider configuration otherwise degrades silently: the misspelt
//! key is dropped, the default is used, and the operator learns about it from a
//! wrong answer rather than from an error.
//!
//! [`ProviderConfig::resolve`] then turns the parsed shape into a
//! [`ResolvedProvider`], which is the only value the rest of the crate accepts.
//! Resolution enforces five things a parser cannot:
//!
//! 1. the identifier resolves through [`crate::alias`];
//! 2. the provider actually has a client, so a registration-only row cannot be
//!    configured into a routing table;
//! 3. an endpoint exists, and is TLS or loopback;
//! 4. no operator-supplied header can overwrite the credential the client is
//!    about to attach;
//! 5. the credential is of an accepted mode and is not blank.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Deserialize;
use url::Url;

use crate::alias::{AliasTable, MatchKind};
use crate::auth::{AuthConfig, AuthError, Authorization, authorize};
use crate::descriptor::ProviderDescriptor;

/// Headers an operator may not set, because the client sets them from the
/// credential and a configured value would silently win or silently lose.
///
/// Matching is ASCII-case-insensitive, as HTTP field names are.
pub const RESERVED_HEADERS: &[&str] = &[
    "anthropic-version",
    "api-key",
    "authorization",
    "x-api-key",
    "x-goog-api-key",
];

/// One provider as an operator configured it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ProviderConfig {
    /// Frozen identifier or alias of the provider.
    pub id: String,
    /// Credential material. Deliberately required: a provider that needs no
    /// credential is configured with an explicit `{"mode": "none"}`, so a
    /// forgotten credential is never mistaken for a deliberate one.
    pub auth: AuthConfig,
    /// Endpoint override. Required when the registry ships no default.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Extra non-secret headers sent with every request.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Whether this provider may be routed to. Defaults to `true`.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

const fn enabled_by_default() -> bool {
    true
}

impl ProviderConfig {
    /// Parses a configuration from JSON.
    ///
    /// # Errors
    ///
    /// Returns the `serde_json` error, which includes the offending field for
    /// an unknown key, a missing key or a wrongly typed value.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Resolves and validates the configuration against the built-in aliases.
    ///
    /// # Errors
    ///
    /// * [`ConfigError::UnknownProvider`] — `id` is neither a frozen identifier
    ///   nor one of [`BUILTIN_ALIASES`](crate::alias::BUILTIN_ALIASES).
    /// * [`ConfigError::NoClient`] — the provider is registered for metadata
    ///   only, so this crate ships no client that could call it.
    /// * [`ConfigError::MissingBaseUrl`] — the registry pins no default
    ///   endpoint for this provider and `base-url` was not supplied.
    /// * [`ConfigError::InvalidBaseUrl`] — the endpoint is not a parsable
    ///   absolute URL, or names no host.
    /// * [`ConfigError::InsecureBaseUrl`] — the endpoint is plaintext and is
    ///   not a loopback address.
    /// * [`ConfigError::ReservedHeader`] — a configured header is one of
    ///   [`RESERVED_HEADERS`], so it would overwrite the credential header the
    ///   client is about to set.
    /// * [`ConfigError::Auth`] — this provider does not declare the offered
    ///   authentication mode, or a required field of the credential is empty
    ///   once trimmed.
    pub fn resolve(&self) -> Result<ResolvedProvider, ConfigError> {
        self.resolve_with(AliasTable::builtin())
    }

    /// Resolves and validates the configuration against an explicit alias table.
    ///
    /// # Errors
    ///
    /// The same refusals as [`ProviderConfig::resolve`], except that
    /// [`ConfigError::UnknownProvider`] is decided against `aliases` rather
    /// than the built-in table.
    pub fn resolve_with(&self, aliases: &AliasTable) -> Result<ResolvedProvider, ConfigError> {
        let resolution = aliases
            .resolve(&self.id)
            .map_err(|error| ConfigError::UnknownProvider { name: error.name })?;
        let descriptor = resolution.descriptor;

        if descriptor.is_registration_only() {
            return Err(ConfigError::NoClient {
                provider: descriptor.id,
            });
        }

        // The operator's override wins; otherwise the frozen default is used.
        // A row that ships neither is refused *here*, at configuration time,
        // rather than at the first request.
        let configured = self.base_url.as_deref().or(descriptor.base_url);
        let endpoint = parse_endpoint(
            descriptor,
            configured.ok_or(ConfigError::MissingBaseUrl {
                provider: descriptor.id,
            })?,
        )?;

        for name in self.headers.keys() {
            let lowered = name.to_ascii_lowercase();
            if RESERVED_HEADERS.contains(&lowered.as_str()) {
                return Err(ConfigError::ReservedHeader {
                    provider: descriptor.id,
                    header: lowered,
                });
            }
        }

        let authorization = authorize(descriptor, &self.auth)?;

        Ok(ResolvedProvider {
            descriptor,
            base_url: endpoint,
            authorization,
            headers: self.headers.clone(),
            enabled: self.enabled,
            via_alias: match resolution.matched {
                MatchKind::Canonical => None,
                MatchKind::Alias(alias) => Some(alias),
            },
        })
    }
}

fn parse_endpoint(
    descriptor: &'static ProviderDescriptor,
    value: &str,
) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::InvalidBaseUrl {
        provider: descriptor.id,
        value: value.to_owned(),
    })?;
    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    let secure = match url.scheme() {
        "https" => true,
        "http" => loopback,
        _ => false,
    };
    if !secure {
        return Err(ConfigError::InsecureBaseUrl {
            provider: descriptor.id,
            value: value.to_owned(),
        });
    }
    if url.host_str().is_none() {
        return Err(ConfigError::InvalidBaseUrl {
            provider: descriptor.id,
            value: value.to_owned(),
        });
    }
    Ok(url)
}

/// One validated provider, ready to be routed to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProvider {
    /// The registry row this configuration names.
    pub descriptor: &'static ProviderDescriptor,
    /// The endpoint that will be called.
    pub base_url: Url,
    /// Proof that the credential was accepted.
    pub authorization: Authorization,
    /// Extra headers, none of which is credential-bearing.
    pub headers: BTreeMap<String, String>,
    /// Whether the provider may be routed to.
    pub enabled: bool,
    /// The alias the operator wrote, when they did not write the frozen id.
    pub via_alias: Option<String>,
}

impl ResolvedProvider {
    /// Returns the frozen identifier of the provider.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.descriptor.id
    }
}

/// Why a configuration was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// The identifier is neither a frozen identifier nor a known alias.
    UnknownProvider {
        /// The name as written.
        name: String,
    },
    /// The provider is registered for metadata only; no client can be built.
    NoClient {
        /// Frozen provider identifier.
        provider: &'static str,
    },
    /// The registry ships no default endpoint and the operator supplied none.
    MissingBaseUrl {
        /// Frozen provider identifier.
        provider: &'static str,
    },
    /// The endpoint is not a parsable absolute URL.
    InvalidBaseUrl {
        /// Frozen provider identifier.
        provider: &'static str,
        /// The value as written.
        value: String,
    },
    /// The endpoint is plaintext and is not a loopback address.
    InsecureBaseUrl {
        /// Frozen provider identifier.
        provider: &'static str,
        /// The value as written.
        value: String,
    },
    /// A configured header would overwrite a credential header.
    ReservedHeader {
        /// Frozen provider identifier.
        provider: &'static str,
        /// The offending header, lowercased.
        header: String,
    },
    /// The credential was refused.
    Auth(AuthError),
}

impl ConfigError {
    /// Every code [`ConfigError::code`] can return, sorted.
    ///
    /// This exists so a caller — and the fixture corpus — can enumerate the
    /// refusals instead of rediscovering them. It is kept honest by
    /// `every_refusal_code_appears_in_all_codes`, which builds one value of
    /// every variant and requires the two sets to be equal; adding a variant
    /// without extending this list therefore fails a test rather than silently
    /// shrinking the corpus.
    pub const ALL_CODES: &'static [&'static str] = &[
        "insecure_base_url",
        "invalid_base_url",
        "missing_base_url",
        "missing_credential",
        "no_client",
        "reserved_header",
        "unknown_provider",
        "unsupported_auth_mode",
    ];

    /// Returns a stable machine-readable code for this refusal.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownProvider { .. } => "unknown_provider",
            Self::NoClient { .. } => "no_client",
            Self::MissingBaseUrl { .. } => "missing_base_url",
            Self::InvalidBaseUrl { .. } => "invalid_base_url",
            Self::InsecureBaseUrl { .. } => "insecure_base_url",
            Self::ReservedHeader { .. } => "reserved_header",
            Self::Auth(error) => error.code(),
        }
    }
}

impl From<AuthError> for ConfigError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

impl Display for ConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProvider { name } => write!(
                formatter,
                "'{name}' is neither a registered provider nor a known alias"
            ),
            Self::NoClient { provider } => write!(
                formatter,
                "provider '{provider}' is registered for metadata only and has no client"
            ),
            Self::MissingBaseUrl { provider } => write!(
                formatter,
                "provider '{provider}' ships no default endpoint, so 'base-url' is required"
            ),
            Self::InvalidBaseUrl { provider, value } => write!(
                formatter,
                "provider '{provider}' has an unparsable endpoint '{value}'"
            ),
            Self::InsecureBaseUrl { provider, value } => write!(
                formatter,
                "provider '{provider}' endpoint '{value}' is neither TLS nor loopback"
            ),
            Self::ReservedHeader { provider, header } => write!(
                formatter,
                "provider '{provider}' may not configure the credential header '{header}'"
            ),
            Self::Auth(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Auth(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SecretField;
    use claw_provider_sdk::model::AuthMode;

    fn parse(json: &str) -> ProviderConfig {
        ProviderConfig::from_json(json).expect("valid configuration")
    }

    #[test]
    fn a_minimal_configuration_takes_the_registry_default_endpoint() {
        let config = parse(r#"{"id":"openai","auth":{"mode":"bearer_token","token":"sk-x"}}"#);
        assert_eq!(config.base_url, None);
        assert!(config.enabled, "providers are enabled unless disabled");
        assert!(config.headers.is_empty());

        let resolved = config.resolve().expect("resolves");
        assert_eq!(resolved.id(), "openai");
        assert_eq!(resolved.base_url.as_str(), "https://api.openai.com/v1");
        assert_eq!(resolved.authorization.mode(), AuthMode::BearerToken);
        assert_eq!(resolved.via_alias, None);
        assert!(resolved.enabled);
    }

    #[test]
    fn an_alias_resolves_and_is_reported_as_such() {
        let resolved = parse(r#"{"id":"CLAUDE","auth":{"mode":"api_key","key":"sk-ant"}}"#)
            .resolve()
            .expect("resolves");
        assert_eq!(resolved.id(), "anthropic");
        assert_eq!(resolved.via_alias.as_deref(), Some("claude"));
    }

    #[test]
    fn an_unknown_field_is_an_error_rather_than_a_silent_default() {
        // The whole point of `deny_unknown_fields`: a misspelt key must not be
        // dropped on the floor.
        let error = ProviderConfig::from_json(
            r#"{"id":"openai","auth":{"mode":"bearer_token","token":"t"},"base_url":"https://x/"}"#,
        )
        .expect_err("base_url is spelt base-url");
        assert!(error.to_string().contains("base_url"), "{error}");

        assert!(
            ProviderConfig::from_json(
                r#"{"id":"openai","auth":{"mode":"bearer_token","token":"t"},"enable":true}"#
            )
            .is_err()
        );
        // A field the schema does not have at all.
        assert!(
            ProviderConfig::from_json(
                r#"{"id":"openai","auth":{"mode":"bearer_token","token":"t"},"proxy":"http://x"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn a_missing_identifier_or_credential_is_an_error() {
        assert!(ProviderConfig::from_json(r#"{"auth":{"mode":"none"}}"#).is_err());
        assert!(ProviderConfig::from_json(r#"{"id":"ollama"}"#).is_err());
        assert!(ProviderConfig::from_json(r#"{"id":42,"auth":{"mode":"none"}}"#).is_err());
        assert!(
            ProviderConfig::from_json(r#"{"id":"ollama","auth":{"mode":"none"},"enabled":"yes"}"#)
                .is_err()
        );
    }

    #[test]
    fn a_registration_only_provider_cannot_be_configured() {
        let error = parse(r#"{"id":"amazon-bedrock","auth":{"mode":"aws_sigv4","access_key_id":"AKIA","secret_access_key":"s","region":"us-east-1"}}"#)
            .resolve()
            .expect_err("no client ships for bedrock");
        assert_eq!(error.code(), "no_client");
        assert_eq!(
            error,
            ConfigError::NoClient {
                provider: "amazon-bedrock"
            }
        );
    }

    #[test]
    fn an_endpoint_required_provider_needs_an_endpoint() {
        let error = parse(r#"{"id":"byteplus","auth":{"mode":"bearer_token","token":"t"}}"#)
            .resolve()
            .expect_err("no default endpoint is shipped for byteplus");
        assert_eq!(error.code(), "missing_base_url");

        let resolved = parse(
            r#"{"id":"byteplus","auth":{"mode":"bearer_token","token":"t"},"base-url":"https://ark.ap-southeast.bytepluses.com/api/v3"}"#,
        )
        .resolve()
        .expect("an explicit endpoint satisfies it");
        assert_eq!(
            resolved.base_url.as_str(),
            "https://ark.ap-southeast.bytepluses.com/api/v3"
        );
    }

    #[test]
    fn a_plaintext_remote_endpoint_is_refused_but_loopback_is_allowed() {
        for insecure in [
            "http://example.invalid/v1",
            "ftp://example.invalid/v1",
            "file:///etc/passwd",
        ] {
            let json = format!(
                r#"{{"id":"byteplus","auth":{{"mode":"bearer_token","token":"t"}},"base-url":"{insecure}"}}"#
            );
            assert_eq!(
                parse(&json).resolve().expect_err(insecure).code(),
                "insecure_base_url",
                "{insecure}"
            );
        }
        assert!(
            parse(
                r#"{"id":"byteplus","auth":{"mode":"bearer_token","token":"t"},"base-url":"not a url"}"#
            )
            .resolve()
            .is_err()
        );
        for loopback in ["http://127.0.0.1:8080/v1", "http://localhost:1234/v1"] {
            let json = format!(
                r#"{{"id":"byteplus","auth":{{"mode":"bearer_token","token":"t"}},"base-url":"{loopback}"}}"#
            );
            assert!(parse(&json).resolve().is_ok(), "{loopback}");
        }
    }

    #[test]
    fn a_configured_credential_header_is_refused_whatever_its_case() {
        for header in [
            "Authorization",
            "authorization",
            "X-Api-Key",
            "api-key",
            "X-Goog-Api-Key",
            "Anthropic-Version",
        ] {
            let json = format!(
                r#"{{"id":"openai","auth":{{"mode":"bearer_token","token":"t"}},"headers":{{"{header}":"stolen"}}}}"#
            );
            let error = parse(&json).resolve().expect_err(header);
            assert_eq!(error.code(), "reserved_header", "{header}");
            assert_eq!(
                error,
                ConfigError::ReservedHeader {
                    provider: "openai",
                    header: header.to_ascii_lowercase(),
                }
            );
        }
        let resolved = parse(
            r#"{"id":"openai","auth":{"mode":"bearer_token","token":"t"},"headers":{"X-Title":"gta-claw"}}"#,
        )
        .resolve()
        .expect("an ordinary header is fine");
        assert_eq!(
            resolved.headers.get("X-Title").map(String::as_str),
            Some("gta-claw")
        );
    }

    #[test]
    fn a_credential_failure_surfaces_through_the_configuration_error() {
        let error = parse(r#"{"id":"openai","auth":{"mode":"api_key","key":"k"}}"#)
            .resolve()
            .expect_err("openai takes a bearer token");
        assert_eq!(error.code(), "unsupported_auth_mode");
        assert!(matches!(error, ConfigError::Auth(_)));
        assert!(error.source().is_some());

        let blank = parse(r#"{"id":"openai","auth":{"mode":"bearer_token","token":"  "}}"#)
            .resolve()
            .expect_err("blank token");
        assert_eq!(blank.code(), "missing_credential");
    }

    #[test]
    fn an_unknown_identifier_is_refused_before_anything_else_is_checked() {
        let error = parse(r#"{"id":"gpt-9","auth":{"mode":"bearer_token","token":"t"}}"#)
            .resolve()
            .expect_err("no such provider");
        assert_eq!(
            error,
            ConfigError::UnknownProvider {
                name: "gpt-9".to_owned()
            }
        );
    }

    #[test]
    fn resolution_can_be_pointed_at_an_explicit_alias_table() {
        let config = parse(r#"{"id":"claude","auth":{"mode":"api_key","key":"k"}}"#);
        assert_eq!(config.resolve().expect("built-in table").id(), "anthropic");
        assert_eq!(
            config
                .resolve_with(&AliasTable::empty())
                .expect_err("the empty table knows no aliases")
                .code(),
            "unknown_provider"
        );
    }

    #[test]
    fn a_disabled_provider_still_resolves() {
        // Disabling is a routing decision, not a validity decision: a disabled
        // configuration must still be checked so a typo is reported at load.
        let resolved =
            parse(r#"{"id":"openai","auth":{"mode":"bearer_token","token":"t"},"enabled":false}"#)
                .resolve()
                .expect("resolves");
        assert!(!resolved.enabled);
    }

    #[test]
    fn every_reserved_header_is_lowercase_and_unique() {
        let mut sorted = RESERVED_HEADERS.to_vec();
        assert!(sorted.windows(2).all(|pair| pair[0] < pair[1]));
        sorted.dedup();
        assert_eq!(sorted.len(), RESERVED_HEADERS.len());
        for header in RESERVED_HEADERS {
            assert_eq!(*header, header.to_ascii_lowercase());
        }
    }

    #[test]
    fn a_hand_built_configuration_resolves_the_same_way_as_a_parsed_one() {
        let built = ProviderConfig {
            id: "ollama".to_owned(),
            auth: AuthConfig::None {},
            base_url: None,
            headers: BTreeMap::new(),
            enabled: true,
        };
        let parsed = parse(r#"{"id":"ollama","auth":{"mode":"none"}}"#);
        assert_eq!(built, parsed);
        assert_eq!(
            built.resolve().expect("resolves"),
            parsed.resolve().expect("resolves")
        );
        assert_ne!(
            built,
            ProviderConfig {
                auth: AuthConfig::BearerToken {
                    token: SecretField::new("t")
                },
                ..built.clone()
            }
        );
    }

    #[test]
    fn every_refusal_code_appears_in_all_codes() {
        // One value of every variant. The `match` below is exhaustive, so a new
        // variant will not compile until it is sampled here, and the set
        // comparison then forces `ALL_CODES` to grow with it.
        let samples = [
            ConfigError::UnknownProvider {
                name: String::new(),
            },
            ConfigError::NoClient { provider: "x" },
            ConfigError::MissingBaseUrl { provider: "x" },
            ConfigError::InvalidBaseUrl {
                provider: "x",
                value: String::new(),
            },
            ConfigError::InsecureBaseUrl {
                provider: "x",
                value: String::new(),
            },
            ConfigError::ReservedHeader {
                provider: "x",
                header: String::new(),
            },
            ConfigError::Auth(AuthError::UnsupportedMode {
                provider: "x",
                offered: AuthMode::ApiKey,
                accepted: Vec::new(),
            }),
            ConfigError::Auth(AuthError::MissingCredential {
                provider: "x",
                offered: AuthMode::ApiKey,
                field: "key",
            }),
        ];
        for sample in &samples {
            match sample {
                ConfigError::UnknownProvider { .. }
                | ConfigError::NoClient { .. }
                | ConfigError::MissingBaseUrl { .. }
                | ConfigError::InvalidBaseUrl { .. }
                | ConfigError::InsecureBaseUrl { .. }
                | ConfigError::ReservedHeader { .. }
                | ConfigError::Auth(_) => {}
            }
        }
        let observed: std::collections::BTreeSet<&str> =
            samples.iter().map(ConfigError::code).collect();
        let declared: std::collections::BTreeSet<&str> =
            ConfigError::ALL_CODES.iter().copied().collect();
        assert_eq!(observed, declared);
        assert_eq!(declared.len(), ConfigError::ALL_CODES.len());
        assert!(
            ConfigError::ALL_CODES
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }
}

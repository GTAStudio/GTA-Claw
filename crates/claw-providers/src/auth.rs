//! Credential shapes and the authorization check that guards every provider.
//!
//! The frozen upstream inventory records identifiers only, so which
//! authentication modes a provider accepts is GTA-Claw-owned metadata carried
//! by [`ProviderDescriptor::auth_modes`]. This module turns that metadata into
//! an enforced rule: a credential of a mode the provider does not accept is
//! refused, and so is a credential whose secret material is absent.
//!
//! Nothing here talks to a network. Authorization is a pure decision over
//! configuration, which is what makes it testable against fixtures.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use claw_provider_sdk::model::AuthMode;
use claw_provider_sdk::secret::SecretString;
use serde::Deserialize;
use serde::de::{Deserializer, Error as DeError};

use crate::descriptor::ProviderDescriptor;

/// A secret configuration field.
///
/// The wrapper exists so that a `ProviderConfig` can be printed in a log or an
/// error without leaking the credential: [`Debug`] renders a fixed redaction
/// and never the value. There is deliberately no `Display` and no `Serialize`,
/// because a configuration file is read, never written back.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretField(SecretString);

impl SecretField {
    /// Wraps a secret value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretString::new(value.into()))
    }

    /// Returns the secret material.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// Returns `true` when the field is empty or entirely whitespace.
    ///
    /// A whitespace-only credential is treated as absent rather than as a
    /// credential that will fail at the service: an operator who wrote `" "`
    /// into a configuration file supplied nothing, and finding that out from a
    /// local error beats finding it out from a remote `401`.
    #[must_use]
    pub fn is_blank(&self) -> bool {
        self.0.expose().trim().is_empty()
    }
}

impl Debug for SecretField {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretField(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for SecretField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer).map_err(DeError::custom)?;
        Ok(Self::new(value))
    }
}

/// Credential material an operator supplied for one provider.
///
/// The externally tagged-by-field form (`{"mode": "...", ...}`) is used so that
/// the mode is always explicit in configuration: a credential can never be
/// silently reinterpreted as another kind because a field happened to match.
/// `deny_unknown_fields` means a key that belongs to a different mode is a
/// hard error rather than a silently ignored one.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "mode")]
pub enum AuthConfig {
    /// The provider takes no credential.
    ///
    /// Written as a struct variant with no fields rather than a unit variant so
    /// that `deny_unknown_fields` applies: serde does not enforce it on an
    /// internally tagged *unit* variant, which would let
    /// `{"mode":"none","key":"…"}` parse and silently drop a credential the
    /// operator believed was in force.
    None {},
    /// A static API key sent in a provider-specific header.
    ApiKey {
        /// The key.
        key: SecretField,
    },
    /// A static bearer token.
    BearerToken {
        /// The token.
        token: SecretField,
    },
    /// An access token obtained through the RFC 8628 device grant.
    OauthDeviceCode {
        /// The access token.
        access_token: SecretField,
    },
    /// An access token obtained through the authorization-code grant.
    OauthAuthorizationCode {
        /// The access token.
        access_token: SecretField,
    },
    /// AWS `SigV4` signing material.
    AwsSigv4 {
        /// Access key identifier. Not secret, but required.
        access_key_id: String,
        /// Secret access key.
        secret_access_key: SecretField,
        /// Signing region.
        region: String,
    },
    /// A Google service-account key document.
    GoogleServiceAccount {
        /// The service-account JSON document.
        service_account_json: SecretField,
    },
    /// An Azure Entra ID token or Azure API key.
    AzureIdentity {
        /// The token or key.
        token: SecretField,
    },
}

impl AuthConfig {
    /// Returns the [`AuthMode`] this credential claims.
    #[must_use]
    pub const fn mode(&self) -> AuthMode {
        match self {
            Self::None {} => AuthMode::None,
            Self::ApiKey { .. } => AuthMode::ApiKey,
            Self::BearerToken { .. } => AuthMode::BearerToken,
            Self::OauthDeviceCode { .. } => AuthMode::OAuthDeviceCode,
            Self::OauthAuthorizationCode { .. } => AuthMode::OAuthAuthorizationCode,
            Self::AwsSigv4 { .. } => AuthMode::AwsSigV4,
            Self::GoogleServiceAccount { .. } => AuthMode::GoogleServiceAccount,
            Self::AzureIdentity { .. } => AuthMode::AzureIdentity,
        }
    }

    /// Returns the name of the first required field that was left blank.
    ///
    /// Fields are checked in declaration order so the reported field is stable.
    #[must_use]
    pub fn blank_field(&self) -> Option<&'static str> {
        match self {
            Self::None {} => None,
            Self::ApiKey { key } => key.is_blank().then_some("key"),
            Self::BearerToken { token } | Self::AzureIdentity { token } => {
                token.is_blank().then_some("token")
            }
            Self::OauthDeviceCode { access_token }
            | Self::OauthAuthorizationCode { access_token } => {
                access_token.is_blank().then_some("access_token")
            }
            Self::AwsSigv4 {
                access_key_id,
                secret_access_key,
                region,
            } => {
                if access_key_id.trim().is_empty() {
                    Some("access_key_id")
                } else if secret_access_key.is_blank() {
                    Some("secret_access_key")
                } else if region.trim().is_empty() {
                    Some("region")
                } else {
                    None
                }
            }
            Self::GoogleServiceAccount {
                service_account_json,
            } => service_account_json
                .is_blank()
                .then_some("service_account_json"),
        }
    }
}

/// Proof that a credential was checked against a provider's accepted modes.
///
/// The only way to build one is [`authorize`], so a caller that holds an
/// `Authorization` holds evidence the check ran.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Authorization {
    provider: &'static str,
    mode: AuthMode,
}

impl Authorization {
    /// Returns the frozen identifier of the authorized provider.
    #[must_use]
    pub const fn provider(&self) -> &'static str {
        self.provider
    }

    /// Returns the authentication mode that was accepted.
    #[must_use]
    pub const fn mode(&self) -> AuthMode {
        self.mode
    }
}

/// Why a credential was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthError {
    /// The provider does not accept credentials of this mode.
    UnsupportedMode {
        /// Frozen provider identifier.
        provider: &'static str,
        /// Mode that was offered.
        offered: AuthMode,
        /// Modes the provider accepts, most preferred first.
        accepted: Vec<AuthMode>,
    },
    /// A required field of the credential was empty or whitespace.
    MissingCredential {
        /// Frozen provider identifier.
        provider: &'static str,
        /// Mode that was offered.
        offered: AuthMode,
        /// Name of the blank field.
        field: &'static str,
    },
}

impl AuthError {
    /// Returns a stable machine-readable code for this refusal.
    ///
    /// Fixtures compare codes rather than rendered messages, so wording can be
    /// improved without rewriting the corpus.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedMode { .. } => "unsupported_auth_mode",
            Self::MissingCredential { .. } => "missing_credential",
        }
    }
}

impl Display for AuthError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedMode {
                provider,
                offered,
                accepted,
            } => {
                let accepted: Vec<&str> = accepted.iter().map(|mode| mode.as_str()).collect();
                write!(
                    formatter,
                    "provider '{provider}' does not accept '{offered}' credentials; it accepts {}",
                    accepted.join(", ")
                )
            }
            Self::MissingCredential {
                provider,
                offered,
                field,
            } => write!(
                formatter,
                "provider '{provider}' needs a non-empty '{field}' for '{offered}' credentials"
            ),
        }
    }
}

impl Error for AuthError {}

/// Checks a credential against a provider's accepted authentication modes.
///
/// # Errors
///
/// Returns [`AuthError::UnsupportedMode`] when the descriptor does not list the
/// offered mode — which is also how a credential handed to a credential-free
/// local runtime is refused, because such a provider accepts only
/// [`AuthMode::None`] — and [`AuthError::MissingCredential`] when a required
/// field of the credential is empty or whitespace.
pub fn authorize(
    descriptor: &'static ProviderDescriptor,
    credential: &AuthConfig,
) -> Result<Authorization, AuthError> {
    let offered = credential.mode();
    if !descriptor.auth_modes.contains(&offered) {
        return Err(AuthError::UnsupportedMode {
            provider: descriptor.id,
            offered,
            accepted: descriptor.auth_modes.to_vec(),
        });
    }
    if let Some(field) = credential.blank_field() {
        return Err(AuthError::MissingCredential {
            provider: descriptor.id,
            offered,
            field,
        });
    }
    Ok(Authorization {
        provider: descriptor.id,
        mode: offered,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ProviderRegistry;

    fn descriptor(id: &str) -> &'static ProviderDescriptor {
        ProviderRegistry::global().get(id).expect("registered")
    }

    #[test]
    fn a_secret_field_never_renders_its_value() {
        let field = SecretField::new("sk-not-in-the-output");
        assert_eq!(format!("{field:?}"), "SecretField(<redacted>)");
        assert!(!format!("{field:?}").contains("sk-not"));

        let credential = AuthConfig::ApiKey {
            key: SecretField::new("sk-not-in-the-output"),
        };
        assert!(!format!("{credential:?}").contains("sk-not"));
        assert_eq!(field.expose(), "sk-not-in-the-output");
    }

    #[test]
    fn every_auth_mode_has_exactly_one_credential_shape() {
        // Both directions, so a mode that gains no shape and a shape that
        // reports the wrong mode both fail.
        let shapes = [
            AuthConfig::None {},
            AuthConfig::ApiKey {
                key: SecretField::new("k"),
            },
            AuthConfig::BearerToken {
                token: SecretField::new("t"),
            },
            AuthConfig::OauthDeviceCode {
                access_token: SecretField::new("t"),
            },
            AuthConfig::OauthAuthorizationCode {
                access_token: SecretField::new("t"),
            },
            AuthConfig::AwsSigv4 {
                access_key_id: "AKIA".to_owned(),
                secret_access_key: SecretField::new("s"),
                region: "us-east-1".to_owned(),
            },
            AuthConfig::GoogleServiceAccount {
                service_account_json: SecretField::new("{}"),
            },
            AuthConfig::AzureIdentity {
                token: SecretField::new("t"),
            },
        ];
        let mut seen: Vec<AuthMode> = shapes.iter().map(AuthConfig::mode).collect();
        seen.sort_unstable();
        let mut all = AuthMode::ALL.to_vec();
        all.sort_unstable();
        assert_eq!(seen, all);
        for shape in &shapes {
            assert_eq!(shape.blank_field(), None, "{shape:?}");
        }
    }

    #[test]
    fn the_credential_tag_is_the_auth_mode_identifier() {
        // The wire tag and `AuthMode::as_str` must agree, or a configuration
        // file would spell a mode differently from every error message and
        // every capability report.
        for mode in AuthMode::ALL {
            let json = match mode {
                AuthMode::None => format!(r#"{{"mode":"{}"}}"#, mode.as_str()),
                AuthMode::ApiKey => format!(r#"{{"mode":"{}","key":"k"}}"#, mode.as_str()),
                AuthMode::BearerToken | AuthMode::AzureIdentity => {
                    format!(r#"{{"mode":"{}","token":"t"}}"#, mode.as_str())
                }
                AuthMode::OAuthDeviceCode | AuthMode::OAuthAuthorizationCode => {
                    format!(r#"{{"mode":"{}","access_token":"t"}}"#, mode.as_str())
                }
                AuthMode::AwsSigV4 => format!(
                    r#"{{"mode":"{}","access_key_id":"AKIA","secret_access_key":"s","region":"r"}}"#,
                    mode.as_str()
                ),
                AuthMode::GoogleServiceAccount => format!(
                    r#"{{"mode":"{}","service_account_json":"{{}}"}}"#,
                    mode.as_str()
                ),
            };
            let parsed: AuthConfig =
                serde_json::from_str(&json).unwrap_or_else(|_| panic!("{}", mode.as_str()));
            assert_eq!(parsed.mode(), mode);
        }
    }

    #[test]
    fn a_credential_field_from_another_mode_is_rejected() {
        assert!(
            serde_json::from_str::<AuthConfig>(r#"{"mode":"api_key","key":"k","token":"t"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<AuthConfig>(r#"{"mode":"api_key"}"#).is_err());
        assert!(serde_json::from_str::<AuthConfig>(r#"{"mode":"none","key":"k"}"#).is_err());
        assert!(serde_json::from_str::<AuthConfig>(r#"{"mode":"totally_new"}"#).is_err());
        assert!(serde_json::from_str::<AuthConfig>(r#"{"key":"k"}"#).is_err());
    }

    #[test]
    fn a_blank_secret_counts_as_no_credential_in_every_shape() {
        let blanks = [
            (
                AuthConfig::ApiKey {
                    key: SecretField::new(""),
                },
                "key",
            ),
            (
                AuthConfig::BearerToken {
                    token: SecretField::new("   "),
                },
                "token",
            ),
            (
                AuthConfig::OauthDeviceCode {
                    access_token: SecretField::new("\t\n"),
                },
                "access_token",
            ),
            (
                AuthConfig::OauthAuthorizationCode {
                    access_token: SecretField::new(""),
                },
                "access_token",
            ),
            (
                AuthConfig::AwsSigv4 {
                    access_key_id: " ".to_owned(),
                    secret_access_key: SecretField::new("s"),
                    region: "r".to_owned(),
                },
                "access_key_id",
            ),
            (
                AuthConfig::AwsSigv4 {
                    access_key_id: "AKIA".to_owned(),
                    secret_access_key: SecretField::new(""),
                    region: "r".to_owned(),
                },
                "secret_access_key",
            ),
            (
                AuthConfig::AwsSigv4 {
                    access_key_id: "AKIA".to_owned(),
                    secret_access_key: SecretField::new("s"),
                    region: String::new(),
                },
                "region",
            ),
            (
                AuthConfig::GoogleServiceAccount {
                    service_account_json: SecretField::new(" "),
                },
                "service_account_json",
            ),
            (
                AuthConfig::AzureIdentity {
                    token: SecretField::new(""),
                },
                "token",
            ),
        ];
        for (credential, field) in &blanks {
            assert_eq!(credential.blank_field(), Some(*field), "{credential:?}");
        }
        assert_eq!(AuthConfig::None {}.blank_field(), None);
    }

    #[test]
    fn authorization_refuses_a_mode_the_provider_does_not_accept() {
        let anthropic = descriptor("anthropic");
        let error = authorize(
            anthropic,
            &AuthConfig::BearerToken {
                token: SecretField::new("t"),
            },
        )
        .expect_err("anthropic takes an api key or oauth, never a bare bearer token");
        assert_eq!(error.code(), "unsupported_auth_mode");
        assert_eq!(
            error,
            AuthError::UnsupportedMode {
                provider: "anthropic",
                offered: AuthMode::BearerToken,
                accepted: vec![AuthMode::ApiKey, AuthMode::OAuthAuthorizationCode],
            }
        );
        assert!(error.to_string().contains("api_key"));

        let authorized = authorize(
            anthropic,
            &AuthConfig::ApiKey {
                key: SecretField::new("sk-ant-x"),
            },
        )
        .expect("api key is accepted");
        assert_eq!(authorized.provider(), "anthropic");
        assert_eq!(authorized.mode(), AuthMode::ApiKey);
    }

    #[test]
    fn a_credential_free_runtime_refuses_a_credential_and_accepts_none() {
        let ollama = descriptor("ollama");
        assert!(ollama.is_credential_free());
        assert_eq!(
            authorize(
                ollama,
                &AuthConfig::BearerToken {
                    token: SecretField::new("t"),
                }
            )
            .expect_err("a local runtime takes no credential")
            .code(),
            "unsupported_auth_mode"
        );
        assert_eq!(
            authorize(ollama, &AuthConfig::None {})
                .expect("none is accepted")
                .mode(),
            AuthMode::None
        );
    }

    #[test]
    fn an_accepted_mode_with_a_blank_secret_is_still_refused() {
        let error = authorize(
            descriptor("openai"),
            &AuthConfig::BearerToken {
                token: SecretField::new("  "),
            },
        )
        .expect_err("a whitespace token is no token");
        assert_eq!(error.code(), "missing_credential");
        assert_eq!(
            error,
            AuthError::MissingCredential {
                provider: "openai",
                offered: AuthMode::BearerToken,
                field: "token",
            }
        );
    }

    #[test]
    fn a_provider_that_needs_no_credential_still_refuses_the_wrong_shape_first() {
        // `litellm` accepts a bearer token *or* nothing, which is the one
        // descriptor shape where both branches of `authorize` are reachable.
        let litellm = descriptor("litellm");
        assert!(!litellm.is_credential_free());
        assert_eq!(
            authorize(litellm, &AuthConfig::None {})
                .expect("litellm may be unauthenticated")
                .mode(),
            AuthMode::None
        );
        assert_eq!(
            authorize(
                litellm,
                &AuthConfig::ApiKey {
                    key: SecretField::new("k"),
                }
            )
            .expect_err("litellm does not take a header api key")
            .code(),
            "unsupported_auth_mode"
        );
    }
}

//! Bounded Gateway credential intake for a mobile client.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use claw_gateway_client::GatewayCredential;
use secrecy::SecretString;

/// Maximum accepted credential text, in UTF-8 bytes.
const MAX_CREDENTIAL_BYTES: usize = 4096;

/// Which Gateway credential a person supplied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IosCredentialKind {
    /// No shared credential; device policy still applies.
    None,
    /// A shared Gateway token.
    Token,
    /// A shared Gateway password.
    Password,
    /// A one-time bootstrap token.
    BootstrapToken,
    /// A previously issued device token.
    DeviceToken,
}

impl IosCredentialKind {
    /// Returns text safe to render beside a credential field.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "no shared credential",
            Self::Token => "Gateway token",
            Self::Password => "Gateway password",
            Self::BootstrapToken => "bootstrap token",
            Self::DeviceToken => "device token",
        }
    }
}

/// A validated Gateway credential.
///
/// This type has no derived [`Debug`]. The secret is held behind
/// [`SecretString`], and the hand-written formatter prints the kind and nothing
/// else, because the only useful thing a log can say about a credential is
/// which slot it filled.
pub struct IosCredential {
    kind: IosCredentialKind,
    secret: Option<SecretString>,
}

impl IosCredential {
    /// Creates the absent credential.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            kind: IosCredentialKind::None,
            secret: None,
        }
    }

    /// Creates a shared Gateway token.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the text is blank, oversized, or
    /// contains control characters.
    pub fn token(raw: &str) -> Result<Self, CredentialError> {
        Self::secret(IosCredentialKind::Token, raw)
    }

    /// Creates a shared Gateway password.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the text is blank, oversized, or
    /// contains control characters.
    pub fn password(raw: &str) -> Result<Self, CredentialError> {
        Self::secret(IosCredentialKind::Password, raw)
    }

    /// Creates a one-time bootstrap token.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the text is blank, oversized, or
    /// contains control characters.
    pub fn bootstrap_token(raw: &str) -> Result<Self, CredentialError> {
        Self::secret(IosCredentialKind::BootstrapToken, raw)
    }

    /// Creates a previously issued device token.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when the text is blank, oversized, or
    /// contains control characters.
    pub fn device_token(raw: &str) -> Result<Self, CredentialError> {
        Self::secret(IosCredentialKind::DeviceToken, raw)
    }

    fn secret(kind: IosCredentialKind, raw: &str) -> Result<Self, CredentialError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CredentialError::Empty);
        }
        if trimmed.len() > MAX_CREDENTIAL_BYTES {
            return Err(CredentialError::TooLong {
                actual: trimmed.len(),
                limit: MAX_CREDENTIAL_BYTES,
            });
        }
        if trimmed.chars().any(char::is_control) {
            return Err(CredentialError::ControlCharacter);
        }
        Ok(Self {
            kind,
            secret: Some(SecretString::from(trimmed.to_owned())),
        })
    }

    /// Returns which credential slot this fills.
    #[must_use]
    pub const fn kind(&self) -> IosCredentialKind {
        self.kind
    }

    /// Converts to the transport-layer credential.
    #[must_use]
    pub fn into_gateway_credential(self) -> GatewayCredential {
        let Some(secret) = self.secret else {
            return GatewayCredential::None;
        };
        match self.kind {
            IosCredentialKind::None => GatewayCredential::None,
            IosCredentialKind::Token => GatewayCredential::Token(secret),
            IosCredentialKind::Password => GatewayCredential::Password(secret),
            IosCredentialKind::BootstrapToken => GatewayCredential::BootstrapToken(secret),
            IosCredentialKind::DeviceToken => GatewayCredential::DeviceToken(secret),
        }
    }
}

impl Debug for IosCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IosCredential")
            .field("kind", &self.kind)
            .field(
                "secret",
                &if self.secret.is_some() {
                    "[REDACTED]"
                } else {
                    "[ABSENT]"
                },
            )
            .finish()
    }
}

/// Credential text a mobile client must refuse before any network operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialError {
    /// The field was blank.
    Empty,
    /// The text exceeded the accepted length.
    TooLong {
        /// Observed UTF-8 byte length.
        actual: usize,
        /// Accepted UTF-8 byte length.
        limit: usize,
    },
    /// The text contained a control character.
    ControlCharacter,
}

impl Display for CredentialError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("enter a credential"),
            Self::TooLong { actual, limit } => write!(
                formatter,
                "credential is {actual} bytes, which exceeds the {limit}-byte limit"
            ),
            Self::ControlCharacter => {
                formatter.write_str("credential contains a control character")
            }
        }
    }
}

impl Error for CredentialError {}

#[cfg(test)]
mod tests {
    use claw_gateway_client::GatewayCredential;

    use super::{CredentialError, IosCredential, IosCredentialKind, MAX_CREDENTIAL_BYTES};

    #[test]
    fn the_debug_representation_never_contains_the_secret() {
        let credential = IosCredential::token("super-secret-value").expect("token is valid");
        let rendered = format!("{credential:?}");

        assert!(
            !rendered.contains("super-secret-value"),
            "Debug leaked the credential: {rendered}"
        );
        assert!(
            rendered.contains("[REDACTED]"),
            "Debug must mark the credential redacted: {rendered}"
        );
    }

    #[test]
    fn the_absent_credential_is_marked_absent_rather_than_redacted() {
        let rendered = format!("{:?}", IosCredential::none());

        assert!(
            rendered.contains("[ABSENT]"),
            "an absent credential must not look like a withheld one: {rendered}"
        );
    }

    #[test]
    fn each_kind_maps_to_its_own_transport_credential() {
        let cases = [
            (
                IosCredentialKind::Token,
                IosCredential::token("value").expect("token is valid"),
            ),
            (
                IosCredentialKind::Password,
                IosCredential::password("value").expect("password is valid"),
            ),
            (
                IosCredentialKind::BootstrapToken,
                IosCredential::bootstrap_token("value").expect("bootstrap token is valid"),
            ),
            (
                IosCredentialKind::DeviceToken,
                IosCredential::device_token("value").expect("device token is valid"),
            ),
        ];

        for (kind, credential) in cases {
            assert_eq!(credential.kind(), kind);
            let transport = credential.into_gateway_credential();
            let matched = matches!(
                (kind, &transport),
                (IosCredentialKind::Token, GatewayCredential::Token(_))
                    | (IosCredentialKind::Password, GatewayCredential::Password(_))
                    | (
                        IosCredentialKind::BootstrapToken,
                        GatewayCredential::BootstrapToken(_)
                    )
                    | (
                        IosCredentialKind::DeviceToken,
                        GatewayCredential::DeviceToken(_)
                    )
            );

            assert!(
                matched,
                "{kind:?} produced the wrong transport credential: {transport:?}"
            );
        }
    }

    #[test]
    fn blank_control_and_oversized_credentials_are_refused() {
        assert_eq!(
            IosCredential::token("  ").err(),
            Some(CredentialError::Empty)
        );
        assert_eq!(
            IosCredential::token("abc\u{7}def").err(),
            Some(CredentialError::ControlCharacter)
        );

        let oversized = "a".repeat(MAX_CREDENTIAL_BYTES + 1);
        let error = IosCredential::token(&oversized).expect_err("oversized credential is refused");

        assert_eq!(
            error,
            CredentialError::TooLong {
                actual: oversized.len(),
                limit: MAX_CREDENTIAL_BYTES,
            }
        );
    }
}

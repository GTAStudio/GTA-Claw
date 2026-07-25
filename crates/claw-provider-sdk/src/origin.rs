//! Binding a credential to the one network origin it may be presented to.
//!
//! # Why this module exists
//!
//! A provider client historically held two independent things: a credential,
//! and a base URL taken from configuration. TLS authenticates whichever host
//! the configuration names — it does not prove that host is the one the
//! credential belongs to. So any input that can influence configuration could
//! keep `provider = openai`, keep the stored OpenAI key, point `base_url` at an
//! attacker's HTTPS origin, and the next completion would ship the key there.
//! The same shape applied to the GitHub Copilot token-exchange and API URLs,
//! where the credential at risk is a long-lived GitHub OAuth token.
//!
//! Validating the URL at each call site does not fix the class: the next
//! provider someone adds reintroduces the bug. Instead the invariant lives in
//! the types.
//!
//! * A credential is wrapped in [`BoundApiKey`] or [`BoundSecret`], which pairs
//!   it with the [`Origin`] it was authorised for.
//! * The only way to read the secret out is [`BoundApiKey::for_url`] /
//!   [`BoundSecret::expose_for`], which take the destination URL and fail with
//!   [`OriginError::Mismatch`] unless the origins are equal.
//! * The request builders
//!   ([`HttpRequest::bearer`](crate::http::HttpRequest::bearer) and friends)
//!   route through those accessors, so an authenticated request whose origin
//!   disagrees with its credential is not constructible.
//! * [`credential_account`] puts the origin inside the secret-store account
//!   name, so a credential saved for one origin is simply not found when the
//!   configuration names another. Redirecting an endpoint therefore cannot
//!   silently reuse a stored secret; it produces a missing credential, and the
//!   operator has to authorise the new origin deliberately.
//!
//! An origin that is not a provider's default requires an explicit
//! [`OriginApproval`], which is how enterprise and self-hosted deployments
//! enrol their own endpoints without weakening the default.

use std::fmt::{self, Debug, Display, Formatter};

use url::Url;

use crate::secret::{ApiKey, CredentialKey, SecretStoreError, SecretString};

/// Why an origin could not be derived or did not match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OriginError {
    /// The URL has no host, so it names no origin a credential can bind to.
    ///
    /// `data:`, `file:` and `mailto:` URLs land here.
    Opaque,
    /// The URL scheme may not carry credentials.
    UnsupportedScheme {
        /// The scheme that was rejected.
        scheme: String,
    },
    /// The destination is not the origin the credential was authorised for.
    Mismatch {
        /// The origin the credential is bound to.
        expected: String,
        /// The origin the request was about to be sent to.
        actual: String,
    },
    /// The text could not be read as an origin.
    Malformed,
}

impl Display for OriginError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opaque => formatter.write_str("the URL has no host, so it names no origin"),
            Self::UnsupportedScheme { scheme } => {
                write!(formatter, "the {scheme} scheme may not carry a credential")
            }
            Self::Mismatch { expected, actual } => write!(
                formatter,
                "the credential is bound to {expected} and must not be sent to {actual}"
            ),
            Self::Malformed => formatter.write_str("the text is not a valid origin"),
        }
    }
}

impl std::error::Error for OriginError {}

/// A scheme, host and port a credential may be sent to.
///
/// Two URLs share an origin when their scheme, host and effective port are all
/// equal. Paths and query strings are irrelevant: a credential sent to
/// `https://evil.test/v1` is just as exposed as one sent to `https://evil.test`.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Origin {
    text: String,
}

impl Origin {
    /// Derives the origin of `url`.
    ///
    /// `http` is accepted only for loopback hosts, which is what makes the
    /// local test servers in this workspace usable without opening a
    /// cleartext-credential hole in production.
    ///
    /// # Errors
    ///
    /// Returns [`OriginError::Opaque`] when the URL has no host and
    /// [`OriginError::UnsupportedScheme`] for a scheme that may not carry a
    /// credential.
    pub fn of(url: &Url) -> Result<Self, OriginError> {
        let host = url.host_str().ok_or(OriginError::Opaque)?;
        let scheme = url.scheme();
        match scheme {
            "https" => {}
            "http" if is_loopback(host) => {}
            other => {
                return Err(OriginError::UnsupportedScheme {
                    scheme: other.to_owned(),
                });
            }
        }
        let text = match url.port() {
            Some(port) => format!("{scheme}://{}:{port}", host.to_ascii_lowercase()),
            None => format!("{scheme}://{}", host.to_ascii_lowercase()),
        };
        Ok(Self { text })
    }

    /// Parses an origin written as `scheme://host[:port]`.
    ///
    /// # Errors
    ///
    /// Returns [`OriginError::Malformed`] when the text is not a URL or carries
    /// a path, query or fragment, and the errors of [`Origin::of`] otherwise.
    pub fn parse(raw: &str) -> Result<Self, OriginError> {
        let url: Url = raw.parse().map_err(|_| OriginError::Malformed)?;
        if url.path() != "/" && !url.path().is_empty() {
            return Err(OriginError::Malformed);
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(OriginError::Malformed);
        }
        Self::of(&url)
    }

    /// Returns the canonical `scheme://host[:port]` text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Reports whether `url` belongs to this origin.
    #[must_use]
    pub fn covers(&self, url: &Url) -> bool {
        Self::of(url).is_ok_and(|other| other == *self)
    }

    /// Returns a [`OriginError::Mismatch`] describing why `url` is not covered.
    ///
    /// # Errors
    ///
    /// Always returns an error; it exists so callers can produce a consistent
    /// message. Returns the derivation error when `url` names no origin.
    fn reject(&self, url: &Url) -> OriginError {
        match Self::of(url) {
            Ok(actual) => OriginError::Mismatch {
                expected: self.text.clone(),
                actual: actual.text,
            },
            Err(error) => error,
        }
    }
}

impl Debug for Origin {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Origin").field(&self.text).finish()
    }
}

impl Display for Origin {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "[::1]"
        || host == "::1"
}

/// A record that an operator deliberately enrolled a non-default origin.
///
/// Providers refuse to send a credential to an origin they do not ship as a
/// default unless one of these is present. It is a distinct type rather than a
/// `bool` so that "the operator approved this" cannot be produced by accident,
/// for instance by a deserialised configuration flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginApproval {
    origin: Origin,
}

impl OriginApproval {
    /// Records an operator's decision to trust `origin`.
    ///
    /// Call this only where a human made the choice — an enterprise endpoint
    /// entered during onboarding, or a test server a test owns. Never derive
    /// one from the same configuration value it is meant to authorise.
    #[must_use]
    pub const fn enroll(origin: Origin) -> Self {
        Self { origin }
    }

    /// Returns the enrolled origin.
    #[must_use]
    pub const fn origin(&self) -> &Origin {
        &self.origin
    }
}

/// The set of origins a provider may present a credential to.
///
/// A provider's compiled-in defaults plus whatever the operator enrolled.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustedOrigins {
    origins: Vec<Origin>,
}

impl TrustedOrigins {
    /// Builds a trust set from a provider's compiled-in default origins.
    ///
    /// # Errors
    ///
    /// Returns [`OriginError`] when a default does not parse, which the
    /// accompanying tests rule out for the shipped constants.
    pub fn pinned(defaults: &[&str]) -> Result<Self, OriginError> {
        let mut origins = Vec::with_capacity(defaults.len());
        for raw in defaults {
            origins.push(Origin::parse(raw)?);
        }
        Ok(Self { origins })
    }

    /// Adds an operator-enrolled origin.
    #[must_use]
    pub fn enrolled(mut self, approval: &OriginApproval) -> Self {
        if !self.origins.contains(approval.origin()) {
            self.origins.push(approval.origin().clone());
        }
        self
    }

    /// Returns the trusted origins.
    #[must_use]
    pub fn origins(&self) -> &[Origin] {
        &self.origins
    }

    /// Returns the origin of `url` when it is trusted.
    ///
    /// # Errors
    ///
    /// Returns [`OriginError::Mismatch`] naming the trusted set when `url` is
    /// not covered by it.
    pub fn authorize(&self, url: &Url) -> Result<Origin, OriginError> {
        let origin = Origin::of(url)?;
        if self.origins.contains(&origin) {
            return Ok(origin);
        }
        Err(OriginError::Mismatch {
            expected: self
                .origins
                .iter()
                .map(Origin::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            actual: origin.text,
        })
    }
}

/// An API key that may only be presented to one origin.
///
/// The inner key is unreachable except through [`BoundApiKey::for_url`], so a
/// request to the wrong origin cannot be authenticated with it.
#[derive(Clone)]
pub struct BoundApiKey {
    origin: Origin,
    key: ApiKey,
}

impl Debug for BoundApiKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundApiKey")
            .field("origin", &self.origin.text)
            .field("key", &self.key)
            .finish()
    }
}

impl BoundApiKey {
    /// Binds `key` to `origin`.
    #[must_use]
    pub const fn new(origin: Origin, key: ApiKey) -> Self {
        Self { origin, key }
    }

    /// Binds `key` to the origin of `url`.
    ///
    /// # Errors
    ///
    /// Returns [`OriginError`] when `url` names no usable origin.
    pub fn for_endpoint(url: &Url, key: ApiKey) -> Result<Self, OriginError> {
        Ok(Self::new(Origin::of(url)?, key))
    }

    /// Returns the origin this key is authorised for.
    #[must_use]
    pub const fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Returns the key, but only for a URL on the bound origin.
    ///
    /// # Errors
    ///
    /// Returns [`OriginError::Mismatch`] when `url` is on a different origin.
    pub fn for_url(&self, url: &Url) -> Result<&ApiKey, OriginError> {
        if self.origin.covers(url) {
            return Ok(&self.key);
        }
        Err(self.origin.reject(url))
    }

    /// Returns the secret-store key this credential is filed under.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::InvalidKey`] when the composed account name
    /// is not a valid key component.
    pub fn credential_key(
        &self,
        service: &str,
        provider: &str,
    ) -> Result<CredentialKey, SecretStoreError> {
        CredentialKey::new(service, credential_account(provider, &self.origin))
    }
}

/// A secret that may only be presented to one origin.
///
/// The counterpart of [`BoundApiKey`] for credentials that are not API keys:
/// GitHub OAuth tokens, exchanged Copilot tokens and refresh tokens.
#[derive(Clone)]
pub struct BoundSecret {
    origin: Origin,
    secret: SecretString,
}

impl Debug for BoundSecret {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundSecret")
            .field("origin", &self.origin.text)
            .field("secret", &self.secret)
            .finish()
    }
}

impl BoundSecret {
    /// Binds `secret` to `origin`.
    #[must_use]
    pub const fn new(origin: Origin, secret: SecretString) -> Self {
        Self { origin, secret }
    }

    /// Returns the origin this secret is authorised for.
    #[must_use]
    pub const fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Returns the secret, but only for a URL on the bound origin.
    ///
    /// # Errors
    ///
    /// Returns [`OriginError::Mismatch`] when `url` is on a different origin.
    pub fn expose_for(&self, url: &Url) -> Result<&SecretString, OriginError> {
        if self.origin.covers(url) {
            return Ok(&self.secret);
        }
        Err(self.origin.reject(url))
    }

    /// Reports whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secret.expose().is_empty()
    }
}

/// Composes the secret-store account name for a provider at an origin.
///
/// The origin is part of the account, so a credential stored for
/// `https://api.openai.com` is simply absent when configuration points the same
/// provider at another host. That turns a silent credential redirect into a
/// missing-credential error the operator has to resolve on purpose.
#[must_use]
pub fn credential_account(provider: &str, origin: &Origin) -> String {
    format!("{provider}@{origin}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> Url {
        raw.parse().expect("a valid test URL")
    }

    #[test]
    fn origins_ignore_path_and_case_but_not_host_scheme_or_port() {
        assert_eq!(
            Origin::of(&url("https://API.OpenAI.com/v1/chat/completions"))
                .expect("an origin")
                .as_str(),
            "https://api.openai.com"
        );
        assert_eq!(
            Origin::of(&url("https://api.openai.com:8443/v1"))
                .expect("an origin")
                .as_str(),
            "https://api.openai.com:8443"
        );
        assert_ne!(
            Origin::of(&url("https://api.openai.com")).expect("an origin"),
            Origin::of(&url("https://api.openai.com.evil.test")).expect("an origin"),
            "a suffix attack must not be treated as the same origin"
        );
        assert_ne!(
            Origin::of(&url("https://api.openai.com")).expect("an origin"),
            Origin::of(&url("https://api.openai.com:8443")).expect("an origin"),
            "an explicit port is a different origin"
        );
    }

    #[test]
    fn cleartext_is_refused_except_on_loopback() {
        assert_eq!(
            Origin::of(&url("http://api.openai.com")),
            Err(OriginError::UnsupportedScheme {
                scheme: "http".to_owned()
            })
        );
        assert_eq!(
            Origin::of(&url("http://127.0.0.1:9/base"))
                .expect("loopback is allowed for local test servers")
                .as_str(),
            "http://127.0.0.1:9"
        );
        assert_eq!(
            Origin::of(&url("http://localhost:1234"))
                .expect("loopback is allowed")
                .as_str(),
            "http://localhost:1234"
        );
        assert_eq!(
            Origin::of(&url("mailto:someone@example.test")),
            Err(OriginError::Opaque)
        );
    }

    #[test]
    fn a_bound_key_refuses_every_other_origin() {
        let bound = BoundApiKey::new(
            Origin::parse("https://api.openai.com").expect("an origin"),
            ApiKey::new("sk-live-9f2c48ab"),
        );
        assert_eq!(
            bound
                .for_url(&url("https://api.openai.com/v1/chat/completions"))
                .expect("the bound origin is allowed")
                .expose(),
            "sk-live-9f2c48ab"
        );
        assert_eq!(
            bound.for_url(&url("https://evil.test/v1/chat/completions")),
            Err(OriginError::Mismatch {
                expected: "https://api.openai.com".to_owned(),
                actual: "https://evil.test".to_owned(),
            })
        );
        assert_eq!(
            bound.for_url(&url("https://api.openai.com:8443/v1")),
            Err(OriginError::Mismatch {
                expected: "https://api.openai.com".to_owned(),
                actual: "https://api.openai.com:8443".to_owned(),
            })
        );
    }

    #[test]
    fn a_bound_credential_never_renders_its_secret() {
        let bound = BoundApiKey::new(
            Origin::parse("https://api.openai.com").expect("an origin"),
            ApiKey::new("sk-live-9f2c48ab"),
        );
        let rendered = format!("{bound:?}");
        assert!(!rendered.contains("sk-live-9f2c48ab"), "{rendered}");
        assert!(rendered.contains("https://api.openai.com"), "{rendered}");

        let secret = BoundSecret::new(
            Origin::parse("https://api.github.com").expect("an origin"),
            SecretString::new("gho_live_5518f2ab"),
        );
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("gho_live_5518f2ab"), "{rendered}");
    }

    #[test]
    fn the_store_account_changes_with_the_origin() {
        let official = Origin::parse("https://api.openai.com").expect("an origin");
        let attacker = Origin::parse("https://evil.test").expect("an origin");
        assert_eq!(
            credential_account("openai", &official),
            "openai@https://api.openai.com"
        );
        assert_ne!(
            credential_account("openai", &official),
            credential_account("openai", &attacker),
            "a redirected endpoint must not resolve to the stored credential"
        );
    }

    #[test]
    fn trust_sets_admit_only_pinned_and_enrolled_origins() {
        let trusted = TrustedOrigins::pinned(&["https://api.github.com", "https://github.com"])
            .expect("the pinned origins parse");
        assert_eq!(
            trusted
                .authorize(&url("https://api.github.com/copilot_internal/v2/token"))
                .expect("a pinned origin is trusted")
                .as_str(),
            "https://api.github.com"
        );
        assert_eq!(
            trusted.authorize(&url("https://ghe.example.test/api")),
            Err(OriginError::Mismatch {
                expected: "https://api.github.com, https://github.com".to_owned(),
                actual: "https://ghe.example.test".to_owned(),
            })
        );

        let approval =
            OriginApproval::enroll(Origin::parse("https://ghe.example.test").expect("an origin"));
        let widened = trusted.enrolled(&approval);
        assert_eq!(
            widened
                .authorize(&url("https://ghe.example.test/api"))
                .expect("an enrolled origin is trusted")
                .as_str(),
            "https://ghe.example.test"
        );
        assert_eq!(widened.origins().len(), 3);
    }

    #[test]
    fn parsing_rejects_text_that_carries_more_than_an_origin() {
        assert_eq!(
            Origin::parse("https://host.test/path"),
            Err(OriginError::Malformed)
        );
        assert_eq!(
            Origin::parse("https://host.test/?q=1"),
            Err(OriginError::Malformed)
        );
        assert_eq!(
            Origin::parse("https://host.test#frag"),
            Err(OriginError::Malformed)
        );
        assert_eq!(Origin::parse("not a url"), Err(OriginError::Malformed));
        assert_eq!(
            Origin::parse("https://host.test/")
                .expect("a bare origin")
                .as_str(),
            "https://host.test"
        );
    }
}

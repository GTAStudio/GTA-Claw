//! Credential handling: redacted secret values and a pluggable [`SecretStore`] port.
//!
//! Nothing in this module ever renders a secret. [`SecretString`] deliberately
//! implements neither [`serde::Serialize`] nor a revealing [`Debug`], and the
//! only way to read the plaintext is the explicitly named
//! [`SecretString::expose`].

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::{Mutex, PoisonError};

use zeroize::Zeroize;

mod file;
pub use file::{FileSecretStore, encode_key};

#[cfg(any(target_os = "macos", target_os = "windows"))]
mod native;

#[cfg(target_os = "macos")]
mod apple;
#[cfg(target_os = "macos")]
pub use apple::AppleKeychainStore;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsCredentialManagerStore;

/// Placeholder rendered in place of any secret value.
pub const REDACTED: &str = "<redacted>";

/// Header names whose values are always replaced by [`REDACTED`].
pub const SENSITIVE_HEADERS: [&str; 9] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "x-auth-token",
    "openai-organization",
];

/// A secret string that cannot be printed, formatted or serialized.
///
/// The buffer is zeroed on drop.
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps a plaintext secret.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the plaintext. Call sites should be auditable and few.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Returns the length of the secret in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Debug for SecretString {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(")?;
        formatter.write_str(REDACTED)?;
        formatter.write_str(")")
    }
}

impl Display for SecretString {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl PartialEq for SecretString {
    /// Compares in time proportional to the longer input, without early exit on
    /// the first differing byte.
    fn eq(&self, other: &Self) -> bool {
        let left = self.0.as_bytes();
        let right = other.0.as_bytes();
        let mut difference = u8::from(left.len() != right.len());
        let length = left.len().max(right.len());
        for index in 0..length {
            let left_byte = left.get(index).copied().unwrap_or(0);
            let right_byte = right.get(index).copied().unwrap_or(0);
            difference |= left_byte ^ right_byte;
        }
        difference == 0
    }
}

impl Eq for SecretString {}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// An API key or bearer token for a provider.
#[derive(Clone, Eq, PartialEq)]
pub struct ApiKey(SecretString);

impl ApiKey {
    /// Wraps a plaintext credential.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretString::new(value))
    }

    /// Returns the plaintext credential.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// Returns the value of an `Authorization: Bearer` header.
    #[must_use]
    pub fn bearer_header(&self) -> SecretString {
        SecretString::new(format!("Bearer {}", self.0.expose()))
    }

    /// Returns `true` when the credential carries no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Debug for ApiKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKey(")?;
        formatter.write_str(REDACTED)?;
        formatter.write_str(")")
    }
}

impl Display for ApiKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl From<SecretString> for ApiKey {
    fn from(value: SecretString) -> Self {
        Self(value)
    }
}

/// Identifies one credential inside a [`SecretStore`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialKey {
    service: String,
    account: String,
}

impl CredentialKey {
    /// Builds a key from a service namespace and an account name.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::InvalidKey`] when either component is empty,
    /// longer than 256 bytes, or contains a control character.
    pub fn new(
        service: impl Into<String>,
        account: impl Into<String>,
    ) -> Result<Self, SecretStoreError> {
        let service = service.into();
        let account = account.into();
        for component in [&service, &account] {
            if component.is_empty()
                || component.len() > 256
                || component.chars().any(char::is_control)
            {
                return Err(SecretStoreError::InvalidKey);
            }
        }
        Ok(Self { service, account })
    }

    /// Returns the service namespace.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Returns the account name.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }
}

impl Display for CredentialKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.service, self.account)
    }
}

/// Failure while reading or writing a credential.
///
/// Variants carry no secret material and no attacker-controlled payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretStoreError {
    /// The key components were empty, over-long or contained control bytes.
    InvalidKey,
    /// The backend refused access, for example because the keychain is locked.
    AccessDenied {
        /// Backend that refused.
        backend: &'static str,
    },
    /// The backend is not available on this platform or in this process.
    Unavailable {
        /// Backend that is missing.
        backend: &'static str,
    },
    /// The stored value was not valid UTF-8.
    Corrupt {
        /// Backend holding the value.
        backend: &'static str,
    },
    /// The credential file had permissions that expose it to other users.
    InsecurePermissions {
        /// Octal mode observed on the file.
        mode: u32,
    },
    /// The backend failed for an unclassified reason.
    Backend {
        /// Backend that failed.
        backend: &'static str,
        /// Stable, non-sensitive description of the failure class.
        detail: &'static str,
    },
}

impl Display for SecretStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => formatter.write_str("credential key is not usable"),
            Self::AccessDenied { backend } => {
                write!(formatter, "{backend} denied access to the credential")
            }
            Self::Unavailable { backend } => {
                write!(formatter, "{backend} is unavailable on this platform")
            }
            Self::Corrupt { backend } => {
                write!(formatter, "{backend} returned a non-UTF-8 credential")
            }
            Self::InsecurePermissions { mode } => {
                write!(
                    formatter,
                    "credential file mode {mode:04o} is readable by other users"
                )
            }
            Self::Backend { backend, detail } => write!(formatter, "{backend} failed: {detail}"),
        }
    }
}

impl Error for SecretStoreError {}

/// A credential backend.
///
/// Implementations must not log, print or otherwise render secret values.
pub trait SecretStore: Send + Sync + Debug {
    /// Stable name of this backend, used in errors and diagnostics.
    fn backend(&self) -> &'static str;

    /// Reads a credential, returning `Ok(None)` when it is absent.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError`] when the backend fails.
    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, SecretStoreError>;

    /// Creates or replaces a credential.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError`] when the backend fails.
    fn set(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), SecretStoreError>;

    /// Removes a credential, returning `false` when it was already absent.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError`] when the backend fails.
    fn delete(&self, key: &CredentialKey) -> Result<bool, SecretStoreError>;
}

/// An in-memory store, used by tests and by ephemeral sessions.
#[derive(Debug, Default)]
pub struct MemorySecretStore {
    entries: Mutex<BTreeMap<CredentialKey, SecretString>>,
}

impl MemorySecretStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of stored credentials.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Returns `true` when nothing is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SecretStore for MemorySecretStore {
    fn backend(&self) -> &'static str {
        "memory"
    }

    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, SecretStoreError> {
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned())
    }

    fn set(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), SecretStoreError> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.clone(), secret.clone());
        Ok(())
    }

    fn delete(&self, key: &CredentialKey) -> Result<bool, SecretStoreError> {
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key)
            .is_some())
    }
}

/// A read-only store backed by process environment variables.
///
/// The variable name is `{SERVICE}_{ACCOUNT}` upper-cased with every character
/// outside `A-Z`, `0-9` replaced by `_`.
#[derive(Debug, Default)]
pub struct EnvSecretStore;

impl EnvSecretStore {
    /// Creates the store.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the environment variable a key maps to.
    #[must_use]
    pub fn variable_name(key: &CredentialKey) -> String {
        let mut name = String::with_capacity(key.service().len() + key.account().len() + 1);
        for part in [key.service(), key.account()] {
            if !name.is_empty() {
                name.push('_');
            }
            for character in part.chars() {
                if character.is_ascii_alphanumeric() {
                    name.push(character.to_ascii_uppercase());
                } else {
                    name.push('_');
                }
            }
        }
        name
    }
}

impl SecretStore for EnvSecretStore {
    fn backend(&self) -> &'static str {
        "environment"
    }

    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, SecretStoreError> {
        match std::env::var(Self::variable_name(key)) {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(SecretString::new(value))),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(SecretStoreError::Corrupt {
                backend: "environment",
            }),
        }
    }

    fn set(&self, _key: &CredentialKey, _secret: &SecretString) -> Result<(), SecretStoreError> {
        Err(SecretStoreError::Backend {
            backend: "environment",
            detail: "environment credentials are read-only",
        })
    }

    fn delete(&self, _key: &CredentialKey) -> Result<bool, SecretStoreError> {
        Err(SecretStoreError::Backend {
            backend: "environment",
            detail: "environment credentials are read-only",
        })
    }
}

/// Tries each backend in order on reads and writes to the first writable one.
#[derive(Debug)]
pub struct LayeredSecretStore {
    layers: Vec<Box<dyn SecretStore>>,
}

impl LayeredSecretStore {
    /// Builds a layered store. The first layer wins on reads.
    #[must_use]
    pub fn new(layers: Vec<Box<dyn SecretStore>>) -> Self {
        Self { layers }
    }

    /// Returns the ordered backend names.
    #[must_use]
    pub fn backends(&self) -> Vec<&'static str> {
        self.layers.iter().map(|layer| layer.backend()).collect()
    }
}

impl SecretStore for LayeredSecretStore {
    fn backend(&self) -> &'static str {
        "layered"
    }

    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, SecretStoreError> {
        let mut last_error = None;
        for layer in &self.layers {
            match layer.get(key) {
                Ok(Some(secret)) => return Ok(Some(secret)),
                Ok(None) => {}
                Err(error) => last_error = Some(error),
            }
        }
        match last_error {
            Some(error) => Err(error),
            None => Ok(None),
        }
    }

    fn set(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), SecretStoreError> {
        let mut last_error = SecretStoreError::Unavailable { backend: "layered" };
        for layer in &self.layers {
            match layer.set(key, secret) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    fn delete(&self, key: &CredentialKey) -> Result<bool, SecretStoreError> {
        let mut removed = false;
        let mut last_error = None;
        for layer in &self.layers {
            match layer.delete(key) {
                Ok(value) => removed |= value,
                Err(error) => last_error = Some(error),
            }
        }
        match last_error {
            Some(error) if !removed => Err(error),
            _ => Ok(removed),
        }
    }
}

/// Builds the recommended store for the current platform.
///
/// * Windows uses the Credential Manager.
/// * macOS uses the login Keychain.
/// * Every other target uses the permission-strict file backend.
///
/// # Errors
///
/// Returns [`SecretStoreError`] when the platform backend cannot be opened.
pub fn platform_secret_store() -> Result<Box<dyn SecretStore>, SecretStoreError> {
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(WindowsCredentialManagerStore::new()?))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(AppleKeychainStore::new()?))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Ok(Box::new(FileSecretStore::default_location()?))
    }
}

/// Replaces the values of [`SENSITIVE_HEADERS`] with [`REDACTED`].
///
/// Header names are compared case-insensitively.
#[must_use]
pub fn redact_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            if is_sensitive_header(name) {
                (name.clone(), REDACTED.to_owned())
            } else {
                (name.clone(), value.clone())
            }
        })
        .collect()
}

/// Returns `true` when a header name carries credential material.
#[must_use]
pub fn is_sensitive_header(name: &str) -> bool {
    SENSITIVE_HEADERS
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-live-4f9a2c7e0b1d";

    #[test]
    fn debug_and_display_never_reveal_a_secret() {
        let secret = SecretString::new(SECRET);
        assert_eq!(format!("{secret:?}"), "SecretString(<redacted>)");
        assert_eq!(format!("{secret}"), "<redacted>");
        assert!(!format!("{secret:?} {secret} {secret:#?}").contains(SECRET));
        assert_eq!(secret.expose(), SECRET);
        assert_eq!(secret.len(), SECRET.len());
        assert!(!secret.is_empty());
    }

    #[test]
    fn api_key_debug_and_display_never_reveal_a_secret() {
        let key = ApiKey::new(SECRET);
        assert_eq!(format!("{key:?}"), "ApiKey(<redacted>)");
        assert_eq!(format!("{key}"), "<redacted>");
        assert!(!format!("{key:?}{key}").contains(SECRET));
        assert_eq!(key.expose(), SECRET);
        assert_eq!(key.bearer_header().expose(), format!("Bearer {SECRET}"));
        assert!(!format!("{:?}", key.bearer_header()).contains(SECRET));
        assert!(!ApiKey::new(SECRET).is_empty());
        assert!(ApiKey::new("").is_empty());
    }

    #[test]
    fn a_secret_nested_in_a_struct_is_still_redacted() {
        #[derive(Debug)]
        struct Config {
            endpoint: String,
            key: ApiKey,
        }

        let config = Config {
            endpoint: "https://api.example.test/v1".to_owned(),
            key: ApiKey::new(SECRET),
        };
        let rendered = format!("{config:#?}");
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(rendered.contains("https://api.example.test/v1"));
        assert!(rendered.contains("<redacted>"));
        assert_eq!(config.endpoint, "https://api.example.test/v1");
        assert_eq!(config.key.expose(), SECRET);
    }

    #[test]
    fn secret_equality_is_value_based() {
        assert_eq!(SecretString::new("abc"), SecretString::new("abc"));
        assert_ne!(SecretString::new("abc"), SecretString::new("abd"));
        assert_ne!(SecretString::new("abc"), SecretString::new("abcd"));
        assert_ne!(SecretString::new(""), SecretString::new("a"));
        assert_eq!(SecretString::new(""), SecretString::new(""));
    }

    #[test]
    fn secret_store_errors_never_carry_secret_material() {
        let errors = [
            SecretStoreError::InvalidKey,
            SecretStoreError::AccessDenied {
                backend: "keychain",
            },
            SecretStoreError::Unavailable {
                backend: "keychain",
            },
            SecretStoreError::Corrupt {
                backend: "keychain",
            },
            SecretStoreError::InsecurePermissions { mode: 0o644 },
            SecretStoreError::Backend {
                backend: "keychain",
                detail: "write failed",
            },
        ];
        for error in errors {
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains(SECRET), "{rendered}");
        }
        assert_eq!(
            SecretStoreError::InsecurePermissions { mode: 0o644 }.to_string(),
            "credential file mode 0644 is readable by other users"
        );
    }

    #[test]
    fn credential_keys_reject_unusable_components() {
        assert_eq!(
            CredentialKey::new("", "a"),
            Err(SecretStoreError::InvalidKey)
        );
        assert_eq!(
            CredentialKey::new("a", ""),
            Err(SecretStoreError::InvalidKey)
        );
        assert_eq!(
            CredentialKey::new("a\u{7}b", "c"),
            Err(SecretStoreError::InvalidKey)
        );
        assert_eq!(
            CredentialKey::new("a".repeat(257), "c"),
            Err(SecretStoreError::InvalidKey)
        );
        let key = CredentialKey::new("gta-claw:openai", "default").expect("valid");
        assert_eq!(key.service(), "gta-claw:openai");
        assert_eq!(key.account(), "default");
        assert_eq!(key.to_string(), "gta-claw:openai/default");
    }

    #[test]
    fn memory_store_round_trips_and_deletes() {
        let store = MemorySecretStore::new();
        let key = CredentialKey::new("gta-claw:openai", "default").expect("valid");
        assert!(store.is_empty());
        assert_eq!(store.get(&key).expect("get"), None);

        store
            .set(&key, &SecretString::new(SECRET))
            .expect("set succeeds");
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.get(&key).expect("get").expect("present").expose(),
            SECRET
        );

        store
            .set(&key, &SecretString::new("second"))
            .expect("overwrite");
        assert_eq!(
            store.get(&key).expect("get").expect("present").expose(),
            "second"
        );
        assert_eq!(store.len(), 1);

        assert!(store.delete(&key).expect("delete"));
        assert!(!store.delete(&key).expect("second delete"));
        assert_eq!(store.get(&key).expect("get"), None);
        assert_eq!(store.backend(), "memory");
    }

    #[test]
    fn memory_store_debug_output_holds_no_secret() {
        let store = MemorySecretStore::new();
        let key = CredentialKey::new("gta-claw:openai", "default").expect("valid");
        store
            .set(&key, &SecretString::new(SECRET))
            .expect("set succeeds");
        let rendered = format!("{store:?}");
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn environment_variable_names_are_normalized() {
        let key = CredentialKey::new("gta-claw:openai", "team.default").expect("valid");
        assert_eq!(
            EnvSecretStore::variable_name(&key),
            "GTA_CLAW_OPENAI_TEAM_DEFAULT"
        );
    }

    #[test]
    fn environment_store_is_read_only() {
        let store = EnvSecretStore::new();
        let key = CredentialKey::new("gta-claw-absent", "nobody").expect("valid");
        assert_eq!(store.get(&key).expect("get"), None);
        assert_eq!(
            store.set(&key, &SecretString::new(SECRET)),
            Err(SecretStoreError::Backend {
                backend: "environment",
                detail: "environment credentials are read-only",
            })
        );
        assert_eq!(
            store.delete(&key),
            Err(SecretStoreError::Backend {
                backend: "environment",
                detail: "environment credentials are read-only",
            })
        );
    }

    #[test]
    fn layered_store_reads_from_the_first_layer_that_has_the_key() {
        let first = MemorySecretStore::new();
        let second = MemorySecretStore::new();
        let key = CredentialKey::new("gta-claw:openai", "default").expect("valid");
        second
            .set(&key, &SecretString::new("from-second"))
            .expect("set");

        let layered = LayeredSecretStore::new(vec![Box::new(first), Box::new(second)]);
        assert_eq!(layered.backends(), vec!["memory", "memory"]);
        assert_eq!(
            layered.get(&key).expect("get").expect("present").expose(),
            "from-second"
        );

        layered
            .set(&key, &SecretString::new("written"))
            .expect("set goes to the first writable layer");
        assert_eq!(
            layered.get(&key).expect("get").expect("present").expose(),
            "written"
        );
        assert!(layered.delete(&key).expect("delete removes every copy"));
        assert_eq!(layered.get(&key).expect("get"), None);
    }

    #[test]
    fn layered_store_falls_through_a_read_only_layer_on_write() {
        let key = CredentialKey::new("gta-claw:openai", "default").expect("valid");
        let layered = LayeredSecretStore::new(vec![
            Box::new(EnvSecretStore::new()),
            Box::new(MemorySecretStore::new()),
        ]);
        layered
            .set(&key, &SecretString::new(SECRET))
            .expect("memory layer accepts the write");
        assert_eq!(
            layered.get(&key).expect("get").expect("present").expose(),
            SECRET
        );
    }

    #[test]
    fn sensitive_headers_are_redacted_case_insensitively() {
        let headers = vec![
            ("Authorization".to_owned(), format!("Bearer {SECRET}")),
            ("X-API-Key".to_owned(), SECRET.to_owned()),
            ("x-goog-api-key".to_owned(), SECRET.to_owned()),
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("User-Agent".to_owned(), "gta-claw/1".to_owned()),
        ];
        let redacted = redact_headers(&headers);
        assert_eq!(
            redacted,
            vec![
                ("Authorization".to_owned(), REDACTED.to_owned()),
                ("X-API-Key".to_owned(), REDACTED.to_owned()),
                ("x-goog-api-key".to_owned(), REDACTED.to_owned()),
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("User-Agent".to_owned(), "gta-claw/1".to_owned()),
            ]
        );
        assert!(!format!("{redacted:?}").contains(SECRET));
        assert!(is_sensitive_header("AUTHORIZATION"));
        assert!(!is_sensitive_header("content-type"));
    }
}

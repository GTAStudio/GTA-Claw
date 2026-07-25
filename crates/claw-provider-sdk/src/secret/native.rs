//! Shared glue between the [`SecretStore`] port and `keyring-core` credential
//! stores.
//!
//! Only compiled on targets that have a native keystore.

use std::collections::HashMap;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use keyring_core::api::CredentialStoreApi;

use super::{CredentialKey, SecretStore, SecretStoreError, SecretString};

/// Characters that must not survive into a platform identifier verbatim.
///
/// The Windows Credential Manager store composes its target name as
/// `{account}.{service}`. A [`CredentialKey`] may contain `.`, so
/// `(service = "b.c", account = "a")` and `(service = "c", account = "a.b")`
/// both compose to `a.b.c` — one provider reading another provider's
/// credential. Percent-encoding `.` (and `%`, so the encoding itself stays
/// reversible) makes the separator impossible inside a component, which makes
/// the composition injective.
fn encode_component(raw: &str) -> String {
    let mut encoded = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '%' => encoded.push_str("%25"),
            '.' => encoded.push_str("%2E"),
            other => encoded.push(other),
        }
    }
    encoded
}

/// Reverses [`encode_component`], rejecting anything it could not have produced.
fn decode_component(encoded: &str) -> Option<String> {
    let mut decoded = String::with_capacity(encoded.len());
    let mut rest = encoded;
    while let Some(index) = rest.find('%') {
        decoded.push_str(&rest[..index]);
        let escape = rest.get(index..index + 3)?;
        match escape {
            "%25" => decoded.push('%'),
            "%2E" => decoded.push('.'),
            _ => return None,
        }
        rest = &rest[index + 3..];
    }
    decoded.push_str(rest);
    Some(decoded)
}

/// Adapts any `keyring-core` credential store to the [`SecretStore`] port.
pub(super) struct NativeKeyringStore {
    backend: &'static str,
    store: Arc<dyn CredentialStoreApi + Send + Sync>,
}

impl Debug for NativeKeyringStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeKeyringStore")
            .field("backend", &self.backend)
            .field("vendor", &self.store.vendor())
            .finish()
    }
}

impl NativeKeyringStore {
    pub(super) fn new(
        backend: &'static str,
        store: Arc<dyn CredentialStoreApi + Send + Sync>,
    ) -> Self {
        Self { backend, store }
    }

    /// Returns the vendor string reported by the underlying store.
    pub(super) fn vendor(&self) -> String {
        self.store.vendor()
    }

    fn entry(&self, key: &CredentialKey) -> Result<keyring_core::Entry, SecretStoreError> {
        self.store
            .build(
                &encode_component(key.service()),
                &encode_component(key.account()),
                None,
            )
            .map_err(|error| self.map_error(&error))
    }

    fn map_error(&self, error: &keyring_core::Error) -> SecretStoreError {
        use keyring_core::Error as KeyringError;

        match error {
            KeyringError::NoEntry => SecretStoreError::Backend {
                backend: self.backend,
                detail: "credential is absent",
            },
            KeyringError::NoStorageAccess(_) => SecretStoreError::AccessDenied {
                backend: self.backend,
            },
            KeyringError::PlatformFailure(_) => SecretStoreError::Backend {
                backend: self.backend,
                detail: "the platform keystore reported a failure",
            },
            KeyringError::BadEncoding(_) | KeyringError::BadDataFormat(_, _) => {
                SecretStoreError::Corrupt {
                    backend: self.backend,
                }
            }
            KeyringError::BadStoreFormat(_) => SecretStoreError::Backend {
                backend: self.backend,
                detail: "the platform keystore holds an unreadable record",
            },
            KeyringError::TooLong(_, _) => SecretStoreError::Backend {
                backend: self.backend,
                detail: "the credential exceeds the keystore size limit",
            },
            KeyringError::Invalid(_, _) => SecretStoreError::InvalidKey,
            KeyringError::Ambiguous(_) => SecretStoreError::Backend {
                backend: self.backend,
                detail: "several credentials match this key",
            },
            KeyringError::NoDefaultStore | KeyringError::NotSupportedByStore(_) => {
                SecretStoreError::Unavailable {
                    backend: self.backend,
                }
            }
            _ => SecretStoreError::Backend {
                backend: self.backend,
                detail: "the platform keystore reported an unknown failure",
            },
        }
    }
}

impl SecretStore for NativeKeyringStore {
    fn backend(&self) -> &'static str {
        self.backend
    }

    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, SecretStoreError> {
        let entry = self.entry(key)?;
        match entry.get_password() {
            Ok(password) => Ok(Some(SecretString::new(password))),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => Err(self.map_error(&error)),
        }
    }

    fn set(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), SecretStoreError> {
        let entry = self.entry(key)?;
        entry
            .set_password(secret.expose())
            .map_err(|error| self.map_error(&error))
    }

    fn delete(&self, key: &CredentialKey) -> Result<bool, SecretStoreError> {
        let entry = self.entry(key)?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring_core::Error::NoEntry) => Ok(false),
            Err(error) => Err(self.map_error(&error)),
        }
    }

    /// Lists accounts through the keystore's own search facility.
    ///
    /// A store that does not implement search reports
    /// [`SecretStoreError::EnumerationUnsupported`], which disables transactions
    /// rather than silently degrading them.
    fn accounts(&self, service: &str) -> Result<Vec<String>, SecretStoreError> {
        let encoded_service = encode_component(service);
        let mut specification = HashMap::new();
        specification.insert("service", encoded_service.as_str());
        let found = match self.store.search(&specification) {
            Ok(found) => found,
            Err(keyring_core::Error::NotSupportedByStore(_)) => {
                return Err(SecretStoreError::EnumerationUnsupported {
                    backend: self.backend,
                });
            }
            Err(error) => return Err(self.map_error(&error)),
        };
        Ok(found
            .iter()
            .filter_map(|entry| entry.get_specifiers())
            .filter(|(found_service, _)| found_service == &encoded_service)
            .filter_map(|(_, account)| decode_component(&account))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_component, encode_component};

    /// The exact pair that collided before the components were encoded.
    #[test]
    fn keys_that_shared_a_windows_target_now_compose_to_different_ones() {
        // The Windows store's own composition, reproduced here so the test
        // states the property rather than trusting the platform to hold it.
        let compose = |service: &str, account: &str| {
            format!(
                "{}.{}",
                encode_component(account),
                encode_component(service)
            )
        };

        assert_eq!(compose("b.c", "a"), "a.b%2Ec");
        assert_eq!(compose("c", "a.b"), "a%2Eb.c");
        assert_ne!(compose("b.c", "a"), compose("c", "a.b"));
    }

    #[test]
    fn components_round_trip_through_the_encoding() {
        for raw in [
            "openai",
            "gta-claw.secret-transaction",
            "manifest.0123456789abcdef0123456789abcdef",
            "100%",
            "%2E",
            "a.b%c.d",
            "",
            "..",
        ] {
            let encoded = encode_component(raw);
            assert!(!encoded.contains('.') || !raw.contains('.'));
            assert_eq!(
                decode_component(&encoded).as_deref(),
                Some(raw),
                "round trip failed for {raw:?} via {encoded:?}"
            );
        }
    }

    #[test]
    fn encoding_leaves_no_separator_inside_a_component() {
        assert!(!encode_component("a.b.c").contains('.'));
        assert_eq!(encode_component("a.b.c"), "a%2Eb%2Ec");
    }

    #[test]
    fn decoding_rejects_escapes_the_encoder_never_emits() {
        assert_eq!(decode_component("%2e"), None, "lowercase is not emitted");
        assert_eq!(decode_component("%41"), None, "only . and % are escaped");
        assert_eq!(decode_component("%2"), None, "a truncated escape");
        assert_eq!(decode_component("abc%"), None, "a dangling percent");
    }
}

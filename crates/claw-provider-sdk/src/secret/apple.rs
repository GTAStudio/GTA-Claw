//! macOS Keychain adapter.

use std::fmt::{self, Debug, Formatter};

use super::native::NativeKeyringStore;
use super::{CredentialKey, SecretStore, SecretStoreError, SecretString};

const BACKEND: &str = "macos-keychain";

/// Credential store backed by the macOS login Keychain.
///
/// Each [`CredentialKey`] maps to one generic password item. The service and
/// account are percent-encoded on the way to the platform so that every native
/// backend addresses a key the same way; see
/// the private `native` module for why the encoding exists.
pub struct AppleKeychainStore {
    inner: NativeKeyringStore,
}

impl Debug for AppleKeychainStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppleKeychainStore")
            .field("vendor", &self.inner.vendor())
            .finish()
    }
}

impl AppleKeychainStore {
    /// Opens the login Keychain.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::Unavailable`] when the Keychain cannot be
    /// opened in this process.
    pub fn new() -> Result<Self, SecretStoreError> {
        let store = apple_native_keyring_store::keychain::Store::new()
            .map_err(|_| SecretStoreError::Unavailable { backend: BACKEND })?;
        Ok(Self {
            inner: NativeKeyringStore::new(BACKEND, store),
        })
    }
}

impl SecretStore for AppleKeychainStore {
    fn backend(&self) -> &'static str {
        BACKEND
    }

    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, SecretStoreError> {
        self.inner.get(key)
    }

    fn set(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), SecretStoreError> {
        self.inner.set(key, secret)
    }

    fn delete(&self, key: &CredentialKey) -> Result<bool, SecretStoreError> {
        self.inner.delete(key)
    }

    fn accounts(&self, service: &str) -> Result<Vec<String>, SecretStoreError> {
        self.inner.accounts(service)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises the real Keychain round trip.
    ///
    /// Headless runners have no unlocked login Keychain, so an
    /// [`SecretStoreError::Unavailable`] or [`SecretStoreError::AccessDenied`]
    /// result is treated as "not testable here" rather than a failure. This
    /// touches no network.
    #[test]
    fn keychain_round_trips_a_secret() {
        let store = match AppleKeychainStore::new() {
            Ok(store) => store,
            Err(SecretStoreError::Unavailable { .. }) => return,
            Err(error) => panic!("unexpected failure: {error}"),
        };
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_nanos();
        let key = CredentialKey::new("gta-claw-test", format!("case-{nanos}")).expect("valid");

        match store.get(&key) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("a freshly generated key must not already exist"),
            Err(SecretStoreError::AccessDenied { .. }) => return,
            Err(error) => panic!("unexpected failure: {error}"),
        }
        store
            .set(&key, &SecretString::new("sk-live-4f9a2c7e0b1d"))
            .expect("set");
        assert_eq!(
            store.get(&key).expect("get").expect("present").expose(),
            "sk-live-4f9a2c7e0b1d"
        );
        store.set(&key, &SecretString::new("rotated")).expect("set");
        assert_eq!(
            store.get(&key).expect("get").expect("present").expose(),
            "rotated"
        );
        assert!(store.delete(&key).expect("delete"));
        assert!(!store.delete(&key).expect("second delete"));
        assert_eq!(store.get(&key).expect("get"), None);
        assert_eq!(store.backend(), "macos-keychain");
    }

    #[test]
    fn debug_output_names_the_backend_and_holds_no_secret() {
        let Ok(store) = AppleKeychainStore::new() else {
            return;
        };
        let rendered = format!("{store:?}");
        assert!(rendered.contains("AppleKeychainStore"), "{rendered}");
        assert!(!rendered.contains("sk-"), "{rendered}");
    }
}

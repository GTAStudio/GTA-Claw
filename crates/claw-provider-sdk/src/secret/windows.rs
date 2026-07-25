//! Windows Credential Manager adapter.

use std::fmt::{self, Debug, Formatter};

use super::native::NativeKeyringStore;
use super::{CredentialKey, SecretStore, SecretStoreError, SecretString};

const BACKEND: &str = "windows-credential-manager";

/// Credential store backed by the Windows Credential Manager.
///
/// Each [`CredentialKey`] maps to one generic credential. The service and
/// account are percent-encoded before they reach the platform, because the
/// underlying store composes its target name as `{account}.{service}` and a
/// [`CredentialKey`] is allowed to contain `.`; without encoding,
/// `(service = "b.c", account = "a")` and `(service = "c", account = "a.b")`
/// would address the same Windows credential.
pub struct WindowsCredentialManagerStore {
    inner: NativeKeyringStore,
}

impl Debug for WindowsCredentialManagerStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsCredentialManagerStore")
            .field("vendor", &self.inner.vendor())
            .finish()
    }
}

impl WindowsCredentialManagerStore {
    /// Opens the Credential Manager.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::Unavailable`] when the Credential Manager
    /// cannot be opened in this process.
    pub fn new() -> Result<Self, SecretStoreError> {
        let store = windows_native_keyring_store::store::Store::new()
            .map_err(|_| SecretStoreError::Unavailable { backend: BACKEND })?;
        Ok(Self {
            inner: NativeKeyringStore::new(BACKEND, store),
        })
    }
}

impl SecretStore for WindowsCredentialManagerStore {
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

    /// Exercises the real Credential Manager round trip.
    ///
    /// The key is namespaced to this test and removed afterwards, so the run
    /// leaves nothing behind. This touches no network.
    #[test]
    fn credential_manager_round_trips_a_secret() {
        let store = match WindowsCredentialManagerStore::new() {
            Ok(store) => store,
            Err(SecretStoreError::Unavailable { .. }) => return,
            Err(error) => panic!("unexpected failure: {error}"),
        };
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_nanos();
        let key = CredentialKey::new("gta-claw-test", format!("case-{nanos}")).expect("valid");

        assert_eq!(store.get(&key).expect("absent key reads as None"), None);
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
        assert_eq!(store.backend(), "windows-credential-manager");
    }

    #[test]
    fn debug_output_names_the_backend_and_holds_no_secret() {
        let Ok(store) = WindowsCredentialManagerStore::new() else {
            return;
        };
        let rendered = format!("{store:?}");
        assert!(
            rendered.contains("WindowsCredentialManagerStore"),
            "{rendered}"
        );
        assert!(!rendered.contains("sk-"), "{rendered}");
    }

    /// Proves the fix against the real Credential Manager, not against our own
    /// encoder.
    ///
    /// Before the components were encoded, both keys below composed to the
    /// target `a.b.c-<nanos>`, so the second `set` overwrote the first and the
    /// first key then read back the second provider's credential.
    #[test]
    fn two_keys_that_used_to_share_a_target_hold_separate_credentials() {
        let store = match WindowsCredentialManagerStore::new() {
            Ok(store) => store,
            Err(SecretStoreError::Unavailable { .. }) => return,
            Err(error) => panic!("unexpected failure: {error}"),
        };
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_nanos();

        // Dotted service, plain account.
        let dotted_service =
            CredentialKey::new(format!("b.c-{nanos}"), "a").expect("a valid credential key");
        // Plain service, dotted account. `{account}.{service}` composes both to
        // the same string unless the components are encoded.
        let dotted_account =
            CredentialKey::new(format!("c-{nanos}"), "a.b").expect("a valid credential key");

        store
            .set(&dotted_service, &SecretString::new("sk-first-2b7f10ac"))
            .expect("the first credential is stored");
        store
            .set(&dotted_account, &SecretString::new("sk-second-91de44c0"))
            .expect("the second credential is stored");

        let first = store
            .get(&dotted_service)
            .expect("the first credential is readable")
            .expect("the first credential is present");
        let second = store
            .get(&dotted_account)
            .expect("the second credential is readable")
            .expect("the second credential is present");

        assert_eq!(
            first.expose(),
            "sk-first-2b7f10ac",
            "the second key overwrote the first, so the two keys still collide"
        );
        assert_eq!(second.expose(), "sk-second-91de44c0");

        assert!(store.delete(&dotted_service).expect("cleanup"));
        assert!(store.delete(&dotted_account).expect("cleanup"));
    }
}

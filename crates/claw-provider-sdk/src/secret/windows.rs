//! Windows Credential Manager adapter.

use std::fmt::{self, Debug, Formatter};

use super::native::NativeKeyringStore;
use super::{CredentialKey, SecretStore, SecretStoreError, SecretString};

const BACKEND: &str = "windows-credential-manager";

/// Credential store backed by the Windows Credential Manager.
///
/// Each [`CredentialKey`] maps to one generic credential whose target name is
/// `{account}.{service}`.
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
}

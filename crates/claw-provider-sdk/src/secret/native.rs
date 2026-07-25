//! Shared glue between the [`SecretStore`] port and `keyring-core` credential
//! stores.
//!
//! Only compiled on targets that have a native keystore.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use keyring_core::api::CredentialStoreApi;

use super::{CredentialKey, SecretStore, SecretStoreError, SecretString};

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
            .build(key.service(), key.account(), None)
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
}

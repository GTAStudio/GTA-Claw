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

    #[test]
    #[ignore = "subprocess fixture invoked by independent_processes_read_the_same_native_credential"]
    fn native_cross_process_read_fixture() {
        let account = std::env::var("GTA_CLAW_NATIVE_CREDENTIAL_FIXTURE_ACCOUNT")
            .expect("owned fixture account");
        let stage: u8 = std::env::var("GTA_CLAW_NATIVE_CREDENTIAL_FIXTURE_STAGE")
            .expect("owned fixture stage")
            .parse()
            .expect("bounded fixture stage");
        assert!(
            account.starts_with("fixture-")
                && account.len() <= 128
                && account
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        );
        assert!(stage <= 4);
        let key =
            CredentialKey::new("gta-claw.test.process-native", account).expect("owned namespace");
        let store = WindowsCredentialManagerStore::new().expect("native store");
        let observed = store.get(&key).expect("fresh process read");
        if stage == 4 {
            assert!(
                observed.is_none(),
                "deleted fixture remains present in a fresh process"
            );
        } else {
            assert!(
                observed
                    .as_ref()
                    .is_some_and(|value| value
                        == &SecretString::new(format!("synthetic-process-stage-{stage}"))),
                "native fixture read mismatch: stage={stage}, present={}",
                observed.is_some()
            );
        }
    }

    #[test]
    fn independent_processes_read_the_same_native_credential() {
        struct OwnedCredential {
            store: WindowsCredentialManagerStore,
            key: CredentialKey,
        }
        impl Drop for OwnedCredential {
            fn drop(&mut self) {
                let _ = self.store.delete(&self.key);
            }
        }
        let account = format!(
            "fixture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("fixture clock")
                .as_nanos()
        );
        let owned = OwnedCredential {
            store: WindowsCredentialManagerStore::new().expect("native backend"),
            key: CredentialKey::new("gta-claw.test.process-native", &account)
                .expect("owned fixture key"),
        };
        assert!(
            owned
                .store
                .get(&owned.key)
                .expect("unique preflight")
                .is_none()
        );
        let reader = WindowsCredentialManagerStore::new().expect("independent parent reader");
        for stage in 0_u8..=4 {
            if stage == 4 {
                assert!(
                    owned
                        .store
                        .delete(&owned.key)
                        .expect("confirmed owned deletion")
                );
            } else {
                let expected = SecretString::new(format!("synthetic-process-stage-{stage}"));
                owned
                    .store
                    .set(&owned.key, &expected)
                    .expect("fixture write");
                assert!(
                    reader
                        .get(&owned.key)
                        .expect("independent parent read")
                        .is_some_and(|observed| observed == expected)
                );
            }
            let mut command =
                std::process::Command::new(std::env::current_exe().expect("test binary"));
            command.env_clear();
            for name in ["SystemRoot", "SystemDrive", "WINDIR"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            let output = command
                .args([
                    "--exact",
                    "secret::windows::tests::native_cross_process_read_fixture",
                    "--ignored",
                    "--nocapture",
                ])
                .env("GTA_CLAW_NATIVE_CREDENTIAL_FIXTURE_ACCOUNT", &account)
                .env(
                    "GTA_CLAW_NATIVE_CREDENTIAL_FIXTURE_STAGE",
                    stage.to_string(),
                )
                .stdin(std::process::Stdio::null())
                .output()
                .expect("fresh reader process");
            let stdout = String::from_utf8(output.stdout).expect("fixture output");
            let stderr = String::from_utf8(output.stderr).expect("fixture diagnostic");
            assert!(
                !stdout.contains("synthetic-process-stage")
                    && !stderr.contains("synthetic-process-stage")
            );
            assert!(output.status.success(), "stage {stage}: {stdout} {stderr}");
            assert!(
                stdout.contains("1 passed; 0 failed"),
                "fresh process must actually execute the fixture"
            );
        }
        assert!(
            owned
                .store
                .get(&owned.key)
                .expect("cleanup readback")
                .is_none()
        );
    }

    #[test]
    fn independent_native_handles_isolate_concurrent_credential_lifecycles() {
        use std::sync::{Arc, Barrier};

        struct OwnedCredential {
            store: WindowsCredentialManagerStore,
            key: CredentialKey,
        }

        impl Drop for OwnedCredential {
            fn drop(&mut self) {
                let _ = self.store.delete(&self.key);
            }
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("fixture clock")
            .as_nanos();
        let barriers: [Arc<Barrier>; 3] = std::array::from_fn(|_| Arc::new(Barrier::new(4)));
        let credentials: Vec<_> = (0..4)
            .map(|ordinal| {
                let owned = OwnedCredential {
                    store: WindowsCredentialManagerStore::new().expect("owned native store"),
                    key: CredentialKey::new(
                        "gta-claw.test.concurrent-native",
                        format!("owned-{}-{nonce}-{ordinal}", std::process::id()),
                    )
                    .expect("unique owned key"),
                };
                let reader = WindowsCredentialManagerStore::new().expect("independent reader");
                assert!(
                    owned
                        .store
                        .get(&owned.key)
                        .expect("unique key preflight")
                        .is_none()
                );
                (owned, reader)
            })
            .collect();
        std::thread::scope(|threads| {
            let mut workers = Vec::new();
            for (ordinal, (owned, reader)) in credentials.into_iter().enumerate() {
                let barriers = barriers.clone();
                workers.push(threads.spawn(move || {
                    let mut stages = Vec::new();
                    for generation in 0..4 {
                        let value = SecretString::new(format!("owned-synthetic-{ordinal}-{generation}"));
                        let set = owned.store.set(&owned.key, &value);
                        barriers[0].wait();
                        let same = owned.store.get(&owned.key);
                        let independent = reader.get(&owned.key);
                        barriers[1].wait();
                        stages.push(set.is_ok()
                            && same.as_ref().is_ok_and(|observed| observed.as_ref() == Some(&value))
                            && independent.as_ref().is_ok_and(|observed| observed.as_ref() == Some(&value)));
                    }
                    let deleted = owned.store.delete(&owned.key);
                    barriers[2].wait();
                    let absent = reader.get(&owned.key);
                    assert!(stages.iter().all(|stage| *stage), "native handle write/readback mismatch for owned fixture {ordinal}: {stages:?}");
                    assert!(matches!(deleted, Ok(true)), "owned fixture deletion {ordinal}: {deleted:?}");
                    assert!(matches!(absent, Ok(None)), "owned fixture deletion readback {ordinal}, presence or static error: {:?}", absent.map(|value| value.is_some()));
                }));
            }
            for worker in workers {
                worker.join().expect("owned credential worker");
            }
        });
    }

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

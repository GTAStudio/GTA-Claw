use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use claw_provider_sdk::secret::{CredentialKey, SecretStore, SecretString as StoredSecret};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use super::{CredentialBinding, CredentialStoreError, TokenSet, TokenStore, TokenWire};

const SERVICE: &str = "gta-claw.mcp-oauth";
const MAX_RECORD_BYTES: usize = 16 * 1024;

/// Local record state, without exposing token data or claiming remote authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeTokenStatus {
    /// No native record exists for the binding.
    Absent,
    /// An interrupted update or deletion requires explicit new authorization.
    ReauthorizationRequired,
    /// The local record is valid; its authority still needs checking before use.
    Available {
        /// The stored access token passes the local expiration check.
        fresh: bool,
        /// A refresh token is stored.
        can_refresh: bool,
        /// The authorization server supplied a finite expiration.
        expiry_known: bool,
    },
}

/// Synchronous OAuth token persistence in the native Windows/macOS credential store.
///
/// Only exact origin/profile keys in its dedicated namespace are accessed. There
/// is no enumeration, file fallback, or token output. Callers must schedule this
/// blocking adapter appropriately; the native API has no hard I/O deadline.
/// Writes/deletes are read back once, not atomically compared with external writers.
#[derive(Clone)]
pub struct NativeTokenStore {
    backend: Arc<dyn SecretStore>,
}

impl Debug for NativeTokenStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTokenStore")
            .field("backend", &self.backend.backend())
            .finish_non_exhaustive()
    }
}

impl NativeTokenStore {
    /// Opens only the current platform's native credential store.
    ///
    /// # Errors
    /// Fails on unsupported platforms or when native credentials are unavailable.
    pub fn new() -> Result<Self, CredentialStoreError> {
        #[cfg(target_os = "windows")]
        let backend = claw_provider_sdk::secret::WindowsCredentialManagerStore::new()
            .map(|store| Arc::new(store) as Arc<dyn SecretStore>);
        #[cfg(target_os = "macos")]
        let backend = claw_provider_sdk::secret::AppleKeychainStore::new()
            .map(|store| Arc::new(store) as Arc<dyn SecretStore>);
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            Ok(Self {
                backend: backend.map_err(|_| failure("native OAuth token store is unavailable"))?,
            })
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            Err(failure(
                "native OAuth token storage is unsupported; no fallback is allowed",
            ))
        }
    }

    /// Returns the dedicated native reference without accessing a store.
    #[must_use]
    pub fn keyring_reference(binding: &CredentialBinding) -> String {
        format!("keyring://{SERVICE}/{}", account(binding))
    }

    /// Reads only the local record's bounded availability metadata.
    ///
    /// # Errors
    /// Rejects unavailable native storage or corrupt/foreign-bound records rather
    /// than treating them as absent. No refresh or network operation is performed.
    pub fn status(
        &self,
        binding: &CredentialBinding,
    ) -> Result<NativeTokenStatus, CredentialStoreError> {
        let Some(encoded) = self
            .backend
            .get(&Self::key(binding)?)
            .map_err(|_| failure("native OAuth token lookup failed"))?
        else {
            return Ok(NativeTokenStatus::Absent);
        };
        let record = read_record(binding, &encoded)?;
        if record.incomplete {
            return Ok(NativeTokenStatus::ReauthorizationRequired);
        }
        let tokens = decode_record(record)?;
        Ok(NativeTokenStatus::Available {
            fresh: tokens.is_fresh(SystemTime::now()),
            can_refresh: tokens.can_refresh(),
            expiry_known: tokens.expires_at.is_some(),
        })
    }

    fn key(binding: &CredentialBinding) -> Result<CredentialKey, CredentialStoreError> {
        CredentialKey::new(SERVICE, account(binding))
            .map_err(|_| failure("OAuth token key is invalid"))
    }

    fn write_confirmed(
        &self,
        key: &CredentialKey,
        encoded: &StoredSecret,
    ) -> Result<(), CredentialStoreError> {
        self.backend.set(key, encoded).map_err(|_| {
            failure("native OAuth token write was not confirmed; do not automatically retry")
        })?;
        let observed = self
            .backend
            .get(key)
            .map_err(|_| failure("native OAuth token write readback failed; outcome is unknown"))?
            .ok_or_else(|| {
                failure("native OAuth token record is absent after write; outcome is unknown")
            })?;
        if &observed != encoded {
            return Err(failure(
                "native OAuth token record changed during verification; outcome is unknown",
            ));
        }
        Ok(())
    }
}

impl TokenStore for NativeTokenStore {
    fn load(&self, binding: &CredentialBinding) -> Result<Option<TokenSet>, CredentialStoreError> {
        self.backend
            .get(&Self::key(binding)?)
            .map_err(|_| failure("native OAuth token lookup failed"))?
            .map(|encoded| decode(binding, &encoded))
            .transpose()
    }

    fn begin_update(
        &self,
        binding: &CredentialBinding,
        previous: Option<&TokenSet>,
    ) -> Result<(), CredentialStoreError> {
        if let Some(previous) = previous {
            let current = self
                .load(binding)?
                .ok_or_else(|| failure("native OAuth refresh credential is absent"))?;
            if !super::same_token_generation(previous, &current) {
                return Err(failure(
                    "native OAuth refresh credential changed before its update marker",
                ));
            }
        }
        let pending = RecordRef {
            schema_version: 1,
            binding: &account(binding),
            incomplete: true,
            access_token: "",
            refresh_token: None,
            token_type: "Bearer",
            scope: None,
            expires_at: None,
            authority: [0; 32],
        };
        let encoded = StoredSecret::new(
            serde_json::to_string(&pending)
                .map_err(|_| failure("native OAuth update marker cannot be encoded"))?,
        );
        self.write_confirmed(&Self::key(binding)?, &encoded)
    }

    fn save(
        &self,
        binding: &CredentialBinding,
        tokens: TokenSet,
    ) -> Result<(), CredentialStoreError> {
        let key = Self::key(binding)?;
        let encoded = encode(binding, &tokens)?;
        self.write_confirmed(&key, &encoded)
    }

    fn delete(&self, binding: &CredentialBinding) -> Result<(), CredentialStoreError> {
        let key = Self::key(binding)?;
        self.begin_update(binding, None)?;
        self.backend
            .delete(&key)
            .map_err(|_| failure("native OAuth token deletion was not confirmed"))?;
        if self
            .backend
            .get(&key)
            .map_err(|_| failure("native OAuth token deletion readback failed"))?
            .is_some()
        {
            return Err(failure(
                "native OAuth token reappeared during deletion; outcome is unknown",
            ));
        }
        Ok(())
    }
}

fn account(binding: &CredentialBinding) -> String {
    binding
        .keyring_reference()
        .rsplit('/')
        .next()
        .expect("credential reference has an account")
        .to_owned()
}

fn failure(message: &'static str) -> CredentialStoreError {
    CredentialStoreError::new(message)
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Expiration {
    seconds: u64,
    nanoseconds: u32,
}

#[derive(Serialize)]
struct RecordRef<'a> {
    schema_version: u32,
    binding: &'a str,
    incomplete: bool,
    access_token: &'a str,
    refresh_token: Option<&'a str>,
    token_type: &'a str,
    scope: Option<&'a str>,
    expires_at: Option<Expiration>,
    authority: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    binding: String,
    incomplete: bool,
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    scope: Option<String>,
    expires_at: Option<Expiration>,
    authority: [u8; 32],
}

impl Drop for Record {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

fn encode(
    binding: &CredentialBinding,
    tokens: &TokenSet,
) -> Result<StoredSecret, CredentialStoreError> {
    let expires_at = tokens
        .expires_at
        .map(|expiry| {
            expiry
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|duration| Expiration {
                    seconds: duration.as_secs(),
                    nanoseconds: duration.subsec_nanos(),
                })
                .map_err(|_| failure("OAuth token expiry cannot be stored"))
        })
        .transpose()?;
    let record = RecordRef {
        schema_version: 1,
        binding: &account(binding),
        incomplete: false,
        access_token: tokens.access_token(),
        refresh_token: tokens.refresh_token(),
        token_type: &tokens.token_type,
        scope: tokens.scope(),
        expires_at,
        authority: tokens.authority.ok_or_else(|| {
            failure("OAuth tokens without issuer/client authority cannot be stored")
        })?,
    };
    let encoded = StoredSecret::new(
        serde_json::to_string(&record)
            .map_err(|_| failure("OAuth token record cannot be encoded"))?,
    );
    decode(binding, &encoded)?;
    Ok(encoded)
}

fn decode(
    binding: &CredentialBinding,
    encoded: &StoredSecret,
) -> Result<TokenSet, CredentialStoreError> {
    decode_record(read_record(binding, encoded)?)
}

fn read_record(
    binding: &CredentialBinding,
    encoded: &StoredSecret,
) -> Result<Record, CredentialStoreError> {
    if encoded.len() > MAX_RECORD_BYTES {
        return Err(failure("native OAuth token record exceeds its bound"));
    }
    let record: Record = serde_json::from_str(encoded.expose())
        .map_err(|_| failure("native OAuth token record is invalid"))?;
    if record.schema_version != 1 || record.binding != account(binding) {
        return Err(failure(
            "native OAuth token record has a different version or owner binding",
        ));
    }
    Ok(record)
}

fn decode_record(mut record: Record) -> Result<TokenSet, CredentialStoreError> {
    if record.incomplete {
        return Err(failure(
            "native OAuth token update is incomplete; new authorization is required",
        ));
    }
    let expires_at = record
        .expires_at
        .map(|expiry| {
            if expiry.nanoseconds >= 1_000_000_000 {
                return Err(failure("native OAuth token expiry is invalid"));
            }
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::new(expiry.seconds, expiry.nanoseconds))
                .ok_or_else(|| failure("native OAuth token expiry overflows the platform clock"))
        })
        .transpose()?;
    let wire = TokenWire {
        access_token: std::mem::take(&mut record.access_token),
        refresh_token: record.refresh_token.take(),
        token_type: std::mem::take(&mut record.token_type),
        scope: record.scope.take(),
        expires_in: None,
    };
    let mut tokens = wire
        .into_token_set(SystemTime::UNIX_EPOCH, None)
        .map_err(|_| failure("native OAuth token fields are invalid"))?;
    tokens.expires_at = expires_at;
    tokens.authority = Some(record.authority);
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use claw_provider_sdk::secret::{MemorySecretStore, SecretStoreError};
    use secrecy::SecretString;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Copy, Debug)]
    enum Fault {
        Write,
        Readback,
        Absent,
        Replacement,
        Delete,
    }

    #[derive(Debug)]
    struct FaultStore {
        inner: MemorySecretStore,
        fault: Fault,
        writes: AtomicUsize,
        deletes: AtomicUsize,
    }

    impl SecretStore for FaultStore {
        fn backend(&self) -> &'static str {
            "fixture"
        }

        fn get(&self, key: &CredentialKey) -> Result<Option<StoredSecret>, SecretStoreError> {
            if self.writes.load(Ordering::SeqCst) > 0 {
                match self.fault {
                    Fault::Readback => {
                        return Err(SecretStoreError::Backend {
                            backend: "fixture",
                            detail: "private-backend-value",
                        });
                    }
                    Fault::Replacement => {
                        return Ok(Some(StoredSecret::new("private-backend-replacement")));
                    }
                    Fault::Absent => return Ok(None),
                    Fault::Write | Fault::Delete => {}
                }
            }
            self.inner.get(key)
        }

        fn set(&self, key: &CredentialKey, value: &StoredSecret) -> Result<(), SecretStoreError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.inner.set(key, value)?;
            if matches!(self.fault, Fault::Write) {
                return Err(SecretStoreError::Backend {
                    backend: "fixture",
                    detail: "private-backend-value",
                });
            }
            Ok(())
        }

        fn delete(&self, key: &CredentialKey) -> Result<bool, SecretStoreError> {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            if matches!(self.fault, Fault::Delete) {
                return Err(SecretStoreError::Backend {
                    backend: "fixture",
                    detail: "private-backend-value",
                });
            }
            self.inner.delete(key)
        }
    }

    fn fixture() -> (CredentialBinding, TokenSet) {
        let binding = CredentialBinding::new(
            "storage-fixture",
            &url::Url::parse("http://127.0.0.1:32109/mcp").expect("resource"),
        )
        .expect("binding");
        let tokens = TokenSet {
            access_token: SecretString::from("private-stored-access".to_owned()),
            refresh_token: Some(SecretString::from("private-stored-refresh".to_owned())),
            token_type: "Bearer".into(),
            scope: Some("tools:read".into()),
            expires_at: Some(SystemTime::UNIX_EPOCH + Duration::new(1_800_000_000, 123_456_789)),
            authority: Some([7; 32]),
        };
        (binding, tokens)
    }

    #[test]
    fn native_token_records_preserve_authority_and_expiry_without_cross_binding_or_plain_output() {
        let (binding, tokens) = fixture();
        let backend = Arc::new(MemorySecretStore::new());
        let store = NativeTokenStore {
            backend: backend.clone(),
        };
        assert!(store.load(&binding).expect("absent record").is_none());
        assert_eq!(
            store.status(&binding).expect("absent status"),
            NativeTokenStatus::Absent
        );
        store
            .save(&binding, tokens.clone())
            .expect("protected record");
        let loaded = store
            .load(&binding)
            .expect("stored record")
            .expect("tokens");
        assert!(super::super::same_token_generation(&loaded, &tokens));
        assert_eq!(loaded.scope(), tokens.scope());
        assert_eq!(
            store.status(&binding).expect("available status"),
            NativeTokenStatus::Available {
                fresh: tokens.is_fresh(SystemTime::now()),
                can_refresh: true,
                expiry_known: true,
            }
        );
        assert!(!format!("{store:?}{loaded:?}").contains("private-stored"));
        assert!(
            NativeTokenStore::keyring_reference(&binding)
                .starts_with("keyring://gta-claw.mcp-oauth/")
        );
        assert_ne!(
            NativeTokenStore::keyring_reference(&binding),
            binding.keyring_reference()
        );
        let other = CredentialBinding::new(
            "other-profile",
            &url::Url::parse("http://127.0.0.1:32109/mcp").expect("resource"),
        )
        .expect("binding");
        let copied = backend
            .get(&NativeTokenStore::key(&binding).expect("key"))
            .expect("raw store")
            .expect("record");
        backend
            .set(&NativeTokenStore::key(&other).expect("other key"), &copied)
            .expect("hostile copied record");
        assert!(store.load(&other).is_err());
        assert!(store.status(&other).is_err());
        store.delete(&other).expect("delete rejected record");
        store.delete(&binding).expect("delete original");
        store.delete(&binding).expect("idempotent absence");
        assert!(backend.is_empty());
    }

    #[test]
    fn native_token_record_schema_and_bounds_fail_closed() {
        let (binding, tokens) = fixture();
        let encoded = encode(&binding, &tokens).expect("record");
        let original: serde_json::Value =
            serde_json::from_str(encoded.expose()).expect("fixture record");
        for (field, value) in [
            ("schema_version", serde_json::json!(2)),
            ("binding", serde_json::json!("foreign")),
            ("incomplete", serde_json::json!(true)),
            ("authority", serde_json::Value::Null),
            ("token_type", serde_json::json!("MAC")),
            ("access_token", serde_json::json!("")),
            ("refresh_token", serde_json::json!("private-token\n")),
            ("unknown", serde_json::json!(true)),
            (
                "expires_at",
                serde_json::json!({"seconds":0,"nanoseconds":1_000_000_000}),
            ),
        ] {
            let mut record = original.clone();
            record[field] = value;
            let error = decode(&binding, &StoredSecret::new(record.to_string()))
                .expect_err("invalid native record");
            assert!(!error.to_string().contains("private-stored"));
        }
        assert!(
            decode(
                &binding,
                &StoredSecret::new("x".repeat(MAX_RECORD_BYTES + 1))
            )
            .is_err()
        );
        let duplicate = encoded.expose().replacen('{', "{\"schema_version\":1,", 1);
        assert!(decode(&binding, &StoredSecret::new(duplicate)).is_err());
        let mut unbound = tokens;
        unbound.authority = None;
        assert!(encode(&binding, &unbound).is_err());
    }

    #[test]
    fn native_token_store_uncertain_writes_and_failed_deletion_never_replay_or_restore_secrets() {
        let (binding, tokens) = fixture();
        for fault in [
            Fault::Write,
            Fault::Readback,
            Fault::Absent,
            Fault::Replacement,
        ] {
            for marker in [false, true] {
                let backend = Arc::new(FaultStore {
                    inner: MemorySecretStore::new(),
                    fault,
                    writes: AtomicUsize::new(0),
                    deletes: AtomicUsize::new(0),
                });
                let store = NativeTokenStore {
                    backend: backend.clone(),
                };
                let result = if marker {
                    store.begin_update(&binding, None)
                } else {
                    store.save(&binding, tokens.clone())
                };
                let error = result.expect_err("uncertain native write");
                assert!(
                    !error.to_string().contains("private-backend")
                        && !error.to_string().contains("private-stored")
                );
                assert!(error.to_string().contains(match fault {
                    Fault::Write => "write was not confirmed",
                    Fault::Readback => "write readback failed",
                    Fault::Absent => "record is absent after write",
                    Fault::Replacement => "record changed during verification",
                    Fault::Delete => unreachable!("deletion tested separately"),
                }));
                assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
                assert_eq!(backend.deletes.load(Ordering::SeqCst), 0);
            }
        }
        let backend = Arc::new(FaultStore {
            inner: MemorySecretStore::new(),
            fault: Fault::Delete,
            writes: AtomicUsize::new(0),
            deletes: AtomicUsize::new(0),
        });
        backend
            .inner
            .set(
                &NativeTokenStore::key(&binding).expect("key"),
                &encode(&binding, &tokens).expect("record"),
            )
            .expect("existing credential");
        let store = NativeTokenStore {
            backend: backend.clone(),
        };
        assert!(store.delete(&binding).is_err());
        assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
        assert_eq!(backend.deletes.load(Ordering::SeqCst), 1);
        let reopened = NativeTokenStore { backend };
        assert!(
            reopened
                .load(&binding)
                .expect_err("failed deletion retains refusal after reopen")
                .to_string()
                .contains("new authorization")
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_token_store_roundtrip_reopens_only_an_owned_windows_entry() {
        struct Owned {
            store: NativeTokenStore,
            binding: CredentialBinding,
        }
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.store.delete(&self.binding);
            }
        }
        let (mut binding, tokens) = fixture();
        binding.profile = format!(
            "oauth-native-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let store = NativeTokenStore::new().expect("native Windows store is required");
        assert!(
            store
                .load(&binding)
                .expect("unique key preflight")
                .is_none()
        );
        let owned = Owned { store, binding };
        owned
            .store
            .save(&owned.binding, tokens.clone())
            .expect("owned native token record");
        let reopened = NativeTokenStore::new().expect("independent native store");
        let loaded = reopened
            .load(&owned.binding)
            .expect("load persisted")
            .expect("retained tokens");
        assert!(super::super::same_token_generation(&tokens, &loaded));
        let mut changed = tokens;
        changed.refresh_token = Some(SecretString::from("other-refresh-generation".to_owned()));
        assert!(
            reopened
                .begin_update(&owned.binding, Some(&changed))
                .is_err()
        );
        assert!(
            reopened
                .load(&owned.binding)
                .expect("unchanged after rejected marker")
                .is_some()
        );
        reopened
            .begin_update(&owned.binding, Some(&loaded))
            .expect("pending marker before network");
        drop(reopened);
        let reopened = NativeTokenStore::new().expect("reopen pending update");
        let error = reopened
            .load(&owned.binding)
            .expect_err("pending update cannot yield old tokens after reopening");
        assert!(error.to_string().contains("new authorization"));
        assert_eq!(
            reopened.status(&owned.binding).expect("pending metadata"),
            NativeTokenStatus::ReauthorizationRequired
        );
        let raw = reopened
            .backend
            .get(&NativeTokenStore::key(&owned.binding).expect("owned key"))
            .expect("pending record")
            .expect("marker");
        assert!(!raw.expose().contains("private-stored"));
        reopened
            .begin_update(&owned.binding, None)
            .expect("new authorization may replace pending marker");
        reopened
            .save(&owned.binding, changed.clone())
            .expect("new authorized token record");
        assert!(super::super::same_token_generation(
            &changed,
            &reopened
                .load(&owned.binding)
                .expect("recovered record")
                .expect("tokens")
        ));
        reopened
            .delete(&owned.binding)
            .expect("explicit fixture cleanup");
        assert!(
            owned
                .store
                .load(&owned.binding)
                .expect("cleanup verified")
                .is_none()
        );
    }
}
